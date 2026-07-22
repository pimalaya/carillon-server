//! CardDAV connection, probe and change enumeration.
//!
//! WebDAV has no long-held push like IMAP IDLE, so a CardDAV service is
//! **polled**: each round opens a fresh TLS connection, drives one
//! io-webdav coroutine (a `sync-collection` REPORT, RFC 6578, or a
//! baseline `PROPFIND`) to completion over it, and closes. The coroutines
//! are I/O-free (`WantsRead` / `WantsWrite`); [`drive`] is the async pump
//! that runs them — the CardDAV analogue of [`crate::imap::pump::run`].
//!
//! The signal stays **content-free by construction**: only `getetag` and
//! `sync-token` are requested, never `address-data` (the vCard body). A
//! change is identified by its opaque href, exactly as an IMAP change is
//! identified by its UID.

use anyhow::{Context, Result, bail};
use io_http::rfc6750::bearer::HttpAuthBearer;
use io_http::rfc7617::basic::HttpAuthBasic;
use io_webdav::coroutine::{WebdavCoroutine, WebdavCoroutineState, WebdavYield};
use io_webdav::rfc4918::propfind::Propfind;
use io_webdav::rfc4918::send::SendError;
use io_webdav::rfc4918::{GETCTAG, GETETAG, SYNC_TOKEN, WebdavAuth};
use io_webdav::rfc6578::sync_collection::{SyncCollection, SyncCollectionError, SyncDelta};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use url::Url;

use crate::guard;

/// Per-read scratch buffer. A `sync-collection` REPORT that only fetches
/// etags stays small; the coroutine reassembles across reads.
const READ_BUF: usize = 16 * 1024;

/// `User-Agent` sent on every WebDAV request.
const USER_AGENT: &str = "carillon";

/// How to authenticate a CardDAV request: a password (HTTP Basic, RFC 7617)
/// or an OAuth 2.0 bearer token (RFC 6750) — mirroring
/// [`crate::imap::session::ImapAuth`]. Resolved just before each poll.
#[derive(Clone, Debug)]
pub enum CardDavAuth {
    /// Cleartext password / app password, sent as HTTP Basic.
    Password(String),
    /// A short-lived OAuth 2.0 bearer access token.
    Bearer(String),
}

/// Connection parameters for one CardDAV addressbook watch.
#[derive(Clone, Debug)]
pub struct CardDavAccount {
    /// Full collection URL, e.g.
    /// `https://carddav.host/dav/addressbooks/user/x/Default/`.
    pub url: String,
    /// Login identity (the HTTP Basic username).
    pub login: String,
    /// How to authenticate (resolved just before each poll).
    pub auth: CardDavAuth,
}

impl CardDavAccount {
    fn webdav_auth(&self) -> WebdavAuth {
        match &self.auth {
            CardDavAuth::Password(password) => {
                WebdavAuth::Basic(HttpAuthBasic::new(self.login.clone(), password.clone()))
            }
            CardDavAuth::Bearer(token) => WebdavAuth::Bearer(HttpAuthBearer::new(token.clone())),
        }
    }

    /// Splits the collection URL into `(host, port, base_url, path)`: the
    /// origin to open a TLS stream to, plus the base and absolute path
    /// io-webdav resolves the request target against.
    fn parts(&self) -> Result<(String, u16, Url, String)> {
        let full =
            Url::parse(&self.url).with_context(|| format!("invalid CardDAV URL: {}", self.url))?;
        if full.scheme() != "https" {
            bail!("CardDAV URL must be https:// (got {}://)", full.scheme());
        }
        let host = full
            .host_str()
            .context("CardDAV URL has no host")?
            .to_string();
        let port = full.port_or_known_default().unwrap_or(443);
        let base_url = Url::parse(&full.origin().ascii_serialization())
            .context("cannot derive CardDAV origin")?;
        let path = full.path().to_string();
        Ok((host, port, base_url, path))
    }
}

/// The content-free resource id of a member href: its last path segment
/// (the vCard resource name), never card contents — the CardDAV analogue of
/// an IMAP UID.
pub fn resource_id(href: &str) -> String {
    href.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(href)
        .to_string()
}

/// Why a `sync-collection` poll failed, keeping the "token rejected"
/// case distinct so the poller can re-baseline instead of erroring.
pub enum SyncPollError {
    /// The server rejected the sync token; a fresh baseline is needed.
    InvalidToken,
    /// A transport / protocol failure — surfaced as a watch error.
    Other(anyhow::Error),
}

/// The structured outcome of probing a CardDAV collection, the read-only
/// basis of the `/test` verdict. Never enumerates the collection.
#[derive(Clone, Debug, Default)]
pub struct CardDavProbe {
    /// DNS + TCP + TLS all succeeded.
    pub reachable: bool,
    /// The credentials were accepted (not a 401/403).
    pub authenticated: bool,
    /// The collection reports a change token (`sync-token` or `getctag`),
    /// so it can be watched by polling.
    pub sync: bool,
    /// The stage that failed, if any.
    pub error: Option<String>,
}

impl CardDavProbe {
    /// Watchable iff reachable, authenticated and reporting a change token.
    pub fn watchable(&self) -> bool {
        self.reachable && self.authenticated && self.sync
    }
}

/// Opens a TLS stream to a CardDAV host, SSRF-guarded exactly like the IMAP
/// path: resolve + check first, then connect to that exact address (SNI and
/// certificate verification still use the hostname).
async fn open(connector: &TlsConnector, host: &str, port: u16) -> Result<TlsStream<TcpStream>> {
    let addr = guard::resolve_allowed(host, port)
        .await
        .with_context(|| format!("Cannot connect to {host}:{port}"))?;
    let tcp = TcpStream::connect(addr)
        .await
        .with_context(|| format!("Cannot connect to {host}:{port}"))?;
    tcp.set_nodelay(true).ok();
    let server_name = ServerName::try_from(host.to_string())
        .with_context(|| format!("Invalid TLS server name: {host}"))?;
    connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake failed")
}

/// Drives an I/O-free WebDAV coroutine to completion over an async stream,
/// returning its terminal value. The CardDAV analogue of
/// [`crate::imap::pump::run`] (there is no fragmentizer: io-http reassembles
/// the response itself).
async fn drive<S, C, R>(stream: &mut S, mut coroutine: C) -> Result<R>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: WebdavCoroutine<Yield = WebdavYield, Return = R>,
{
    let mut buf = [0u8; READ_BUF];
    let mut arg: Option<&[u8]> = None;
    let mut eof = false;
    loop {
        match coroutine.resume(arg.take()) {
            WebdavCoroutineState::Yielded(WebdavYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).await.context("write failed")?;
            }
            WebdavCoroutineState::Yielded(WebdavYield::WantsRead) => {
                if eof {
                    bail!("connection closed by peer");
                }
                let n = stream.read(&mut buf).await.context("read failed")?;
                if n == 0 {
                    // A close-delimited body ends here: feed the empty slice so
                    // the coroutine finalizes; a further read request is an error.
                    eof = true;
                }
                arg = Some(&buf[..n]);
            }
            WebdavCoroutineState::Complete(value) => return Ok(value),
        }
    }
}

/// Probes a collection read-only: opens TLS, `PROPFIND`s (Depth 0) its
/// change token, and reports each stage. Never raises — stage failures are
/// captured in the returned [`CardDavProbe`], like the IMAP probe.
pub async fn probe(connector: &TlsConnector, account: &CardDavAccount) -> CardDavProbe {
    let mut probe = CardDavProbe::default();

    let (host, port, base_url, path) = match account.parts() {
        Ok(parts) => parts,
        Err(err) => {
            probe.error = Some(format!("{err:#}"));
            return probe;
        }
    };
    let auth = account.webdav_auth();

    let mut stream = match open(connector, &host, port).await {
        Ok(stream) => stream,
        Err(err) => {
            probe.error = Some(format!("{err:#}"));
            return probe;
        }
    };
    probe.reachable = true;

    let propfind = Propfind::new(
        &base_url,
        &auth,
        USER_AGENT,
        &path,
        0,
        &[SYNC_TOKEN, GETCTAG],
    );
    match drive(&mut stream, propfind).await {
        Ok(Ok(multistatus)) => {
            probe.authenticated = true;
            probe.sync = multistatus
                .responses
                .iter()
                .any(|entry| entry.text(SYNC_TOKEN).is_some() || entry.text(GETCTAG).is_some());
            if !probe.sync {
                probe.error = Some("collection reports no sync-token".into());
            }
        }
        Ok(Err(SendError::HttpStatus(401 | 403, _))) => {
            probe.error = Some("authentication failed".into());
        }
        Ok(Err(err)) => {
            // Reached and answered, but not a usable collection (e.g. 404).
            probe.authenticated = true;
            probe.error = Some(format!("{err}"));
        }
        Err(err) => probe.error = Some(format!("{err:#}")),
    }

    probe
}

/// Runs one `sync-collection` REPORT (RFC 6578) against the collection,
/// asking only for etags. `since` is the checkpoint token (`None` for an
/// initial enumeration). Returns the parsed delta, or a [`SyncPollError`]
/// distinguishing a rejected token (re-baseline) from a transport failure.
pub async fn sync_changes(
    connector: &TlsConnector,
    account: &CardDavAccount,
    since: Option<&str>,
) -> Result<SyncDelta, SyncPollError> {
    let (host, port, base_url, path) = account.parts().map_err(SyncPollError::Other)?;
    let auth = account.webdav_auth();
    let mut stream = open(connector, &host, port)
        .await
        .map_err(SyncPollError::Other)?;
    let report = SyncCollection::new(&base_url, &auth, USER_AGENT, &path, since, &[GETETAG]);
    match drive(&mut stream, report).await {
        Ok(Ok(delta)) => Ok(delta),
        Ok(Err(SyncCollectionError::InvalidSyncToken)) => Err(SyncPollError::InvalidToken),
        Ok(Err(err)) => Err(SyncPollError::Other(anyhow::anyhow!(
            "sync-collection failed: {err}"
        ))),
        Err(err) => Err(SyncPollError::Other(err)),
    }
}
