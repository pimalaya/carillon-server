//! IMAP connection setup: TCP, TLS, greeting and authentication.
//!
//! Produces a live authenticated [`Session`] for the mailbox watcher,
//! and a read-only [`probe`] that connects, inspects capabilities and
//! logs out without selecting a mailbox: the basis of the `/test`
//! endpoint. All the coroutines are driven by the async
//! [`crate::imap::pump`].

use std::time::Duration;

use anyhow::{Context, Result};
use io_imap::codec::fragmentizer::Fragmentizer;
use io_imap::rfc3501::greeting::{ImapGreetingGet, ImapGreetingGetOptions};
use io_imap::rfc3501::list::ImapMailboxList;
use io_imap::rfc3501::login::{ImapLogin, ImapLoginOptions};
use io_imap::rfc3501::logout::ImapLogout;
use io_imap::rfc7628::auth_oauthbearer::{ImapAuthOauthbearer, ImapAuthOauthbearerOptions};
use io_imap::types::flag::FlagNameAttribute;
use io_imap::types::mailbox::{ListMailbox, Mailbox};
use io_imap::types::response::Capability;
use rustls::pki_types::ServerName;
use serde::Serialize;
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tracing::debug;

use crate::guard;
use crate::imap::pump;

/// Safety bound on the parser buffer; only UID and FLAGS are fetched,
/// never bodies, so it never needs to grow large (the fragmentizer grows
/// lazily into it).
const MAX_MESSAGE_SIZE: u32 = 1 << 20;

/// TCP keepalive: probe after a minute of silence to detect a half-dead
/// socket (a missed notification is the worst failure) and keep NAT
/// mappings warm.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);

/// How to authenticate an IMAP session: a password (`LOGIN`) or an OAuth
/// 2.0 access token (SASL `OAUTHBEARER`). Resolved just before
/// connecting; for OAuth the access token is minted fresh from the
/// stored refresh token.
#[derive(Clone, Debug)]
pub enum ImapAuth {
    /// Cleartext password / app password.
    Password(String),
    /// A short-lived OAuth 2.0 bearer access token.
    OauthBearer(String),
}

/// Connection parameters for one watch.
#[derive(Clone, Debug)]
pub struct ImapAccount {
    /// IMAP server host.
    pub host: String,
    /// IMAP server port.
    pub port: u16,
    /// Login (authentication identity).
    pub login: String,
    /// How to authenticate (resolved just before connecting).
    pub auth: ImapAuth,
    /// Mailbox to watch.
    pub mailbox: String,
}

/// A live, authenticated IMAP session.
pub struct Session {
    /// The negotiated TLS stream.
    pub stream: TlsStream<TcpStream>,
    /// The connection-wide parser buffer, shared across coroutines.
    pub fragmentizer: Fragmentizer,
    /// Post-authentication capabilities (where QRESYNC surfaces).
    pub capabilities: Vec<Capability<'static>>,
}

/// Opens TCP + TLS and reads the greeting, leaving a stream ready to
/// authenticate. Success means the server is reachable (DNS, TCP, TLS and
/// a valid greeting all worked).
async fn open(
    connector: &TlsConnector,
    account: &ImapAccount,
) -> Result<(TlsStream<TcpStream>, Fragmentizer)> {
    // NOTE: resolve + SSRF-check first, then connect to that exact
    // address (rebinding-safe). TLS still uses the hostname for SNI +
    // certificate verification below.
    let addr = guard::resolve_allowed(&account.host, account.port)
        .await
        .with_context(|| format!("Cannot connect to {}:{}", account.host, account.port))?;
    let tcp = TcpStream::connect(addr)
        .await
        .with_context(|| format!("Cannot connect to {}:{}", account.host, account.port))?;
    tcp.set_nodelay(true).ok();

    let keepalive = TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL);
    SockRef::from(&tcp).set_tcp_keepalive(&keepalive).ok();

    let server_name = ServerName::try_from(account.host.clone())
        .with_context(|| format!("Invalid TLS server name: {}", account.host))?;
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake failed")?;

    let mut fragmentizer = Fragmentizer::new(MAX_MESSAGE_SIZE);

    // NOTE: read the greeting, ensuring a CAPABILITY is observed.
    let greeting_opts = ImapGreetingGetOptions {
        ensure_capabilities: true,
    };
    pump::run(
        &mut stream,
        &mut fragmentizer,
        ImapGreetingGet::new(greeting_opts),
    )
    .await?
    .context("IMAP greeting failed")?;

    Ok((stream, fragmentizer))
}

/// Authenticates an opened stream (`LOGIN` for a password, SASL
/// `OAUTHBEARER` for an OAuth access token), returning the fresh
/// post-authentication capabilities.
async fn authenticate(
    stream: &mut TlsStream<TcpStream>,
    fragmentizer: &mut Fragmentizer,
    account: &ImapAccount,
) -> Result<Vec<Capability<'static>>> {
    match &account.auth {
        ImapAuth::Password(password) => {
            let login_opts = ImapLoginOptions {
                ensure_capabilities: true,
                auto_id: None,
            };
            let login = ImapLogin::new(&account.login, password, login_opts)
                .context("Invalid IMAP credentials")?;
            pump::run(stream, fragmentizer, login)
                .await?
                .context("IMAP login failed")
        }
        ImapAuth::OauthBearer(token) => {
            let opts = ImapAuthOauthbearerOptions {
                initial_request: true,
                ensure_capabilities: true,
                auto_id: None,
            };
            let auth =
                ImapAuthOauthbearer::new(&account.login, &account.host, account.port, token, opts);
            pump::run(stream, fragmentizer, auth)
                .await?
                .context("IMAP OAUTHBEARER authentication failed")
        }
    }
}

/// Opens TCP + TLS, reads the greeting and authenticates with LOGIN,
/// returning the post-login capabilities.
pub async fn connect(connector: &TlsConnector, account: &ImapAccount) -> Result<Session> {
    let (mut stream, mut fragmentizer) = open(connector, account).await?;
    let capabilities = authenticate(&mut stream, &mut fragmentizer, account).await?;

    Ok(Session {
        stream,
        fragmentizer,
        capabilities,
    })
}

/// The structured outcome of probing an account, stage by stage. Never
/// selects a mailbox and issues no write: the read-only basis of the
/// `/test` endpoint.
#[derive(Clone, Debug, Default)]
pub struct Probe {
    /// DNS + TCP + TLS + a valid greeting all succeeded.
    pub reachable: bool,
    /// LOGIN succeeded with the supplied credentials.
    pub authenticated: bool,
    /// Server advertises IDLE (RFC 2177), required to watch.
    pub idle: bool,
    /// Server advertises QRESYNC (RFC 7162), used by the watcher's change
    /// guard.
    pub qresync: bool,
    /// Server advertises CONDSTORE (implied by QRESYNC).
    pub condstore: bool,
    /// The stage that failed, if any.
    pub error: Option<String>,
}

impl Probe {
    /// Watchable iff reachable, authenticated and advertising IDLE, the
    /// one hard requirement (the wake signal). QRESYNC is optional: with
    /// it the watcher tracks new/flags/removed via `run_watch`; without
    /// it the IDLE-only `run_watch_idle` path tracks new mail only.
    pub fn watchable(&self) -> bool {
        self.reachable && self.authenticated && self.idle
    }

    /// The names of the required capabilities the server does not
    /// advertise (only meaningful once authenticated). QRESYNC is an
    /// enhancement, not a requirement, so it is not listed here.
    pub fn missing(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.idle {
            missing.push("IDLE");
        }
        missing
    }
}

/// Connects read-only, records what the watcher's guard cares about, and
/// logs out cleanly, spending no standing resource. Stage failures are
/// captured in the returned [`Probe`] rather than raised, so the caller
/// can report which stage failed.
pub async fn probe(connector: &TlsConnector, account: &ImapAccount) -> Probe {
    let mut probe = Probe::default();

    let (mut stream, mut fragmentizer) = match open(connector, account).await {
        Ok(opened) => opened,
        Err(err) => {
            probe.error = Some(format!("{err:#}"));
            return probe;
        }
    };
    probe.reachable = true;

    let capabilities = match authenticate(&mut stream, &mut fragmentizer, account).await {
        Ok(capabilities) => capabilities,
        Err(err) => {
            probe.error = Some(format!("{err:#}"));
            return probe;
        }
    };
    probe.authenticated = true;
    probe.idle = capabilities.contains(&Capability::Idle);
    probe.qresync = capabilities.contains(&Capability::QResync);
    probe.condstore = capabilities.contains(&Capability::CondStore);

    // NOTE: a provider that supports IDLE but reads as non-watchable
    // here means the capability was not captured (e.g.
    // inline-vs-follow-up CAPABILITY), not that the server lacks it.
    debug!(
        host = %account.host,
        idle = probe.idle,
        qresync = probe.qresync,
        capabilities = ?capabilities,
        "imap probe post-auth capabilities",
    );

    // NOTE: best-effort clean logout; the verdict is already decided.
    let _ = pump::run(&mut stream, &mut fragmentizer, ImapLogout::new()).await;

    probe
}

/// One selectable mailbox from a LIST, with its RFC 6154 special-use role
/// if the server advertises one. Fills the onboarding mailbox picker,
/// defaulting to the inbox.
#[derive(Clone, Debug, Serialize)]
pub struct MailboxEntry {
    /// The unicode mailbox name (e.g. `INBOX`, `[Gmail]/All Mail`).
    pub name: String,
    /// The special-use role, if the server flags one.
    pub role: Option<&'static str>,
}

/// Connects, authenticates, `LIST`s every selectable mailbox and logs
/// out: the read side behind the onboarding mailbox picker. `\Noselect`
/// containers are dropped; the result is sorted with `INBOX` first, then
/// case-insensitively by name.
pub async fn list_mailboxes(
    connector: &TlsConnector,
    account: &ImapAccount,
) -> Result<Vec<MailboxEntry>> {
    let (mut stream, mut fragmentizer) = open(connector, account).await?;
    authenticate(&mut stream, &mut fragmentizer, account).await?;

    let reference = Mailbox::try_from("").expect("empty reference is valid");
    let pattern = ListMailbox::try_from("*").expect("'*' wildcard is valid");
    let rows = pump::run(
        &mut stream,
        &mut fragmentizer,
        ImapMailboxList::new(reference, pattern),
    )
    .await?
    .context("IMAP LIST failed")?;

    // NOTE: best-effort clean logout; the listing is already in hand.
    let _ = pump::run(&mut stream, &mut fragmentizer, ImapLogout::new()).await;

    let mut entries: Vec<MailboxEntry> = rows
        .into_iter()
        .filter(|(_, _, attrs)| {
            !attrs
                .iter()
                .any(|attr| matches!(attr, FlagNameAttribute::Noselect))
        })
        .map(|(mailbox, _, attrs)| {
            let (name, is_inbox) = match &mailbox {
                Mailbox::Inbox => ("INBOX".to_string(), true),
                Mailbox::Other(other) => (
                    String::from_utf8_lossy(other.inner().as_ref()).into_owned(),
                    false,
                ),
            };
            MailboxEntry {
                role: mailbox_role(is_inbox, &attrs),
                name,
            }
        })
        .collect();

    // NOTE: INBOX first, then case-insensitive name; drop duplicate
    // names.
    entries.sort_by(|a, b| {
        let rank = |e: &MailboxEntry| (e.name != "INBOX", e.name.to_ascii_lowercase());
        rank(a).cmp(&rank(b))
    });
    entries.dedup_by(|a, b| a.name == b.name);

    Ok(entries)
}

/// Maps a mailbox's RFC 6154 special-use attributes to a coarse role, or
/// `None` for a plain folder.
fn mailbox_role(is_inbox: bool, attrs: &[FlagNameAttribute]) -> Option<&'static str> {
    if is_inbox {
        return Some("inbox");
    }
    attrs.iter().find_map(|attr| {
        match attr
            .to_string()
            .trim_start_matches('\\')
            .to_ascii_lowercase()
            .as_str()
        {
            "sent" => Some("sent"),
            "drafts" => Some("drafts"),
            "junk" => Some("junk"),
            "trash" => Some("trash"),
            "archive" => Some("archive"),
            "all" => Some("all"),
            "flagged" => Some("flagged"),
            _ => None,
        }
    })
}
