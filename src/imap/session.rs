//! IMAP connection setup: TCP, TLS, greeting and authentication.
//!
//! Produces a live authenticated [`Session`] ready to be handed to the
//! mailbox watcher, and a read-only [`probe`] that connects, inspects
//! capabilities and logs out again without ever selecting a mailbox —
//! the basis of the `/test` endpoint. All the coroutines are driven by
//! the async [`crate::imap::pump`].

use std::time::Duration;

use anyhow::{Context, Result};
use io_imap::codec::fragmentizer::Fragmentizer;
use io_imap::rfc3501::greeting::{ImapGreetingGet, ImapGreetingGetOptions};
use io_imap::rfc3501::login::{ImapLogin, ImapLoginOptions};
use io_imap::rfc3501::logout::ImapLogout;
use io_imap::types::response::Capability;
use rustls::pki_types::ServerName;
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::imap::pump;

/// We fetch only UID and FLAGS, never bodies, so the parser buffer
/// never needs to grow large; this is a safety bound, not a
/// preallocation (the fragmentizer grows lazily into it).
const MAX_MESSAGE_SIZE: u32 = 1 << 20;

/// TCP keepalive: probe after a minute of silence to detect a
/// half-dead socket (a missed notification is the worst failure) and
/// to keep NAT mappings warm.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);

/// Connection parameters for one watch.
#[derive(Clone, Debug)]
pub struct ImapAccount {
    /// IMAP server host.
    pub host: String,
    /// IMAP server port.
    pub port: u16,
    /// Login (authentication identity).
    pub login: String,
    /// Cleartext password (decrypted just before connecting).
    pub password: String,
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
/// authenticate. Success here means the server is *reachable* (DNS,
/// TCP, TLS and a valid greeting all worked).
async fn open(
    connector: &TlsConnector,
    account: &ImapAccount,
) -> Result<(TlsStream<TcpStream>, Fragmentizer)> {
    let tcp = TcpStream::connect((account.host.as_str(), account.port))
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

    // Greeting (ensuring a CAPABILITY is observed).
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

/// Authenticates an opened stream with LOGIN, returning the fresh
/// post-authentication capabilities.
async fn authenticate(
    stream: &mut TlsStream<TcpStream>,
    fragmentizer: &mut Fragmentizer,
    account: &ImapAccount,
) -> Result<Vec<Capability<'static>>> {
    let login_opts = ImapLoginOptions {
        ensure_capabilities: true,
        auto_id: None,
    };
    let login = ImapLogin::new(&account.login, &account.password, login_opts)
        .context("Invalid IMAP credentials")?;
    pump::run(stream, fragmentizer, login)
        .await?
        .context("IMAP login failed")
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
/// selects a mailbox and issues no write — this is the read-only basis
/// of the `/test` endpoint (the plan's "Test", distinct from "Activate").
#[derive(Clone, Debug, Default)]
pub struct Probe {
    /// DNS + TCP + TLS + a valid greeting all succeeded.
    pub reachable: bool,
    /// LOGIN succeeded with the supplied credentials.
    pub authenticated: bool,
    /// Server advertises IDLE (RFC 2177) — required to watch.
    pub idle: bool,
    /// Server advertises QRESYNC (RFC 7162) — required by the watcher's
    /// change guard.
    pub qresync: bool,
    /// Server advertises CONDSTORE (implied by QRESYNC).
    pub condstore: bool,
    /// The stage that failed, if any.
    pub error: Option<String>,
}

impl Probe {
    /// Watchable iff reachable, authenticated and advertising the
    /// capabilities the watcher needs. This is the plan's "green light":
    /// `TLS + auth + CAPABILITY ⊇ {IDLE, QRESYNC}`, **not** just auth.
    pub fn watchable(&self) -> bool {
        self.reachable && self.authenticated && self.idle && self.qresync
    }

    /// The names of the required capabilities the server does not
    /// advertise (only meaningful once authenticated).
    pub fn missing(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.idle {
            missing.push("IDLE");
        }
        if !self.qresync {
            missing.push("QRESYNC");
        }
        missing
    }
}

/// Connects read-only, records what the watcher's guard cares about,
/// and logs out cleanly — spending no standing resource. Stage failures
/// are captured in the returned [`Probe`] rather than raised, so the
/// caller can report *which* stage failed (reachable vs authenticated
/// vs a missing capability).
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

    // Best-effort clean logout; the verdict is already decided.
    let _ = pump::run(&mut stream, &mut fragmentizer, ImapLogout::new()).await;

    probe
}
