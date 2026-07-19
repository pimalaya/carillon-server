//! IMAP connection setup: TCP, TLS, greeting and authentication.
//!
//! Produces a live authenticated [`Session`] ready to be handed to the
//! mailbox watcher. All the coroutines are driven by the async
//! [`crate::imap::pump`].

use std::time::Duration;

use anyhow::{Context, Result};
use io_imap::codec::fragmentizer::Fragmentizer;
use io_imap::rfc3501::greeting::{ImapGreetingGet, ImapGreetingGetOptions};
use io_imap::rfc3501::login::{ImapLogin, ImapLoginOptions};
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

/// Opens TCP + TLS, reads the greeting and authenticates with LOGIN,
/// returning the post-login capabilities.
pub async fn connect(connector: &TlsConnector, account: &ImapAccount) -> Result<Session> {
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

    // LOGIN, returning fresh post-authentication capabilities.
    let login_opts = ImapLoginOptions {
        ensure_capabilities: true,
        auto_id: None,
    };
    let login = ImapLogin::new(&account.login, &account.password, login_opts)
        .context("Invalid IMAP credentials")?;
    let capabilities = pump::run(&mut stream, &mut fragmentizer, login)
        .await?
        .context("IMAP login failed")?;

    Ok(Session {
        stream,
        fragmentizer,
        capabilities,
    })
}
