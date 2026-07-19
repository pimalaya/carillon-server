//! The async coroutine pump.
//!
//! `io-imap` coroutines are I/O-free: they yield `WantsRead` /
//! `WantsWrite` (and, for the watcher, `Event`) and the caller owns the
//! socket. `pimalaya-stream` ships a blocking, thread-per-connection
//! pump; holding tens of thousands of IDLE connections needs an async
//! one, so we inline it here over any `tokio` stream. It is ~30 lines
//! and drives every coroutine the same way — the whole trick of the
//! beast.

use anyhow::{Context, Result, bail};
use io_imap::codec::fragmentizer::Fragmentizer;
use io_imap::coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield};
use io_imap::watch::{ImapMailboxWatch, ImapMailboxWatchYield};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

use crate::event::ChangeEvent;

/// Per-read scratch buffer. IDLE never fetches bodies, so a small
/// buffer is plenty; the fragmentizer reassembles across reads.
const READ_BUF: usize = 8 * 1024;

/// Proactively drop and reconnect an idle connection after this long
/// with no server traffic. TCP keepalive keeps NAT mappings warm; this
/// bounds the silent-dead-socket window and refreshes server-side IDLE
/// state well under the RFC 2177 §3 cap.
const IDLE_REFRESH: Duration = Duration::from_secs(15 * 60);

/// Drives a request/response coroutine (greeting, login, capability,
/// ...) to completion over an async stream, returning the coroutine's
/// own terminal value.
pub async fn run<S, C>(
    stream: &mut S,
    fragmentizer: &mut Fragmentizer,
    mut coroutine: C,
) -> Result<C::Return>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: ImapCoroutine<Yield = ImapYield>,
{
    let mut buf = [0u8; READ_BUF];
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(fragmentizer, arg.take()) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).await.context("write failed")?;
            }
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf).await.context("read failed")?;
                if n == 0 {
                    bail!("connection closed by peer");
                }
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Complete(value) => return Ok(value),
        }
    }
}

/// Drives the mailbox watcher, forwarding each change (tagged with the
/// account id) to `events`.
///
/// Returns `Ok(())` on a clean wind-down or a periodic idle refresh,
/// `Err` on a connection failure; the caller reconnects in both live
/// cases. Graceful stop is done by aborting the task, so this never
/// needs to poll the shutdown flag itself.
pub async fn run_watch<S>(
    account: &str,
    stream: &mut S,
    fragmentizer: &mut Fragmentizer,
    mut watch: ImapMailboxWatch,
    events: &mpsc::Sender<ChangeEvent>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = [0u8; READ_BUF];
    let mut arg: Option<&[u8]> = None;

    loop {
        match watch.resume(fragmentizer, arg.take()) {
            ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).await.context("write failed")?;
            }
            ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsRead) => {
                match timeout(IDLE_REFRESH, stream.read(&mut buf)).await {
                    Ok(Ok(0)) => bail!("connection closed by peer"),
                    Ok(Ok(n)) => arg = Some(&buf[..n]),
                    Ok(Err(err)) => return Err(err).context("read failed"),
                    // No traffic for a while: drop and reconnect to
                    // refresh the session.
                    Err(_elapsed) => return Ok(()),
                }
            }
            ImapCoroutineState::Yielded(ImapMailboxWatchYield::Event(event)) => {
                let change = ChangeEvent::from_watch(account, &event);
                if events.send(change).await.is_err() {
                    bail!("delivery channel closed");
                }
            }
            ImapCoroutineState::Complete(Ok(())) => return Ok(()),
            ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
        }
    }
}
