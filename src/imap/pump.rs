//! The async coroutine pump.
//!
//! `io-imap` coroutines are I/O-free: they yield `WantsRead` /
//! `WantsWrite` (and, for the watcher, `Event`) and the caller owns the
//! socket. `pimalaya-stream` ships a blocking, thread-per-connection
//! pump; holding tens of thousands of IDLE connections needs an async
//! one, so we inline it here over any `tokio` stream. It is ~30 lines
//! and drives every coroutine the same way — the whole trick of the
//! beast.

use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use io_imap::codec::fragmentizer::Fragmentizer;
use io_imap::coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield};
use io_imap::rfc2177::idle::{ImapIdle, ImapIdleOptions, ImapIdleYield};
use io_imap::rfc3501::examine::{ImapMailboxExamine, ImapMailboxExamineOptions};
use io_imap::rfc3501::fetch::{ImapMessageFetch, ImapMessageFetchOptions};
use io_imap::types::fetch::{MacroOrMessageDataItemNames, MessageDataItem, MessageDataItemName};
use io_imap::types::mailbox::Mailbox;
use io_imap::types::sequence::SequenceSet;
use io_imap::watch::{ImapMailboxWatch, ImapMailboxWatchYield};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};
use tracing::debug;

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

/// A single IDLE round's outcome.
enum IdleOutcome {
    /// The server sent untagged data (something changed) — go resync.
    Data,
    /// The periodic refresh timer fired with no data — reconnect.
    Refresh,
    /// Shutdown was requested.
    Shutdown,
}

/// Runs one IDLE round: waits for untagged server data (or the periodic
/// refresh timeout), then ends IDLE cleanly. Mirrors `run_watch`'s IDLE
/// handling, but standalone so the IDLE-only watcher can compose it.
async fn idle_once<S>(
    stream: &mut S,
    fragmentizer: &mut Fragmentizer,
    shutdown: &Arc<AtomicBool>,
) -> Result<IdleOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if shutdown.load(Ordering::SeqCst) {
        return Ok(IdleOutcome::Shutdown);
    }

    let done = Arc::new(AtomicBool::new(false));
    let mut idle = ImapIdle::new(done.clone(), ImapIdleOptions::default());
    let mut buf = [0u8; READ_BUF];
    let mut arg: Option<&[u8]> = None;

    loop {
        // Let a shutdown request wind IDLE down cleanly (send DONE).
        if shutdown.load(Ordering::SeqCst) {
            done.store(true, Ordering::SeqCst);
        }
        match idle.resume(fragmentizer, arg.take()) {
            // Untagged data: end IDLE, then resync.
            ImapCoroutineState::Yielded(ImapIdleYield::Event(_)) => {
                done.store(true, Ordering::SeqCst);
                if !shutdown.load(Ordering::SeqCst) {
                    // Drive the DONE round to completion, then resync.
                    return drain_idle(stream, fragmentizer, &mut idle).await.map(|()| {
                        if shutdown.load(Ordering::SeqCst) {
                            IdleOutcome::Shutdown
                        } else {
                            IdleOutcome::Data
                        }
                    });
                }
            }
            ImapCoroutineState::Yielded(ImapIdleYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).await.context("write failed")?;
            }
            ImapCoroutineState::Yielded(ImapIdleYield::WantsRead) => {
                match timeout(IDLE_REFRESH, stream.read(&mut buf)).await {
                    Ok(Ok(0)) => bail!("connection closed by peer"),
                    Ok(Ok(n)) => arg = Some(&buf[..n]),
                    Ok(Err(err)) => return Err(err).context("read failed"),
                    // Refresh window elapsed: drop and reconnect.
                    Err(_elapsed) => return Ok(IdleOutcome::Refresh),
                }
            }
            ImapCoroutineState::Complete(Ok(())) => {
                return Ok(if shutdown.load(Ordering::SeqCst) {
                    IdleOutcome::Shutdown
                } else {
                    IdleOutcome::Refresh
                });
            }
            ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
        }
    }
}

/// Drives an IDLE coroutine whose `done` flag is already set to completion
/// (writing DONE, reading the tagged response). A separate `buf`/`arg` scope
/// keeps the borrow checker happy across the two read loops.
async fn drain_idle<S>(
    stream: &mut S,
    fragmentizer: &mut Fragmentizer,
    idle: &mut ImapIdle,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = [0u8; READ_BUF];
    let mut arg: Option<&[u8]> = None;
    loop {
        match idle.resume(fragmentizer, arg.take()) {
            ImapCoroutineState::Yielded(ImapIdleYield::Event(_)) => {}
            ImapCoroutineState::Yielded(ImapIdleYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).await.context("write failed")?;
            }
            ImapCoroutineState::Yielded(ImapIdleYield::WantsRead) => {
                let n = stream.read(&mut buf).await.context("read failed")?;
                if n == 0 {
                    bail!("connection closed by peer");
                }
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Complete(Ok(())) => return Ok(()),
            ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
        }
    }
}

/// Fetches the fresh `UIDNEXT` by re-EXAMINE-ing the (read-only) mailbox.
async fn examine_uid_next<S>(
    stream: &mut S,
    fragmentizer: &mut Fragmentizer,
    mailbox: &Mailbox<'static>,
) -> Result<Option<NonZeroU32>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let examine = ImapMailboxExamine::new(mailbox.clone(), ImapMailboxExamineOptions::default());
    let data = run(stream, fragmentizer, examine).await??;
    Ok(data.uid_next)
}

/// The IDLE-only mailbox watcher, for servers that support IDLE but **not**
/// QRESYNC (e.g. Gmail, Yahoo). It tracks **new messages only**: it keeps the
/// mailbox's `UIDNEXT`, and on each IDLE wake re-EXAMINEs and `UID FETCH`es any
/// UIDs that appeared since, emitting one `new` event each. Flag changes and
/// deletions are not tracked (that needs QRESYNC/CONDSTORE — the `run_watch`
/// path). Read-only throughout (EXAMINE + FETCH + IDLE, never a write).
///
/// Returns `Ok(())` on a clean wind-down or the periodic refresh (the caller
/// reconnects), `Err` on a connection failure.
pub async fn run_watch_idle<S>(
    account: &str,
    stream: &mut S,
    fragmentizer: &mut Fragmentizer,
    mailbox: Mailbox<'static>,
    shutdown: Arc<AtomicBool>,
    events: &mpsc::Sender<ChangeEvent>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Baseline: the UID the next new message will get. Anything >= this that
    // later appears is new mail.
    let mut next_uid = match examine_uid_next(stream, fragmentizer, &mailbox).await? {
        Some(uid) => uid,
        None => bail!("server did not report UIDNEXT; cannot track new mail without QRESYNC"),
    };
    debug!(watch = %account, uid_next = next_uid.get(), "idle-only watch (new mail only)");

    loop {
        match idle_once(stream, fragmentizer, &shutdown).await? {
            IdleOutcome::Shutdown | IdleOutcome::Refresh => return Ok(()),
            IdleOutcome::Data => {}
        }

        let Some(new_next) = examine_uid_next(stream, fragmentizer, &mailbox).await? else {
            continue;
        };
        if new_next <= next_uid {
            // Woke for something other than new mail (a flag change / expunge
            // we don't track without QRESYNC).
            continue;
        }

        // Fetch just the new UIDs: `UID FETCH <next_uid>:<new_next - 1> (UID)`.
        // A bounded range (not `:*`) avoids the "UIDNEXT:* returns the last
        // message" gotcha.
        let end = NonZeroU32::new(new_next.get() - 1).expect("new_next > next_uid >= 1");
        let range: SequenceSet = format!("{}:{}", next_uid.get(), end.get())
            .as_str()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid UID range"))?;
        let items =
            MacroOrMessageDataItemNames::MessageDataItemNames(vec![MessageDataItemName::Uid]);
        let fetch = ImapMessageFetch::new(
            range,
            items,
            ImapMessageFetchOptions {
                uid: true,
                modifiers: Vec::new(),
            },
        );
        let fetched = run(stream, fragmentizer, fetch).await??;

        let mut uids: Vec<NonZeroU32> = fetched
            .into_values()
            .filter_map(|items| {
                items.into_inner().into_iter().find_map(|item| match item {
                    MessageDataItem::Uid(uid) => Some(uid),
                    _ => None,
                })
            })
            .filter(|uid| *uid >= next_uid)
            .collect();
        uids.sort();

        for uid in uids {
            if events
                .send(ChangeEvent::new_mail(account, uid.get()))
                .await
                .is_err()
            {
                bail!("delivery channel closed");
            }
        }
        next_uid = new_next;
    }
}
