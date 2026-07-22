//! The CardDAV poll pump.
//!
//! One `sync-collection` round: enumerate what changed since the last
//! checkpoint token, fold each changed / removed member into a canonical
//! [`ChangeEvent`], and hand back the next token to checkpoint. The
//! reconnect / backoff / status orchestration lives in the
//! [`supervisor`](crate::supervisor) — this is the CardDAV analogue of
//! [`crate::imap::pump::run_watch`], which likewise only turns protocol
//! changes into events.

use std::sync::Arc;

use anyhow::{Result, bail};
use tokio::sync::{Semaphore, mpsc};
use tokio_rustls::TlsConnector;

use crate::carddav::session::{self, CardDavAccount, SyncPollError};
use crate::event::{ChangeEvent, ChangeKind};

/// Runs one poll of a CardDAV collection.
///
/// `token` is the last checkpoint (`None` means "never synced yet"). A
/// `None` token performs a **baseline** enumeration whose members are
/// *not* emitted — otherwise activating a service would fire one event per
/// existing contact — and only checkpoints the returned token. Every later
/// poll emits the real delta.
///
/// Returns the next token to persist (which may equal `token` if nothing
/// changed, or `None` if the server rejected the token and a fresh baseline
/// is needed). A transport / protocol failure is returned as `Err`, letting
/// the supervisor surface it and back off.
pub async fn poll_once(
    connector: &TlsConnector,
    account: &CardDavAccount,
    watch_id: &str,
    token: Option<String>,
    events: &mpsc::Sender<ChangeEvent>,
    handshake_sem: &Arc<Semaphore>,
) -> Result<Option<String>> {
    // A first-ever sync (no token) enumerates the whole collection; suppress
    // its members so a freshly activated watch does not flood the endpoint.
    let baseline = token.is_none();
    let mut cursor = token;

    loop {
        let permit = handshake_sem
            .clone()
            .acquire_owned()
            .await
            .expect("handshake semaphore never closes");
        let delta = session::sync_changes(connector, account, cursor.as_deref()).await;
        drop(permit);

        let delta = match delta {
            Ok(delta) => delta,
            // The token is no longer valid: reset to a fresh baseline next poll.
            Err(SyncPollError::InvalidToken) => return Ok(None),
            Err(SyncPollError::Other(err)) => return Err(err),
        };

        if !baseline {
            for change in &delta.changed {
                // A poll can't tell a created contact from an edited one (both are
                // just a changed etag), so report the honest "changed".
                let event = ChangeEvent::carddav(
                    watch_id,
                    ChangeKind::Changed,
                    session::resource_id(&change.href),
                );
                if events.send(event).await.is_err() {
                    bail!("delivery channel closed");
                }
            }
            for href in &delta.vanished {
                let event =
                    ChangeEvent::carddav(watch_id, ChangeKind::Removed, session::resource_id(href));
                if events.send(event).await.is_err() {
                    bail!("delivery channel closed");
                }
            }
        }

        let next = delta.sync_token.or_else(|| cursor.clone());

        // Drain a truncated result set (RFC 6578 §3.6) before returning, so a
        // large first sync fully checkpoints in one poll.
        if delta.truncated && next.is_some() && next != cursor {
            cursor = next;
            continue;
        }
        return Ok(next);
    }
}
