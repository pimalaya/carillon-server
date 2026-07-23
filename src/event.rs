//! The canonical, content-free change event.
//!
//! Every watcher folds its native change into this single shape. It
//! carries that something changed and which UID; never the sender,
//! subject or body. Enriching the notification is the consumer's job
//! (it holds the credentials).
//!
//! [`id`](ChangeEvent::id) lets receivers dedupe retries;
//! [`ts`](ChangeEvent::ts) is folded into the signed preimage for
//! replay protection. Both are stamped once, at fold time, so every
//! retry of the same event carries the same id, timestamp and
//! signature.

use io_imap::watch::ImapMailboxWatchEvent;
use rand::RngExt;
use serde::Serialize;

use crate::util::now_secs;

/// The kind of change observed on a mailbox.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// A message appeared (new UID).
    New,
    /// A resource was created or modified. Used by CardDAV, whose
    /// `sync-collection` poll reports a changed member (new or edited,
    /// the same etag change) without distinguishing the two. IMAP splits
    /// new/flags instead.
    Changed,
    /// Flags were set on an existing message.
    FlagsAdded,
    /// Flags were cleared on an existing message.
    FlagsRemoved,
    /// A message left the mailbox (expunged or moved away).
    Removed,
}

impl ChangeKind {
    /// The wire string, matching the JSON `event` field.
    pub fn as_str(&self) -> &'static str {
        match self {
            ChangeKind::New => "new",
            ChangeKind::Changed => "changed",
            ChangeKind::FlagsAdded => "flags_added",
            ChangeKind::FlagsRemoved => "flags_removed",
            ChangeKind::Removed => "removed",
        }
    }
}

/// The signed payload POSTed to a watch's notify URL.
#[derive(Clone, Debug, Serialize)]
pub struct ChangeEvent {
    /// Unique event id (128-bit random, hex), stable across retries so
    /// receivers can dedupe.
    pub id: String,
    /// Unix timestamp (seconds) the event was folded, stable across
    /// retries and signed for replay protection.
    pub ts: i64,
    /// The watch (account) this change belongs to.
    pub account: String,
    /// What changed.
    pub event: ChangeKind,
    /// The affected message UID (IMAP). Omitted for sources that
    /// identify a change by opaque reference (CardDAV, see [`resource`]).
    ///
    /// [`resource`]: ChangeEvent::resource
    #[serde(skip_serializing_if = "is_zero")]
    pub uid: u32,
    /// The changed resource's opaque reference: a CardDAV member href's
    /// last path segment, the content-free analogue of an IMAP UID.
    /// `None` for IMAP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

/// Whether a UID is zero, the "not applicable" sentinel for a CardDAV
/// event (dropping `uid` from its payload). IMAP UIDs are always ≥ 1.
fn is_zero(uid: &u32) -> bool {
    *uid == 0
}

impl ChangeEvent {
    /// Folds a native IMAP watch event into the canonical shape,
    /// stamping a fresh id and timestamp.
    pub fn from_watch(account: impl Into<String>, event: &ImapMailboxWatchEvent) -> Self {
        let (kind, uid) = match event {
            ImapMailboxWatchEvent::EnvelopeAdded { uid, .. } => (ChangeKind::New, uid.get()),
            ImapMailboxWatchEvent::FlagsAdded { uid, .. } => (ChangeKind::FlagsAdded, uid.get()),
            ImapMailboxWatchEvent::FlagsRemoved { uid, .. } => {
                (ChangeKind::FlagsRemoved, uid.get())
            }
            ImapMailboxWatchEvent::EnvelopeRemoved { uid } => (ChangeKind::Removed, uid.get()),
        };
        Self::build(account.into(), kind, uid, None)
    }

    /// A `new`-mail event for a UID, used by the IDLE-only watcher
    /// (which, lacking QRESYNC/CONDSTORE, tracks new messages only).
    pub fn new_mail(account: impl Into<String>, uid: u32) -> Self {
        Self::build(account.into(), ChangeKind::New, uid, None)
    }

    /// Folds a CardDAV addressbook change into the canonical shape.
    ///
    /// There is no UID; the changed member is identified by its opaque
    /// `resource` reference (its href's last segment). Only `changed`
    /// and `removed` occur, since WebDAV has no flag concept.
    pub fn carddav(
        account: impl Into<String>,
        event: ChangeKind,
        resource: impl Into<String>,
    ) -> Self {
        Self::build(account.into(), event, 0, Some(resource.into()))
    }

    fn build(account: String, event: ChangeKind, uid: u32, resource: Option<String>) -> Self {
        Self {
            id: new_id(),
            ts: now_secs(),
            account,
            event,
            uid,
            resource,
        }
    }
}

/// A 128-bit random, hex-encoded event id.
fn new_id() -> String {
    format!("{:032x}", rand::rng().random::<u128>())
}
