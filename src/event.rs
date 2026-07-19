//! The canonical, content-free change event.
//!
//! Every watcher, whatever the source protocol, folds its native
//! change into this single shape. It carries *that* something changed
//! and *which* UID — never the sender, subject or body. Enriching the
//! notification is the consumer's job (it holds the credentials); the
//! signal Carillon emits stays pure.

use io_imap::watch::ImapMailboxWatchEvent;
use serde::Serialize;

/// The kind of change observed on a mailbox.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// A message appeared (new UID).
    New,
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
            ChangeKind::FlagsAdded => "flags_added",
            ChangeKind::FlagsRemoved => "flags_removed",
            ChangeKind::Removed => "removed",
        }
    }
}

/// The signed payload POSTed to a watch's notify URL.
#[derive(Clone, Debug, Serialize)]
pub struct ChangeEvent {
    /// The watch (account) identifier this change belongs to.
    pub account: String,
    /// What changed.
    pub event: ChangeKind,
    /// The affected message UID.
    pub uid: u32,
}

impl ChangeEvent {
    /// Folds a native IMAP watch event into the canonical shape,
    /// tagging it with the owning account.
    pub fn from_watch(account: impl Into<String>, event: &ImapMailboxWatchEvent) -> Self {
        let (kind, uid) = match event {
            ImapMailboxWatchEvent::EnvelopeAdded { uid, .. } => (ChangeKind::New, uid.get()),
            ImapMailboxWatchEvent::FlagsAdded { uid, .. } => (ChangeKind::FlagsAdded, uid.get()),
            ImapMailboxWatchEvent::FlagsRemoved { uid, .. } => {
                (ChangeKind::FlagsRemoved, uid.get())
            }
            ImapMailboxWatchEvent::EnvelopeRemoved { uid } => (ChangeKind::Removed, uid.get()),
        };

        Self {
            account: account.into(),
            event: kind,
            uid,
        }
    }
}
