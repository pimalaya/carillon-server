//! CardDAV watching: the [`session`] setup + probe and the poll [`pump`].
//!
//! Unlike IMAP (a held IDLE connection), a CardDAV addressbook has no push,
//! so it is watched by periodically running a `sync-collection` REPORT
//! (RFC 6578) and emitting a content-free signal when the collection's
//! sync-token advances. Same two-axis rule: a new *source* protocol, never
//! a richer payload.

pub mod pump;
pub mod session;
