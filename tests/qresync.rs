//! Regression guard for the imap-types capability-mapping bug.
//!
//! imap-types 2.0.0-alpha.6 mapped the "QRESYNC" and "CONDSTORE"
//! capability atoms to `Capability::Unselect`, which made io-imap's
//! `ImapMailboxWatch::new` reject every server ("does not advertise
//! QRESYNC"). Fixed upstream in imap-types 2.0.0-alpha.7 (pulled via
//! imap-codec alpha.9); the earlier vendored `[patch.crates-io]`
//! workaround has been removed. This test fails loudly if a resolved
//! imap-types ever regresses the mapping.

use io_imap::types::core::Atom;
use io_imap::types::response::Capability;

#[test]
fn qresync_and_condstore_atoms_map_correctly() {
    let qresync = Atom::try_from("QRESYNC").expect("valid atom");
    assert_eq!(
        Capability::from(qresync),
        Capability::QResync,
        "QRESYNC must parse to Capability::QResync (patched imap-types)",
    );

    let condstore = Atom::try_from("CONDSTORE").expect("valid atom");
    assert_eq!(
        Capability::from(condstore),
        Capability::CondStore,
        "CONDSTORE must parse to Capability::CondStore (patched imap-types)",
    );

    // Sanity: UNSELECT still maps to itself.
    let unselect = Atom::try_from("UNSELECT").expect("valid atom");
    assert_eq!(Capability::from(unselect), Capability::Unselect);
}
