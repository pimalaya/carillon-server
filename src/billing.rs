//! Billing — behind a trait so the payment provider is swappable.
//!
//! Payment is **stateless on our side** (§ DECISIONS 3, 5): the provider
//! (Stripe on the web, RevenueCat unifying the app stores) owns the
//! customer and the receipt; Carillon persists only what a paid session
//! grants (watch-seconds) and, on fulfilment, the resulting account
//! balance — never card details or PII. A pack maps to watch-time; its
//! *price* lives in the provider, set on capability, not encoded here.
//!
//! The [`StubBilling`] provider needs no keys and stands in until a real
//! provider is wired: `checkout_url` returns a local placeholder, and the
//! webhook fulfils on trust. A Stripe/RevenueCat impl slots in behind the
//! same [`Billing`] trait (creating a real Checkout Session, verifying the
//! webhook signature) without touching the metering or account code.

/// A prepaid credit pack: what it grants, in watch-seconds. The price is
/// configured in the payment provider, not here.
#[derive(Clone, Copy, Debug)]
pub struct Pack {
    /// Stable pack id (the SKU key the provider prices).
    pub id: &'static str,
    /// Watch-seconds granted on fulfilment.
    pub secs: f64,
}

const DAY: f64 = 86_400.0;

/// The catalogue of packs. Watch-time only — pricing is the provider's.
pub const PACKS: &[Pack] = &[
    Pack {
        id: "week",
        secs: 7.0 * DAY,
    },
    Pack {
        id: "quarter",
        secs: 90.0 * DAY,
    },
    Pack {
        id: "year",
        secs: 365.0 * DAY,
    },
];

/// Looks up a pack by id.
pub fn pack(id: &str) -> Option<Pack> {
    PACKS.iter().copied().find(|pack| pack.id == id)
}

/// A payment-provider adapter. Kept object-safe and synchronous for the
/// stub; a real provider that must call out on checkout would make this
/// async (behind `async-trait`) when it lands.
pub trait Billing: Send + Sync {
    /// The provider name, surfaced to clients.
    fn provider(&self) -> &'static str;

    /// The URL to send the buyer to for a given pending session. A real
    /// provider creates a hosted Checkout Session and returns its URL.
    fn checkout_url(&self, session_id: &str, account_id: &str, pack: &Pack) -> String;
}

/// The keyless stand-in provider.
pub struct StubBilling;

impl Billing for StubBilling {
    fn provider(&self) -> &'static str {
        "stub"
    }

    fn checkout_url(&self, session_id: &str, _account_id: &str, _pack: &Pack) -> String {
        format!("https://checkout.stub.local/pay/{session_id}")
    }
}
