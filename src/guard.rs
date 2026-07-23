//! SSRF egress guard.
//!
//! Several public, unauthenticated endpoints make the server originate
//! connections to caller-supplied destinations (`/test` and
//! `/mailboxes` TLS-connect to an arbitrary `imap_host:port`;
//! `/webhook/test` and a created watch POST to an arbitrary URL).
//! Without a guard those become an internal port-scanner and an SSRF
//! into loopback or the cloud metadata service.
//!
//! Destination IPs are classified and a host is resolved to a single
//! validated address, so the caller connects to exactly what was
//! checked (closing the DNS-rebinding TOCTOU window). Private targets
//! are refused unless the operator opts in with
//! `[server] allow_private_targets`.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};
use tokio::net::lookup_host;
use url::Url;

/// Process-wide policy set once at startup. `None`/`false` blocks
/// private targets (the secure default); `true` permits them.
static ALLOW_PRIVATE: OnceLock<bool> = OnceLock::new();

/// Sets the process-wide egress policy from config. Idempotent; the
/// first call wins.
pub fn set_allow_private_targets(allow: bool) {
    let _ = ALLOW_PRIVATE.set(allow);
}

fn allow_private() -> bool {
    *ALLOW_PRIVATE.get().unwrap_or(&false)
}

/// Whether to refuse originating a connection to this IP: anything not
/// a globally-routable unicast address (loopback, private (RFC1918 /
/// IPv6 ULA), link-local including the cloud metadata address
/// `169.254.169.254`, unspecified, multicast, broadcast, and the
/// `0.0.0.0/8` / CGNAT ranges).
pub fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                // NOTE: 0.0.0.0/8 ("this network") and 100.64.0.0/10
                // (CGNAT).
                || v4.octets()[0] == 0
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || is_unique_local_v6(v6)
                || is_link_local_v6(v6)
                // NOTE: an IPv4-mapped address (`::ffff:a.b.c.d`) is
                // only as safe as its embedded IPv4; validate that.
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_blocked_ip(&IpAddr::V4(v4)))
        }
    }
}

/// IPv6 unique-local `fc00::/7` (`Ipv6Addr::is_unique_local` is unstable).
fn is_unique_local_v6(ip: &Ipv6Addr) -> bool {
    (ip.octets()[0] & 0xfe) == 0xfc
}

/// IPv6 link-local `fe80::/10` (`Ipv6Addr::is_unicast_link_local` is unstable).
fn is_link_local_v6(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// Resolves `host:port` and returns the first allowed socket address.
///
/// The caller must connect to this address (not re-resolve the host) to
/// stay rebinding-safe. Errors if the host resolves to nothing, or only
/// to blocked addresses with the private-target opt-in off.
pub async fn resolve_allowed(host: &str, port: u16) -> Result<SocketAddr> {
    let allow = allow_private();
    let addrs = lookup_host((host, port))
        .await
        .with_context(|| format!("cannot resolve host '{host}'"))?;

    let mut saw_any = false;
    for addr in addrs {
        saw_any = true;
        if allow || !is_blocked_ip(&addr.ip()) {
            return Ok(addr);
        }
    }

    if saw_any {
        bail!(
            "refusing to connect to a private/loopback address for host '{host}' \
             (set [server] allow_private_targets = true for local/self-host use)"
        );
    }
    bail!("host '{host}' resolved to no addresses");
}

/// Validates that a URL's host is a permitted egress target: an IP
/// literal is checked directly, a name is resolved and validated. Used
/// before POSTing to a caller-supplied webhook URL.
pub async fn check_url_host(url: &Url) -> Result<()> {
    let host = url.host_str().context("URL has no host")?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        if !allow_private() && is_blocked_ip(&ip) {
            bail!(
                "refusing to send to a private/loopback address \
                 (set [server] allow_private_targets = true for local/self-host use)"
            );
        }
        return Ok(());
    }

    let port = url.port_or_known_default().unwrap_or(443);
    resolve_allowed(host, port).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn blocks_loopback_private_linklocal_metadata() {
        for s in [
            "127.0.0.1",
            "127.9.9.9",
            "10.0.0.5",
            "172.16.3.4",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "169.254.0.1",
            "0.0.0.0",
            "100.64.0.1", // CGNAT
            "::1",
            "fe80::1", // link-local
            "fc00::1", // ULA
            "fd12:3456::1",
            "::ffff:127.0.0.1", // v4-mapped loopback
            "::ffff:10.0.0.1",  // v4-mapped private
        ] {
            assert!(is_blocked_ip(&ip(s)), "expected blocked: {s}");
        }
    }

    #[test]
    fn allows_public_addresses() {
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "142.250.1.1", // gmail-ish
            "2606:4700:4700::1111",
            "2a00:1450:400c::1", // google v6
        ] {
            assert!(!is_blocked_ip(&ip(s)), "expected allowed: {s}");
        }
    }
}
