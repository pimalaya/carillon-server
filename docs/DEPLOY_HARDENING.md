# Carillon: Production Deploy Hardening Plan

The prototype is functionally complete (watch → signed webhook, metering, OAuth, onboarding). This is the checklist that takes it from "runs on my machine" to "runs unattended, holding tens of thousands of standing IMAP IDLE connections, taking money, on the public internet." Ordered by blast radius. Items marked **[gap]** need code; the rest are ops/config.

The MVP target is deliberately one cheap VPS (single sqlite store, vertical scale). Everything below assumes that shape and calls out where it breaks.

---

## 0. Threat model in one paragraph

Carillon holds two things worth stealing: **credentials** (age-encrypted IMAP passwords + OAuth refresh tokens) and the **ability to make the server open connections** (to arbitrary IMAP hosts and webhook URLs). It is deliberately content-free, so a breach leaks metadata + credentials, never mail. The two highest-value hardening axes are therefore **key custody** and **egress control (SSRF)**.

---

## 1. SSRF & the public request surface **[highest priority]**

Six endpoints are unauthenticated (rate-limited only) and cause the server to originate connections to caller-supplied destinations:

| Endpoint | Server action | Risk |
|---|---|---|
| `/discover` | outbound HTTP to autoconfig/DNS | SSRF (GET) |
| `/test`, `/mailboxes` | TLS connect to `imap_host:imap_port` | **arbitrary internal port scan** |
| `/webhook/test` | POST to `notify_url` | **SSRF incl. `http://` loopback** |
| `/oauth/start`,`/oauth/callback` | outbound token exchange | SSRF (fixed hosts) |

Mitigations:
- **[LANDED] Block internal targets**: src/guard.rs classifies destination IPs (loopback, RFC1918, IPv6 ULA, link-local incl. `169.254.169.254`, unspecified, CGNAT, v4-mapped) and `resolve_allowed()` resolves a host to one **validated address** that `session::open` then connects to directly (rebinding-safe). `guard::check_url_host()` gates the webhook path (`create_watch` + `/webhook/test`). Off by default; `[server] allow_private_targets = true` opts in for self-host/dev. Unit-tested.
- **[LANDED] `http://` loopback** now falls under the same flag: with `allow_private_targets = false` (production default) a loopback webhook target is refused even though `validate_notify_url` permits the `http` scheme.
- **[gap] `/discover` + OAuth token exchange** still originate outbound requests inside `io-pim-discovery` / `io-oauth` (derived, not fully arbitrary hosts); guarding those needs a custom resolver in those libs, a follow-up.
- **Egress firewall** (belt-and-suspenders): allow outbound only to :993, :443, :80, DNS; deny the metadata IP and RFC1918 at the host/security-group level.
- Keep the existing per-`(IP,login)` / per-IP rate limiters; add a **global** ceiling and put the reverse proxy's rate limiting in front as well.
- Cap and sanitise error strings returned from these probes (already mostly done) so they don't become an oracle for internal topology.

---

## 2. Secrets & key custody

- **age key (`server.age_key_file`)** decrypts every stored credential: it is the crown jewel. Generate offline, store `0600` owned by the service user, **back it up out-of-band** (losing it bricks every watch; leaking it + a DB dump = full credential compromise). Prefer delivery via **systemd `LoadCredential=`/`systemd-creds`** or a secrets manager over a file on disk.
- **`api.admin_token`** is a god token (unscoped access to every account). Set a long random value, deliver it the same way, and scope its use to ops. Consider making it **required** in production (fail closed) rather than `Option`.
- **Stripe secret key + webhook signing secret**, **OAuth client secrets**: same handling, never in the repo, never in plaintext env in the unit file; use `LoadCredential=`.
- **Rotation runbook**: document how to rotate the age key (decrypt-all / re-encrypt-all migration), admin token, and HMAC secrets (already supported per-watch via `/rotate-secret` with overlap).

---

## 3. TLS, network & host

- **API TLS**: terminate at a reverse proxy (Caddy = auto Let's Encrypt, or nginx + certbot). HSTS, TLS 1.2+, OCSP stapling, auto-renew. The app listens on loopback; only the proxy is public.
- **Firewall**: inbound 443 (+22 restricted) only; egress as in §1.
- **systemd unit hardening**: dedicated non-root user, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `ReadWritePaths=` just the data dir, `Restart=on-failure`, `RestartSec`.
- **CORS**: set `api.cors_allow_origin` to the exact dashboard origin (never `*` in production). `public_url`/`dashboard_url` set to the real hosts.

---

## 4. Capacity: the 10⁴-IDLE-connection box

The whole point is holding a lot of idle sockets. That is FD- and memory-bound, not CPU-bound:
- **`LimitNOFILE`** in the unit → 100k+; matching `fs.file-max`, `fs.nr_open`.
- **sysctl**: widen `net.ipv4.ip_local_port_range`, raise `net.core.somaxconn`, `net.netfilter.nf_conntrack_max` (+ `nf_conntrack` timeouts): one entry per held connection.
- **`server.max_concurrent_handshakes`** already throttles the thundering herd on reconnect; tune it against provider rate limits and CPU.
- **[gap] Document the vertical ceiling** and the shard-by-`mailbox_key` horizontal story. The store is **local sqlite**, so scaling out needs either sharded independent nodes (each owning a mailbox-key range) or a shared store. Until then, one big box; publish the connection budget.
- Memory: ~small per connection (fetch buffers are UID/FLAGS only, bounded by `MAX_MESSAGE_SIZE`); measure RSS under load and set `MemoryMax=` with headroom.

---

## 5. Data durability & retention

- **[gap] Delivery-log retention**: the `delivery` table grows unbounded. Add a periodic prune (keep N days) + `VACUUM`/WAL checkpoint schedule.
- **Backups**: sqlite in WAL → use **Litestream** (continuous replication to object storage) or scheduled snapshots. Test restore. Back up the age key **separately** and never in the same bucket as the DB.
- **Migrations**: exercise the `migrate()` path on a copy before each deploy; keep them forward-only and idempotent.
- **OAuth session GC**: confirm stale `oauth_session` rows are aged out.

---

## 6. Billing integration (see §8 for the sequence)

- **[gap] Real payment adapter** replacing `StubBilling`: Stripe Checkout (hosted) is simplest, needs the secret key + **webhook signing secret**.
- **Webhook security**: verify the Stripe signature, enforce idempotency (the store's `checkout_session.fulfilled` flag already gives fulfil-once), reject replays, and reconcile daily against Stripe as a backstop.
- **Money invariants** are already good (trial drains before pool; pool is the only paid counter): keep them; add alerting on negative balances / refunds.

---

## 7. Observability & reliability

- **[gap] `/metrics`** (Prometheus): active watches, connected/reconnecting counts, delivery success/latency/attempts, metering debits, pool exhaustion, age-key/decrypt errors, oauth-refresh failures.
- **Logs**: structured `tracing` already in place; ship to a store, scrub any potentially-sensitive fields, keep the Gmail capability `debug!` at debug.
- **Health**: `/health` exists → wire an **external uptime monitor** + cert-expiry + disk-space alerts. Alert on delivery-failure spikes and mass reconnects (provider outage vs our bug).
- **[gap] Poison-endpoint circuit-breaking**: a webhook that always 5xxes burns retries forever across events. Consider auto-pausing a watch (with a `notice`) after sustained delivery failure.

---

## 8. Provider app verification (parallel track, long lead times)

- **Google**: the `https://mail.google.com/` scope is **restricted** → the hosted app needs **CASA** security assessment (paid, annual) before public verification. Start early; self-hosters BYO client ID sidestep it (see the OAuth-client decision doc). Microsoft: publisher verification (free).
- **Legal for SaaS**: privacy policy (lead with content-free), ToS, DPA, GDPR data-deletion on signout/close (data footprint is tiny: login+host+encrypted secret+URL). These gate app verification and app-store/Play too.

---

## 9. Deploy pipeline

- `cargo build --release`; embed the carillon-frontend build via `api.ui_dir` (single origin, no CORS) **or** serve the SPA from a CDN with locked CORS.
- Versioned artifacts, config-file (not env) for secrets via `LoadCredential`, graceful shutdown already handled (SSE drain + supervisor stop), documented rollback. A brief connection blip on deploy is acceptable (watchers reconnect); note it.

---

## Priority order

1. **SSRF/egress lockdown (§1)** + secrets custody (§2): before any public exposure.
2. TLS/proxy/systemd/firewall/capacity (§3, §4).
3. Backups + delivery-log retention (§5).
4. Real billing + Stripe webhook hardening (§6).
5. Metrics/alerting/circuit-breaking (§7).
6. Provider verification + legal (§8), in parallel from day one (long lead).
