---
cairn: spec
capability: hardening
status: current
---

# Hardening

This is the production posture that takes Carillon from prototype to running unattended on the public internet, holding tens of thousands of standing IMAP IDLE connections and taking money on one cheap VPS (single SQLite store, vertical scale). Requirements are ordered by blast radius: the higher-value axes come first and gate public exposure. Some are already landed in code; the rest are ops/config or documented gaps.

Threat model: Carillon holds two things worth stealing — **credentials** (age-encrypted IMAP passwords plus OAuth refresh tokens) and the **ability to make the server open connections** to arbitrary IMAP hosts and webhook URLs. It is deliberately content-free, so a breach leaks metadata plus credentials, never mail. The two highest-value hardening axes are therefore **key custody** and **egress control (SSRF)**; everything below is prioritised by that blast radius. See [[architecture]] for the runtime shape, [[webhooks]] for the delivery contract, and [[auth]] for identity.

### Requirement: Block SSRF on the public request surface
Endpoints that cause the server to originate connections to caller-supplied destinations SHALL NOT be able to reach internal addresses. Six endpoints are unauthenticated (rate-limited only) and originate outbound connections: `/discover` (HTTP to autoconfig/DNS), `/test` and `/mailboxes` (TLS connect to `imap_host:imap_port`, an arbitrary internal port-scan risk), `/webhook/test` (POST to `notify_url`, SSRF including `http://` loopback), and `/oauth/start` + `/oauth/callback` (outbound token exchange). This is the highest-priority axis and SHALL be closed before any public exposure. See [[webhooks]] for the delivery path this gates.

#### Scenario: A webhook target resolves to an internal address
- **GIVEN** a create-watch or `/webhook/test` request whose notify URL resolves to a loopback, RFC1918, IPv6 ULA, link-local (including `169.254.169.254`), unspecified, CGNAT, or v4-mapped address
- **WHEN** `guard::check_url_host()` classifies the destination with `allow_private_targets = false` (the production default)
- **THEN** the request is refused, even for an `http://` loopback target that `validate_notify_url` would otherwise permit by scheme

### Requirement: Rebinding-safe destination validation
Outbound connections SHALL resolve a caller-supplied host to one validated address and connect to that address directly, so a DNS rebind between the check and the connect cannot redirect to an internal target. `guard::resolve_allowed()` SHALL classify and pin the address that `session::open` then uses; `src/guard.rs` SHALL remain unit-tested. The private-target block SHALL be off only under an explicit opt-in (`[server] allow_private_targets = true`) reserved for self-host/dev.

### Requirement: Guard derived-host outbound requests
`/discover` and the OAuth token exchange, which originate outbound requests inside `io-pim-discovery` / `io-oauth` to derived (not fully arbitrary) hosts, SHALL be brought under the same address guard via a custom resolver in those libraries.

### Requirement: Egress firewall as defence in depth
The host or security group SHALL restrict outbound traffic to only :993, :443, :80, and DNS, and SHALL deny the cloud metadata IP and RFC1918 ranges at the network level, independent of the in-process guard.

### Requirement: Layered and sanitised request limits
The existing per-`(IP,login)` and per-IP rate limiters SHALL be retained, a **global** ceiling SHALL be added, and the reverse proxy SHALL rate-limit in front as well. Error strings returned from these probes SHALL be capped and sanitised so they do not become an oracle for internal network topology.

### Requirement: Custody of the age key
The age key (`server.age_key_file`) decrypts every stored credential and is the crown jewel: losing it bricks every watch, and leaking it plus a DB dump is full credential compromise. It SHALL be generated offline, stored `0600` owned by the service user, and backed up out-of-band — never in the same bucket as the DB. It SHALL be delivered via systemd `LoadCredential=` / `systemd-creds` or a secrets manager in preference to a plaintext file on disk. See [[architecture]] on credential custody as the adoption ground.

### Requirement: Custody of the admin, billing, and OAuth secrets
The `api.admin_token` is an unscoped god token and SHALL be a long random value, scoped to ops, and required in production (fail closed) rather than optional. The Stripe secret key, the Stripe webhook signing secret, and the OAuth client secrets SHALL be handled the same way — never in the repo and never in plaintext env in the unit file, delivered via `LoadCredential=`. See [[auth]] for the identity surface these protect.

### Requirement: Secret rotation runbook
There SHALL be a documented runbook to rotate the age key (a decrypt-all / re-encrypt-all migration), the admin token, and the per-watch HMAC secrets (already supported via `/rotate-secret` with overlap).

### Requirement: TLS, network, and host baseline
API TLS SHALL terminate at a reverse proxy (Caddy with auto Let's Encrypt, or nginx + certbot) with HSTS, TLS 1.2+, OCSP stapling, and auto-renew; the app SHALL listen on loopback with only the proxy public. Inbound firewall SHALL allow only 443 (plus restricted 22). The systemd unit SHALL run as a dedicated non-root user with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `ReadWritePaths=` scoped to the data dir, and `Restart=on-failure` with `RestartSec`. `api.cors_allow_origin` SHALL be the exact dashboard origin (never `*` in production), with `public_url` / `dashboard_url` set to the real hosts.

### Requirement: Capacity for the 10^4-IDLE-connection box
The box SHALL be tuned for the FD- and memory-bound workload of holding tens of thousands of idle sockets. `LimitNOFILE` SHALL be 100k+ with matching `fs.file-max` and `fs.nr_open`; sysctl SHALL widen `net.ipv4.ip_local_port_range` and raise `net.core.somaxconn` and `net.netfilter.nf_conntrack_max` (with `nf_conntrack` timeouts), since there is one conntrack entry per held connection. `server.max_concurrent_handshakes` SHALL be tuned against provider rate limits and CPU to throttle the reconnect thundering herd. RSS SHALL be measured under load and `MemoryMax=` set with headroom. The vertical ceiling and connection budget SHALL be documented, along with the horizontal shard-by-`mailbox_key` story: because the store is local SQLite, scaling out needs either sharded independent nodes each owning a mailbox-key range or a shared store. See [[architecture]] for the single-VPS topology.

### Requirement: Data durability and retention
The unbounded-growth `delivery` table SHALL have a periodic prune (keep N days) plus a `VACUUM` / WAL-checkpoint schedule. The WAL-mode SQLite store SHALL be backed up via continuous replication (Litestream) or scheduled snapshots with a tested restore; the age key SHALL be backed up separately and never in the same bucket as the DB. The `migrate()` path SHALL be exercised on a copy before each deploy and migrations kept forward-only and idempotent. Stale `oauth_session` rows SHALL be confirmed to age out.

### Requirement: Harden the real billing adapter
The `StubBilling` placeholder SHALL be replaced by a real payment adapter (Stripe Checkout hosted). The Stripe webhook SHALL verify the signature, enforce idempotency (the store's `checkout_session.fulfilled` fulfil-once flag), reject replays, and reconcile daily against Stripe as a backstop. The existing money invariants (trial drains before pool; pool is the only paid counter) SHALL be kept, with alerting added on negative balances and refunds.

### Requirement: Observability and reliability
A `/metrics` Prometheus endpoint SHALL expose active watches, connected/reconnecting counts, delivery success/latency/attempts, metering debits, pool exhaustion, age-key/decrypt errors, and oauth-refresh failures. Structured `tracing` logs SHALL be shipped to a store with sensitive fields scrubbed and the Gmail capability kept at `debug!`. The existing `/health` endpoint SHALL be wired to an external uptime monitor with cert-expiry and disk-space alerts, and delivery-failure spikes and mass reconnects SHALL be alerted on. A silently dead socket is a missed notification — the worst failure mode — so liveness and delivery must be observable. See [[architecture]] on dead-socket detection.

#### Scenario: A poison endpoint always fails
- **GIVEN** a webhook target that always returns 5xx
- **WHEN** it burns delivery retries across sustained events
- **THEN** the watch is auto-paused (with a `notice`) after sustained delivery failure so one bad endpoint does not starve retries for others

### Requirement: Provider app verification as a parallel long-lead track
Provider verification and legal SHALL run in parallel from day one because of long lead times. Google's `https://mail.google.com/` scope is restricted and the hosted app needs a CASA security assessment (paid, annual) before public verification; self-hosters who bring their own client ID sidestep it. Microsoft needs publisher verification (free). SaaS legal SHALL provide a privacy policy (leading with content-free), ToS, DPA, and GDPR data-deletion on signout/close (the footprint is login + host + encrypted secret + URL); these gate app verification and app-store/Play listing. See [[auth]] for the OAuth surface.

---

The blast-radius priority order is the spine of this spec: SSRF/egress lockdown and secret custody come before any public exposure, then TLS/proxy/systemd/firewall/capacity, then backups and retention, then real billing, then metrics/alerting/circuit-breaking, with provider verification and legal running in parallel from day one.
