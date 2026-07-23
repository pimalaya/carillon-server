---
cairn: spec
capability: production
status: current
---

# Production

Go-live for the MVP is a single 4 GB / 2 vCore VPS holding many standing IMAP IDLE connections, with a local SQLite store and no HA. The box listens on loopback only behind a reverse proxy that is the sole public surface. This is a sequenced runbook executed in order: (0) prerequisites — DNS, Stripe, Resend, object storage, a CI-built frontend, and the age key generated offline; (1) host baseline — dedicated no-shell user, kernel/socket tuning, firewall; (2) secrets — age key and config sealed as encrypted credentials; (3) build & install binary + same-origin UI; (4) hardened systemd service + auto-TLS reverse proxy; (5) continuous DB backup + delivery-log retention; (6) observability & alerting; (7) a hard go-live gate that must fully pass before public exposure; (8) post-launch code fast-follows plus the long-lead CASA/legal track. The load-bearing constraints of each phase are captured as requirements below. See [[architecture]] for the runtime shape, and [[hardening]] and [[nixos]] for the blast-radius checklist and declarative host binding.

### Requirement: Memory-bound connection budget
Standing IMAP IDLE SHALL be treated as file-descriptor- and memory-bound, not CPU-bound. The box SHALL budget roughly 60 KB RSS per connection and reserve about 1.5 GB for the OS, reverse proxy, backup agent, SQLite page cache, delivery worker, and reconnect-storm headroom, leaving roughly 2.5 GB usable. The theoretical connection ceiling SHALL NOT be published as a capacity promise; launch SHALL start with a soft cap of 5000 mailboxes, instrument RSS at 500 / 1000 / 2000, and raise the cap only after a load test. Operators SHALL account for provider-side per-account and per-IP simultaneous-connection caps often being the true binding limit.

### Requirement: Memory hard stop and fair-use caps
The service SHALL enforce `MemoryMax=3G` as a hard stop with `MemoryHigh=2.5G` throttling first. The per-account fair-use cap `server.max_watches_per_account` SHALL be set (default 25), and until an in-app global concurrent-watch ceiling exists, a global ceiling SHALL be enforced at the reverse proxy or WAF.

### Requirement: File descriptor and ephemeral port headroom
The host SHALL raise file-descriptor limits well above the connection count (one FD per held socket plus short-lived delivery sockets) via `fs.file-max` and `fs.nr_open`, and the service unit SHALL set `LimitNOFILE` to at least 262144. The outbound ephemeral port range SHALL be widened (e.g. `ip_local_port_range = 10240 65535`) because each held IMAP connection consumes one ephemeral port.

### Requirement: Conntrack table and established timeout
The netfilter conntrack table SHALL be raised (e.g. `nf_conntrack_max = 262144`) to hold one long-lived entry per connection, and the established-connection timeout (`nf_conntrack_tcp_timeout_established`) SHALL be kept well above the ~29-minute IDLE re-issue bound (the default 5 days is acceptable). This timeout SHALL NOT be lowered below that bound, or idle-but-alive connections are silently dropped and notifications are missed.

### Requirement: TCP keepalive below NAT idle cutoffs
TCP keepalive SHALL be tuned below any NAT or provider idle cutoff (e.g. `tcp_keepalive_time = 300` with periodic probes) so that dead peers are detected and the flow stays live between IDLE re-issues.

### Requirement: Dedicated no-shell service user
The daemon SHALL run as a dedicated system user with no login shell and no home login, and SHALL listen on loopback only (`127.0.0.1:3000`) so the reverse proxy is the only public surface.

### Requirement: Reverse proxy with automatic TLS
A reverse proxy (Caddy) SHALL terminate TLS with automatic certificate issuance and renewal, serve valid HSTS, and reverse-proxy to the loopback app. The app SHALL serve the frontend build same-origin (Mode 2, single origin) so there is no CORS, no cross-origin, and no cookies. The frontend SHALL be built in CI, never on the box, keeping the Node toolchain off the host.

### Requirement: Host patching and intrusion baseline
The host SHALL run `fail2ban` guarding SSH and `unattended-upgrades` for automatic patching, both enabled at boot.

### Requirement: Firewall ingress and egress
The firewall (nftables) SHALL default-drop inbound and permit only SSH, ACME (80), and HTTPS (443), plus established/related and loopback. Egress SHALL remain open to the public internet (customer webhooks target arbitrary HTTPS hosts and cannot be allow-listed) but SHALL drop the cloud metadata IP (169.254.0.0/16) and RFC1918 / ULA ranges as an SSRF backstop behind the application guard. The same metadata + private-range deny SHALL also be applied at the service unit via `IPAddressDeny`, allowing loopback and public egress.

### Requirement: age key generated offline
The `age` credential-encryption key SHALL be generated offline on a workstation with `0600` permissions, never on the VPS, and its backup SHALL exist before go-live.

### Requirement: age key custody and out-of-band backup
The age key SHALL be backed up in two out-of-band locations (e.g. a password manager plus an offline copy) and SHALL NEVER be stored in the same bucket or snapshot as the database backup. Losing the age key bricks every watch (all mailbox credentials become undecryptable); leaking it together with a database dump is a full credential compromise. Both conditions SHALL be treated as catastrophic in custody decisions.

### Requirement: Secrets delivered as encrypted credentials
The config file SHALL hold no plaintext secrets: every secret SHALL be supplied via its `*_file` variant (`admin_token_file`, `stripe.secret_key_file`, `stripe.webhook_secret_file`, `resend.api_key_file`, and the path-based `server.age_key_file`), delivered as an encrypted systemd credential materialized into a private tmpfs readable only by the service user and absent from the persistent disk and the daily snapshot. Plaintext copies of the config and age key SHALL be shredded from the box after sealing. The `admin_token` SHALL be long and random (e.g. `openssl rand -hex 32`). See [[nixos]] for the declarative sops binding of the same `*_file` inputs.

#### Scenario: Host rebuild
- **GIVEN** the systemd host credential secret is lost when the host is rebuilt
- **WHEN** the operator restores service
- **THEN** the encrypted credentials are re-sealed from the offline copies of the config and age key, and no plaintext secret is left on disk

### Requirement: Production security posture defaults
The production config SHALL set `allow_private_targets = false` (SSRF guard on) and SHALL treat `api.admin_token` as required, failing closed and ops-only. The pre-generated age key SHALL be opened read-only so the app never generates one.

### Requirement: Continuous database backup in WAL
The database SHALL be continuously replicated (Litestream) to S3-compatible object storage for a seconds-scale RPO, with the provider snapshot serving only as coarse DR. SQLite SHALL run in WAL mode (required by the replicator). The replicator's object-storage credentials SHALL be delivered as their own credential and SHALL NOT reuse the age key's bucket or credentials. A restore SHALL be rehearsed into a scratch directory before go-live.

### Requirement: Delivery-log retention
Because the `delivery` table grows unbounded and no in-app prune exists yet, an interim nightly ops timer SHALL prune old rows (e.g. older than 30 days) and checkpoint the WAL with `wal_checkpoint(TRUNCATE)`. A full `VACUUM` SHALL be avoided while replication is active, since it rewrites the whole database and forces a re-snapshot. In-app transactional retention SHALL replace this interim timer as a fast-follow.

### Requirement: Observability and alerting
Before go-live the box SHALL have an off-box uptime monitor on `GET /health`, a TLS-expiry alert, a disk-space alert at 70% of capacity (the delivery table is the growth risk), and a memory alert near `MemoryHigh` as the signal to stop taking new watches or scale. Logs SHALL be shipped off `journald` with alerts on delivery-failure spikes, mass reconnects, and age-decrypt or OAuth-refresh errors. Stripe webhook handling SHALL verify signatures and be idempotent, with a daily reconciliation against Stripe as a backstop. See [[webhooks]] for the delivery contract.

### Requirement: Go-live gate
The box SHALL NOT be exposed publicly until every gate check passes: an end-to-end smoke test on the real box (discover, auth magic-link delivery, a live watch that holds IDLE, a verified signed webhook, a live Stripe pack purchase that credits and meters, a service restart with watchers reconnecting and no data loss, and a Litestream restore that resumes watches); `allow_private_targets = false` with SSRF probes to loopback and internal targets refused; every data route returning 401 without a valid bearer and `admin_token` set long and random; secrets present only as encrypted credentials in tmpfs with grep-verified no plaintext on disk and the age key confirmed out of the backup bucket and in two offline places; valid TLS + HSTS with the app unreachable except via loopback; the systemd sandbox active with a low exposure score; replication live with a rehearsed restore; the prune timer installed and dry-run-verified with alerts firing; and `LimitNOFILE`, sysctls, and `MemoryMax` confirmed in effect.

### Requirement: Post-launch fast-follows and long-lead track
After launch the code gaps this runbook works around SHALL be closed in priority order: in-app transactional delivery-log retention, a `/metrics` endpoint, poison-endpoint circuit-breaking that auto-pauses a persistently failing watch, an in-app global concurrent-watch ceiling, and SSRF hardening for discovery and OAuth token exchange. In parallel from day one, the Google CASA assessment (gating hosted Gmail, with Gmail remaining BYO client-id until it clears) and the SaaS legal track (privacy policy, ToS, DPA, GDPR deletion) SHALL run as long-lead items.
