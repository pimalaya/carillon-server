# Carillon — Production Runbook (single 4 GB VPS)

The go-live *execution* plan for the MVP box. Companion to
[`DEPLOY_HARDENING.md`](DEPLOY_HARDENING.md): that doc is the
blast-radius-ordered checklist of **what must be true**; this doc is the
**sequenced how**, tailored to one specific machine, with copy-paste
artifacts, capacity numbers, and a hard go-live gate.

**Target box**

| Resource | Spec | Consequence for Carillon |
|---|---|---|
| CPU | 2 vCore | Idle is cheap; the CPU spike is TLS handshakes during a reconnect storm → throttle it. |
| RAM | 4 GB | The real ceiling. Standing IDLE sockets are memory-bound. `MemoryMax` + a published connection cap. |
| Disk | 40 GB NVMe | Fine for the binary + sqlite, **but the `delivery` table grows unbounded** → retention prune is mandatory. |
| Backup | provider daily snapshot | Coarse DR only. sqlite-in-WAL isn't snapshot-consistent, and the snapshot bundles the age key with the DB → add Litestream + keep the key offsite. |
| Traffic | unlimited, 500 Mbit/s | Non-issue; signals are tiny. |

**Design decisions locked for the MVP** (change deliberately, not by drift):

- **One box, vertical scale, local sqlite.** No HA, no shared store. Accept a
  brief reconnect blip on deploy (watchers reconnect on their own).
- **Front = Mode 2, single origin** ([`SELF_HOST.md`](SELF_HOST.md)). The Rust
  app serves the `carillon-admin` build via `api.ui_dir`; Caddy only
  TLS-terminates and reverse-proxies. **No CORS, no cross-origin, no cookies.**
- **App listens on loopback only** (`127.0.0.1:3000`); the reverse proxy is the
  only public surface.
- **Launch providers = Fastmail (RFC 7591, zero setup) + IMAP password/app-password
  + Microsoft (free publisher verification).** Hosted Gmail is **deferred**
  behind the paid annual CASA assessment — start CASA in parallel (§ Phase 8);
  Google users go BYO-client-ID until it clears.
- **`allow_private_targets = false`** (the production default — SSRF guard on).
- **`api.admin_token` is set and treated as required** — fail closed, ops-only.

---

## Capacity budget for this box

Standing IMAP IDLE is FD- and memory-bound, not CPU-bound.

- **Per-connection RSS**: budget **~60 KB/conn** (rustls session + buffers +
  tokio task + io-imap session state; fetches are UID/FLAGS only).
- **Reserve ~1.5 GB** for OS + Caddy + Litestream + sqlite page cache + the
  delivery worker + **reconnect-storm headroom** (many simultaneous TLS
  handshakes each allocate transiently — this is the spiky part).
- Usable ≈ 2.5 GB ⇒ **theoretical ~40 k** connections, but **do not publish
  that.** Start with a **soft cap of 5 000 mailboxes**, instrument RSS at
  500 / 1 000 / 2 000, and raise only after a load test. In practice the binding
  limit is often **provider-side** (per-account / per-IP simultaneous-connection
  caps), not the box.
- **`MemoryMax=3G`** is the hard stop; `MemoryHigh=2.5G` throttles first.
- Set the fair-use cap `server.max_watches_per_account` (default 25) and, once
  measured, a global ceiling in front (§ Phase 6 has no in-app global cap yet —
  enforce at the proxy).

Kernel tunables that make 10³–10⁴ held sockets possible are in Phase 1.

---

## Phase 0 — Prerequisites (do before touching the box)

- [ ] **DNS**: `carillon.pimalaya.org` (API + UI, one origin) → the VPS public IP.
      A `mail.carillon.pimalaya.org` sending subdomain for magic-link email
      (SPF + DKIM + DMARC, tracking OFF — see [`EMAIL.md`](EMAIL.md)).
- [ ] **Stripe**: live account, one **one-time Price** for the 5-credit pack,
      a webhook endpoint (`/billing/webhook`) → note the `whsec_…` signing secret.
- [ ] **Resend** (or chosen mailer): API key + verified sending subdomain.
- [ ] **Object storage** for Litestream: an S3-compatible bucket (Backblaze B2 /
      Scaleway / OVH) + scoped credentials.
- [ ] **Build `carillon-admin`** on a machine with Node (CI, **not** the VPS —
      keep the Node toolchain off the box). Produce `dist/` with
      `VITE_API_BASE_URL` **empty** (same-origin). Artifact to ship: the `dist/`.
- [ ] **age key generated offline** (§ Phase 2) and its backup already stored in
      **two** out-of-band locations.

---

## Phase 1 — Host baseline

```sh
# Dedicated system user, no shell, no home login.
sudo useradd --system --no-create-home --shell /usr/sbin/nologin carillon

# Base packages: reverse proxy (auto-TLS), sqlite CLI (prune/inspect),
# fail2ban (SSH), unattended-upgrades (patching).
sudo apt update && sudo apt install -y caddy sqlite3 fail2ban unattended-upgrades nftables
sudo systemctl enable --now unattended-upgrades fail2ban nftables
```

**Kernel tunables** — `/etc/sysctl.d/90-carillon.conf`:

```ini
# File descriptors: one per held socket, plus short-lived delivery sockets.
fs.file-max = 1000000
fs.nr_open  = 1048576
# Inbound API backlog (small, but cheap headroom).
net.core.somaxconn = 4096
# Outbound ephemeral ports (one per held IMAP connection).
net.ipv4.ip_local_port_range = 10240 65535
# Keepalive BELOW any NAT/provider idle cutoff, so dead peers are detected and
# the flow stays live between IDLE re-issues (~29 min RFC bound).
net.ipv4.tcp_keepalive_time   = 300
net.ipv4.tcp_keepalive_intvl  = 30
net.ipv4.tcp_keepalive_probes = 5
# conntrack: one long-lived entry per held connection. Raise the table and keep
# the established timeout WELL above the 29-min re-IDLE (default 5 days is fine —
# never lower it, or idle-but-alive connections get silently dropped).
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 432000
```

```sh
sudo sysctl --system
```

**Firewall** — `nftables`. Inbound: SSH + ACME + HTTPS only. Egress: open to
the public internet (webhooks go to *arbitrary* customer HTTPS hosts, so it
can't be allow-listed) **but drop the metadata IP + RFC1918** as defense in
depth behind `guard.rs`. `/etc/nftables.conf`:

```nft
table inet carillon {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    tcp dport 22 accept          # restrict to your admin IP if you have a static one
    tcp dport { 80, 443 } accept # 80 for ACME; 443 for the API/UI
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept
  }
  chain output {
    type filter hook output priority 0; policy accept;
    oif lo accept
    # Block cloud metadata + private ranges (SSRF belt-and-suspenders).
    # NOTE: if this VPS's DNS resolver is on an RFC1918 IP, add an explicit
    # `ip daddr <resolver> accept` ABOVE these drops, or DNS breaks.
    ip daddr 169.254.0.0/16 drop
    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } drop
    ip6 daddr fc00::/7 drop
  }
}
```

```sh
sudo systemctl restart nftables
```

---

## Phase 2 — Secrets (the crown jewels)

Every secret has a **`*_file` variant** (`admin_token_file`,
`billing.stripe.secret_key_file`, `billing.stripe.webhook_secret_file`,
`email.resend.api_key_file`, plus the path-based `server.age_key_file`) — the
daemon reads and trims the value from that file at load. So the config file
itself holds **no secrets**; each secret is delivered as a file by systemd
`LoadCredential`, sops-nix, or any secret manager. Two shapes, pick one:

- **Per-secret `LoadCredential`** (recommended): point each `*_file` at
  `$CREDENTIALS_DIRECTORY/<name>`; each secret is its own encrypted credential,
  materialized into a private tmpfs (`0400`, service user only), never plaintext
  on disk and **not in the daily snapshot**. On NixOS this is what `nix/sops.nix`
  does declaratively (see [`NIXOS.md`](NIXOS.md)).
- **Whole-config credential** (simplest for a hand-rolled box): keep secrets
  inline and encrypt the entire `carillon.toml` as one systemd credential.

The per-secret shape below; the whole-file shape is the same `systemd-creds`
command applied to `carillon.toml` instead of each secret.

```sh
# 1) Generate the age key OFFLINE (on your workstation), 0600.
age-keygen -o age.key
#    Back it up in TWO out-of-band places (password manager + offline copy).
#    Losing it bricks every watch; leaking it + a DB dump = full credential
#    compromise. NEVER store it in the same bucket as the DB backup.

# 2) Author the real carillon.toml (see Phase 3 template) with the live
#    admin_token, Stripe keys, Resend key filled in.

# 3) Encrypt both into systemd credentials (host-key bound; no TPM required).
sudo mkdir -p /etc/carillon
sudo systemd-creds encrypt --name=carillon.toml carillon.toml /etc/carillon/carillon.toml.cred
sudo systemd-creds encrypt --name=age.key        age.key       /etc/carillon/age.key.cred
sudo chmod 600 /etc/carillon/*.cred
#    Then shred the plaintext carillon.toml and age.key from the box.
```

> The host key lives at `/var/lib/systemd/credential.secret` (root-only). If you
> rebuild the host, re-run the two `systemd-creds encrypt` from your offline
> copies. Generate a long random `admin_token` with `openssl rand -hex 32`.

Rotation runbooks (age key = decrypt-all/re-encrypt-all migration; admin token;
per-watch HMAC via `/rotate-secret` with overlap) live in `DEPLOY_HARDENING.md` §2.

---

## Phase 3 — Build & install artifacts

```sh
# Build the release binary (uses the repo's nix flake + the imap-types patch).
nix develop --command cargo build --release
sudo install -m 0755 target/release/carillon-server /usr/local/bin/carillon

# Ship the carillon-admin dist/ (built in CI) to the box, served same-origin.
sudo mkdir -p /var/lib/carillon/ui
sudo rsync -a dist/ /var/lib/carillon/ui/
sudo chown -R carillon:carillon /var/lib/carillon
```

**The `carillon.toml` you encrypted in Phase 2** (production shape):

```toml
[server]
db = "/var/lib/carillon/carillon.db"
# Stable per-unit credentials path (see the systemd unit). The key is
# pre-generated (Phase 2), so the app opens it read-only and never generates.
age_key_file = "/run/credentials/carillon.service/age.key"
max_concurrent_handshakes = 25     # 2 vCore: keep the reconnect storm off both cores
reconcile_interval_secs = 60
# allow_private_targets omitted => false => SSRF guard ON (production posture).
max_watches_per_account = 25

[api]
listen = "127.0.0.1:3000"          # loopback only; Caddy is the public face
ui_dir = "/var/lib/carillon/ui"    # same-origin SPA => no CORS
admin_token = "<openssl rand -hex 32>"
public_url = "https://carillon.pimalaya.org"
# dashboard_url defaults to public_url (single origin) — leave unset.

[oauth.microsoft]
client_id = "<entra public client id>"
# [oauth.google] added only once CASA clears; until then Google = BYO client id.

[billing.stripe]
secret_key = "sk_live_…"
webhook_secret = "whsec_…"
[billing.stripe.prices]
pack = "price_…"                   # the one-time 5-credit pack Price

[email.resend]
api_key = "re_…"
from = "Carillon <no-reply@mail.carillon.pimalaya.org>"
```

---

## Phase 4 — Service + reverse proxy

**`/etc/systemd/system/carillon.service`** — hardened, secrets via credentials,
FD + memory limits, kernel-level SSRF backstop:

```ini
[Unit]
Description=Carillon watch server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=carillon
Group=carillon
ExecStart=/usr/local/bin/carillon serve
Environment=CARILLON_CONFIG=%d/carillon.toml
Environment=RUST_LOG=info,carillon_server=info

# Secrets: config + age key, encrypted at rest, materialized into a private
# tmpfs (%d = /run/credentials/carillon.service), never on the persistent disk.
LoadCredentialEncrypted=carillon.toml:/etc/carillon/carillon.toml.cred
LoadCredentialEncrypted=age.key:/etc/carillon/age.key.cred

# Data dir (creates/owns /var/lib/carillon).
StateDirectory=carillon
ReadWritePaths=/var/lib/carillon

# Capacity.
LimitNOFILE=262144
MemoryHigh=2.5G
MemoryMax=3G
TasksMax=4096

# Restart policy.
Restart=on-failure
RestartSec=5s

# Sandbox.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
RestrictAddressFamilies=AF_INET AF_INET6
CapabilityBoundingSet=

# Kernel-level SSRF backstop (atop guard.rs). Allow loopback (Caddy<->app) +
# public egress; deny metadata + RFC1918. Add your DNS resolver to Allow if
# it is on a private IP.
IPAddressAllow=localhost
IPAddressDeny=169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now carillon
sudo systemctl status carillon      # expect active; check journal for the listen line
```

**`/etc/caddy/Caddyfile`** — auto Let's Encrypt, HSTS, rate-limit the
unauthenticated probe endpoints, proxy everything to the app (which owns both
the API routes and the SPA):

```caddy
carillon.pimalaya.org {
	encode zstd gzip
	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
		X-Content-Type-Options "nosniff"
		Referrer-Policy "strict-origin-when-cross-origin"
	}
	# Belt-and-suspenders rate limit in front of the unauth SSRF-y probes
	# (app keeps its own per-(IP,login) + per-IP limiters). Needs the
	# caddy-ratelimit plugin; otherwise enforce at a WAF/CDN.
	# rate_limit { zone probes { match { path /discover /test /webhook/test /auth /oauth/* } key {remote_host} events 30 window 1m } }
	reverse_proxy 127.0.0.1:3000
}
```

```sh
sudo systemctl reload caddy
```

---

## Phase 5 — Backups & retention

**Continuous DB backup (Litestream)** — the real RPO≈seconds backup; the
provider snapshot is only coarse DR. `/etc/litestream.yml`:

```yaml
dbs:
  - path: /var/lib/carillon/carillon.db
    replicas:
      - type: s3
        endpoint: https://s3.<region>.backblazeb2.com
        bucket: carillon-backup
        path: carillon.db
        # LITESTREAM_ACCESS_KEY_ID / _SECRET_ACCESS_KEY via its own systemd
        # LoadCredential — NOT the age key's bucket, NOT the same creds.
```

Run Litestream as its own hardened unit. **Test a restore** into a scratch dir
before go-live. Confirm the app opens sqlite in **WAL** mode (Litestream
requires it). **The age key is backed up separately, offline, never in this
bucket** (§ Phase 2).

**Delivery-log retention** — the `delivery` table grows unbounded and there is
**no in-app prune yet** (`DEPLOY_HARDENING.md` §5, still a gap). Interim ops
timer, nightly:

`/usr/local/bin/carillon-prune.sh`:
```sh
#!/bin/sh
set -eu
sqlite3 /var/lib/carillon/carillon.db <<'SQL'
PRAGMA busy_timeout = 10000;
DELETE FROM delivery WHERE created_at < strftime('%s','now','-30 days');
PRAGMA wal_checkpoint(TRUNCATE);
SQL
```

> **Avoid full `VACUUM`** while Litestream is replicating (it rewrites the whole
> DB → a huge WAL and forces a re-snapshot). Rely on freelist reuse +
> `wal_checkpoint(TRUNCATE)`. Move this into the app (transactional, same
> connection) as a fast-follow — see Phase 8.

Wire it with a `systemd` timer (daily, `After=carillon.service`). Also GC stale
`oauth_session` rows (confirm the app already ages them out).

---

## Phase 6 — Observability & alerting

No `/metrics` endpoint exists yet (gap). Ship the following now; add Prometheus
in Phase 8.

- [ ] **External uptime monitor** hitting `GET /health` from off-box (UptimeRobot
      / Healthchecks.io) — alert on down.
- [ ] **TLS-expiry alert** (Caddy auto-renews, but monitor the cert anyway).
- [ ] **Disk-space alert** at 70 % of 40 GB — the delivery table is the growth
      risk; this is the smoke alarm if the prune timer ever fails.
- [ ] **Memory alert** near `MemoryHigh` — the signal to stop taking new watches
      / scale the box.
- [ ] **Log shipping**: `journald` → your log store; alert on:
      - spikes in delivery failures (a customer's broken webhook, or our bug),
      - **mass reconnects** (provider outage vs. our regression),
      - `age`-key / decrypt errors and OAuth-refresh failures (credential rot).
- [ ] **Global rate ceiling at Caddy/WAF** until the app grows one.
- [ ] **Stripe reconciliation**: confirm the webhook verifies the signature and
      is idempotent (fulfil-once flag exists); add a daily reconcile against
      Stripe as a backstop and alert on negative balances / refunds.

---

## Phase 7 — Go-live gate (all must pass)

**Smoke test on the real box, one throwaway mailbox:**
1. `POST /discover` → config resolves.
2. `POST /auth` → capability link minted (magic-link email actually arrives, not
   spam-foldered).
3. Create a watch (Fastmail) → it connects, IDLE holds.
4. Send a mail to that box → a **signed webhook** lands at a public HTTPS sink;
   verify the HMAC signature ([`WEBHOOKS.md`](WEBHOOKS.md)).
5. Buy one pack via **Stripe live** → webhook credits the pool; a second watch is
   allowed; metering debits.
6. `systemctl restart carillon` → watchers reconnect within seconds; no data loss.
7. Kill the box's DB, **restore from Litestream** → watches resume.

**Hard gate — do not expose publicly until every box is checked:**
- [ ] `allow_private_targets = false`; `/webhook/test` to `http://127.0.0.1` is **refused**.
- [ ] `/test` to an internal IP/port is **refused** (SSRF guard + firewall).
- [ ] Every data route returns 401 without a valid bearer; `admin_token` is set, long, random.
- [ ] Secrets exist **only** as encrypted credentials + tmpfs — `grep`-verify no plaintext token on disk; the age key is **not** in the DB backup bucket and **is** in two offline places.
- [ ] Caddy serves valid TLS + HSTS; app is unreachable except via loopback (`ss -tlnp`).
- [ ] systemd unit shows the sandbox active (`systemd-analyze security carillon` — aim for a low exposure score).
- [ ] Litestream replicating; a restore has been rehearsed.
- [ ] Prune timer installed and dry-run-verified; disk/mem/uptime/TLS alerts firing on test.
- [ ] `LimitNOFILE`, sysctls, and `MemoryMax` in effect (`systemctl show carillon | grep -E 'NOFILE|Memory'`).

---

## Phase 8 — Post-launch (code fast-follows + long-lead parallel track)

**Code gaps this runbook works around — close them, priority order:**
1. **In-app delivery-log retention** (replace the interim cron; transactional).
2. **`/metrics`** (Prometheus): active/reconnecting watches, delivery
   success/latency/attempts, metering debits, pool exhaustion, decrypt &
   oauth-refresh errors.
3. **Poison-endpoint circuit-breaking**: auto-pause a watch (with a `notice`)
   after sustained delivery failure, so one dead webhook doesn't burn retries
   across every event.
4. **Global concurrent-watch ceiling** in the app (today it's proxy-enforced).
5. ~~**Config secret indirection**: support `*_file` for secrets.~~ **DONE** —
   `admin_token_file` / `stripe.*_file` / `resend.api_key_file` (+ `age_key_file`)
   read each secret from its own file; the NixOS `sops` binding uses them.
6. **SSRF for `/discover` + OAuth token exchange**: custom resolver inside
   `io-pim-discovery` / `io-oauth` (they still originate outbound to
   derived-but-not-fully-arbitrary hosts).

**Long lead, start day one, run in parallel:**
- **Google CASA** security assessment (paid, annual) — gates hosted Gmail.
  Microsoft publisher verification (free). Until CASA clears, Gmail = BYO client id.
- **Legal for SaaS**: privacy policy (lead with *content-free*), ToS, DPA,
  GDPR data-deletion on signout/close. These also gate app-store/Play.

---

## One-glance sequence

```
0 Prereqs (DNS, Stripe, Resend, object store, admin dist, age key offline)
1 Host baseline (user, sysctl, FD/conntrack, nftables)
2 Secrets (age key offline → systemd-creds encrypt config + key)
3 Build & install (carillon binary + admin dist)
4 Service + proxy (hardened systemd unit → Caddy auto-TLS)
5 Backups & retention (Litestream + offsite age key + prune timer)
6 Observability (uptime/disk/mem/TLS alerts, log shipping, Stripe reconcile)
7 GO-LIVE GATE (smoke test + security checklist)  ← do not expose before this
8 Fast-follows (retention-in-code, /metrics, circuit-breaker) + CASA/legal
```
