---
cairn: spec
capability: nixos
status: current
---

# NixOS

Carillon ships a NixOS service module so the host side of the [[production]] runbook — the dedicated user, the hardened systemd unit, the FD/memory limits, the sysctls, the SSRF egress backstop — is declarative and reproducible instead of copy-paste, with secrets kept out of the world-readable Nix store. The flake exposes two module layers plus an overlay: a backend-agnostic hardened service, a swappable secret-binding layer, and an overlay that provides the package. A flake consumer composes them, wires each secret slot, and runs `nixos-rebuild switch`. The module implements the declarative parts of the runbook; everything else (proxy/TLS, firewall, backups) stays a host concern.

### Requirement: Two module layers plus an overlay
The flake SHALL expose three outputs: `nixosModules.carillon` (= `default`) as **Layer 1**, the hardened, backend-agnostic service that knows nothing about how secrets arrive and is usable on its own; `nixosModules.sops` as **Layer 2**, the sops-nix secret binding that points each of the daemon's `*_file` options at a per-secret runtime path; and `overlays.default`, which adds `pkgs.carillon-backend` so the module's default `package` resolves.

### Requirement: File-based secret seam
The daemon SHALL read each secret from a file named by a `*_file` config option — `api.admin_token_file`, `billing.stripe.secret_key_file`, `billing.stripe.webhook_secret_file`, `email.resend.api_key_file`, and `server.age_key_file`. Layer 2 SHALL set those options in `settings` to per-secret runtime paths that a provider creates, so only paths, never secret values, land in the Nix store. For a provider that hands over one already-complete config file, `services.carillon.configFile` SHALL point `CARILLON_CONFIG` straight at it. With `configFile` unset and no `*_file` paths given, the non-secret `settings` SHALL be used directly with no secrets — acceptable for dev or a non-metered self-host.

### Requirement: Flake-consumer quick start
A flake consumer SHALL enable the daemon by composing, in their `nixosSystem` modules, the upstream `sops-nix` module, Layer 1 (`carillon.nixosModules.carillon`), Layer 2 (`carillon.nixosModules.sops`), and the overlay (`carillon.overlays.default`), then setting `services.carillon.enable = true`. Non-secret `carillon.toml` values SHALL be placed under `services.carillon.settings` (rendered to the store — never secrets). Each secret slot under `services.carillon.sops.secrets` (`ageKey` required, plus `adminToken`, `stripeSecretKey`, `stripeWebhookSecret`, `resendApiKey`) SHALL map to a sops secret the consumer declares and owns. `nixos-rebuild switch` SHALL then build the hardened unit, drop the secrets into tmpfs, render the full config there, and start the daemon.

### Requirement: Two distinct age keys are never conflated
The deployment SHALL treat two separate age keys as distinct. The **sops master key** (`sops.age.keyFile`, e.g. `/var/lib/sops-nix/key.txt` or derived from the host SSH key via `ssh-to-age`) is sops's own key and decrypts `secrets.yaml` at activation. **Carillon's age identity** (the `ageKey` slot) decrypts the IMAP/OAuth credentials stored inside Carillon's sqlite DB; it SHALL itself be stored as one of the secrets in `secrets.yaml`, so sops delivers it to a runtime path the daemon reads. The two keys are the same primitive one layer apart — sops (via age) delivers the age key Carillon (via age) uses — and SHALL NOT be merged.

#### Scenario: Generating Carillon's age identity
- **GIVEN** a fresh deployment needing Carillon's age identity
- **WHEN** the operator runs `age-keygen` offline and pastes the printed `AGE-SECRET-KEY-...` into `secrets.yaml` under the `carillon-age-key` key
- **THEN** sops encrypts it at rest and delivers it at runtime, and the operator SHALL back that identity up out-of-band (an independent offline copy, never in the DB backup bucket): losing it bricks every watch, and leaking it together with a DB dump is full credential compromise.

### Requirement: Layer 1 host guarantees
Layer 1 SHALL declaratively provide the system user/group; a hardened systemd unit (`ProtectSystem=strict`, `MemoryDenyWriteExecute`, empty `CapabilityBoundingSet`, `SystemCallFilter=@system-service`, and similar); `LimitNOFILE`, `MemoryMax`, and `MemoryHigh`; a `StateDirectory` for the DB; the sysctls for holding many idle sockets; and, when `blockPrivateEgress` is set, a kernel-level `IPAddressDeny` for the metadata IP plus RFC1918 on top of the app's own SSRF guard. Key overridable options SHALL include `memoryMax`, `maxOpenFiles`, `tuneKernel`, and `blockPrivateEgress`.

### Requirement: Out-of-scope host concerns
The module SHALL NOT manage reverse proxy / TLS (the app binds loopback; a Caddy or nginx front end via the upstream `services.caddy` module), the host firewall and conntrack sizing (`networking.firewall` / `networking.nftables`, raising `nf_conntrack_max`), backups (Litestream plus the offline age-key copy), or the [[serving]] carillon-frontend build placed at `ui_dir` (built in CI and rsynced). These remain host concerns per the [[production]] runbook.

### Requirement: Local testing without an OS rebuild
The module SHALL be exercisable without `nixos-rebuild switch`, along a spectrum from fastest to most realistic: a pure `nix eval` that builds nothing and catches module errors; `nixos-container` (needs a NixOS host and `sudo`) that runs a real systemd service in seconds against the shipped dev-mode `nixosConfigurations.container`, leaving the host untouched; a full VM (`system.build.vm`) that validates sysctls/firewall under a real kernel; and a `nixosTest` for a headless, reproducible CI check. In the container path `tuneKernel` and `blockPrivateEgress` SHALL be disabled (a container cannot set host sysctls and its own network is RFC1918, so health checks run from inside), while the systemd sandbox directives still apply.

### Requirement: Swappable secret backend, one file per secret
Layer 2 SHALL be swappable. To use agenix or a systemd credential instead of sops, the consumer SHALL drop `carillon.nixosModules.sops` and point the daemon's `*_file` options at the runtime paths their provider creates — one file per secret, mirroring the sops binding (e.g. `server.age_key_file = config.age.secrets.carillon-age-key.path`). Alternatively `services.carillon.configFile` SHALL accept one complete config file from a provider. In every case Layer 1 SHALL be unchanged.

### Requirement: Relationship to the production runbook
The module SHALL implement the declarative parts of the [[production]] runbook — Phase 1 (host baseline: user, sysctls, limits) and Phase 4 (the hardened service plus the credentials seam). The runbook's remaining phases — DNS/TLS/proxy, firewall/conntrack, Litestream backups, the retention timer, observability, and the go-live gate — SHALL remain as written; the module only makes the service itself reproducible.
