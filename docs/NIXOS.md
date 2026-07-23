# Running Carillon on NixOS

Carillon ships a NixOS service module so the whole host side of
[`PRODUCTION.md`](PRODUCTION.md) — the dedicated user, the hardened systemd
unit, the FD/memory limits, the sysctls, the SSRF egress backstop — is
declarative and reproducible instead of copy-paste. Secrets are kept out of the
world-readable Nix store.

## Two layers + an overlay

The flake exposes three things (`flake.nix`):

| Output | Role |
|---|---|
| `nixosModules.carillon` (`= default`) | **Layer 1** — the hardened service. Backend-agnostic: knows *nothing* about how secrets arrive. Usable on its own. |
| `nixosModules.sops` | **Layer 2** — the sops-nix secret binding. Points each of the daemon's `*_file` secret options at a per-secret sops runtime path. |
| `overlays.default` | Adds `pkgs.carillon-backend` (this flake's build) so the module's default `package` resolves. |

The seam works two ways. The daemon reads each secret from a file via a `*_file`
config option (`api.admin_token_file`, `billing.stripe.secret_key_file`,
`billing.stripe.webhook_secret_file`, `email.resend.api_key_file`, and
`server.age_key_file`); Layer 2 just sets those paths in `settings` to per-secret
runtime paths a provider (sops-nix, agenix, systemd `LoadCredential`) creates —
so only paths, never secrets, land in the store. For providers that hand you one
already-complete config file instead, **`services.carillon.configFile`** points
`CARILLON_CONFIG` straight at it. Left unset with no `*_file` paths, the
non-secret `settings` are used directly with no secrets — fine for dev or a
non-metered self-host.

## Quick start (flake consumer)

```nix
{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.11";
    carillon.url = "github:pimalaya/carillon-backend";
    sops-nix.url = "github:Mic92/sops-nix";
  };

  outputs = { nixpkgs, carillon, sops-nix, ... }: {
    nixosConfigurations.watchbox = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        sops-nix.nixosModules.sops
        carillon.nixosModules.carillon      # Layer 1: the service
        carillon.nixosModules.sops          # Layer 2: sops binding
        { nixpkgs.overlays = [ carillon.overlays.default ]; }
        ./watchbox.nix
      ];
    };
  };
}
```

`./watchbox.nix` — the non-secret config plus the secret wiring:

```nix
{ config, ... }:
{
  services.carillon = {
    enable = true;

    # Non-secret carillon.toml — rendered to the store. Never put secrets here.
    settings = {
      server.max_concurrent_handshakes = 25;   # 2 vCore: keep reconnect storms tame
      server.max_watches_per_account = 25;
      api.listen = "127.0.0.1:3000";            # loopback; a proxy fronts it
      api.ui_dir = "/var/lib/carillon/ui";      # same-origin carillon-frontend dist
      api.public_url = "https://carillon.example.org";
      billing.stripe.prices.pack = "price_...";  # the price id is not a secret
      email.resend.from = "Carillon <no-reply@mail.carillon.example.org>";
      oauth.microsoft.client_id = "...";
    };

    # Secret binding: map each slot to a sops secret you declare below.
    sops = {
      enable = true;
      secrets = {
        ageKey = "carillon-age-key";                       # required
        adminToken = "carillon-frontend-token";
        stripeSecretKey = "carillon-stripe-secret-key";
        stripeWebhookSecret = "carillon-stripe-webhook-secret";
        resendApiKey = "carillon-resend-api-key";
      };
    };

    # Optional overrides (defaults shown):
    # memoryMax = "3G"; maxOpenFiles = 262144; tuneKernel = true; blockPrivateEgress = true;
  };

  # You OWN the sops file and declare each secret referenced above.
  sops.defaultSopsFile = ./secrets.yaml;
  sops.age.keyFile = "/var/lib/sops-nix/key.txt";  # the sops MASTER key (see below)
  sops.secrets.carillon-age-key = { };
  sops.secrets.carillon-frontend-token = { };
  sops.secrets.carillon-stripe-secret-key = { };
  sops.secrets.carillon-stripe-webhook-secret = { };
  sops.secrets.carillon-resend-api-key = { };
}
```

That's it. `nixos-rebuild switch` builds the hardened unit, drops the secrets
into tmpfs, renders the full config there, and starts the daemon.

## The two age keys — don't conflate them

There are **two** age keys in play, and they are different:

1. **The sops master key** (`sops.age.keyFile`, e.g. `/var/lib/sops-nix/key.txt`,
   or derived from the host's SSH key via `ssh-to-age`). It decrypts
   `secrets.yaml` at activation. This is sops's own key.
2. **Carillon's age identity** (the `ageKey` slot). It decrypts the IMAP/OAuth
   credentials *inside Carillon's sqlite DB*. It is **stored as one of the
   secrets** in `secrets.yaml`, so sops delivers it to `/run/secrets/…` at
   runtime and the daemon reads it there.

So sops (via age) delivers the age key that Carillon (via age) uses — same
primitive, one layer up. Generate Carillon's identity **offline** and paste it
into `secrets.yaml` under the `carillon-age-key` key:

```sh
age-keygen                       # prints AGE-SECRET-KEY-... — this is the value
sops secrets.yaml                # paste it as: carillon-age-key: AGE-SECRET-KEY-...
```

**Back that identity up out-of-band.** Losing it bricks every watch; leaking it
plus a DB dump is full credential compromise (see
[`DEPLOY_HARDENING.md`](DEPLOY_HARDENING.md) §2). It lives encrypted in
`secrets.yaml`, but keep an independent offline copy — never in the DB backup
bucket.

## What the module does and does not do

**Does** (Layer 1): system user/group; a hardened `systemd` unit
(`ProtectSystem=strict`, `MemoryDenyWriteExecute`, empty
`CapabilityBoundingSet`, `SystemCallFilter=@system-service`, …);
`LimitNOFILE`/`MemoryMax`/`MemoryHigh`; `StateDirectory` for the DB; the sysctls
for holding many idle sockets; and (when `blockPrivateEgress`) a kernel-level
`IPAddressDeny` for the metadata IP + RFC1918 on top of the app's own SSRF
guard.

**Does not** — these stay host concerns, per [`PRODUCTION.md`](PRODUCTION.md):
- **Reverse proxy / TLS.** The app binds loopback; put Caddy (or nginx) in
  front. Manage it with the upstream `services.caddy` module.
- **Host firewall + conntrack sizing.** Use `networking.firewall` /
  `networking.nftables`; raise `nf_conntrack_max` there.
- **Backups.** Litestream + the offline age-key copy.
- **The `carillon-frontend` build** at `ui_dir` (build it in CI; rsync the `dist/`).

## Testing locally (no OS rebuild)

You never need `nixos-rebuild switch` to try the module. Fastest to most
realistic:

- **Pure eval — builds nothing, catches module errors:**
  ```sh
  nix eval --impure --expr 'let e = import <nixpkgs/nixos/lib/eval-config.nix> {
    system = "x86_64-linux";
    modules = [ ./nix/module.nix ./nix/container.nix
                { services.carillon.package = (import <nixpkgs>{}).hello; } ];
  }; in e.config.systemd.services.carillon.serviceConfig.ExecStart'
  ```
- **`nixos-container` — a real systemd service in seconds, host untouched** (needs
  a NixOS host + `sudo`; the flake ships `nixosConfigurations.container` in dev
  mode):
  ```sh
  sudo nixos-container create carillon --flake .#container
  sudo nixos-container start   carillon
  sudo nixos-container run     carillon -- systemctl status carillon
  sudo nixos-container run     carillon -- curl -sf http://127.0.0.1:3000/health
  sudo nixos-container update  carillon --flake .#container   # after edits
  sudo nixos-container destroy carillon
  ```
  Caveats: a container can't set host sysctls (so `tuneKernel` is a no-op there —
  the dev config disables it) and its own network is RFC1918 (so `blockPrivateEgress`
  is disabled too and you `curl` from *inside*). The sandbox directives still apply.
- **Full VM — validates sysctls/firewall under a real kernel:**
  ```sh
  nix build .#nixosConfigurations.container.config.system.build.vm && ./result/bin/run-*-vm
  ```
- **`nixosTest`** for a headless, reproducible/CI check.

## Other secret backends (the seam)

Layer 2 is swappable. To use **agenix** or a **systemd credential** instead of
sops, drop `carillon.nixosModules.sops` and point the daemon's `*_file` options
at whatever runtime paths your provider creates:

```nix
# agenix example — one file per secret, same as the sops binding does
age.secrets.carillon-age-key.file = ./secrets/age-key.age;
age.secrets.carillon-frontend-token.file = ./secrets/admin-token.age;
services.carillon.settings = {
  server.age_key_file = config.age.secrets.carillon-age-key.path;
  api.admin_token_file = config.age.secrets.carillon-frontend-token.path;
};
```

Or, for a provider that hands you one complete config file, set
`services.carillon.configFile` to its path instead. Either way Layer 1 is
unchanged.

## Docker / OCI

The module is NixOS-only (systemd + sops-nix). For a container, take the
**binary** from this flake and hand it a config via `CARILLON_CONFIG`:

```nix
pkgs.dockerTools.buildLayeredImage {
  name = "carillon-backend";
  config.Entrypoint = [ "${carillon.packages.x86_64-linux.default}/bin/carillon-backend" "serve" ];
  config.Env = [ "CARILLON_CONFIG=/config/carillon.toml" ];
}
```

Mount the config + age key as secrets (Docker/K8s secrets, not image layers).
Note the trade-offs from [`PRODUCTION.md`](PRODUCTION.md): a container drops the
systemd sandbox this module provides and adds a NAT layer that pressures the
very conntrack table we tune — fine for dev/CI/demo, weaker than
NixOS-on-the-host as the production substrate for a socket-heavy daemon.

## Relationship to PRODUCTION.md

This module implements the declarative parts of **Phase 1** (host baseline: user,
sysctls, limits) and **Phase 4** (the hardened service + credentials seam). The
runbook's other phases — DNS/TLS/proxy, firewall/conntrack, Litestream backups,
the retention timer, observability, the go-live gate — remain as written; the
module just makes the service itself reproducible.
