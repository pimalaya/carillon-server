# Carillon — sops-nix secret binding (Layer 2 over ./module.nix).
#
# Each secret is delivered as its OWN file: sops materializes it into a private
# tmpfs at activation, and we point the daemon's `*_file` config options at
# those runtime paths (the app reads + trims them at load — see src/config.rs
# `resolve_secrets`). No template, no whole-config rendering, no IFD: the
# non-secret `services.carillon.settings` stays fully declarative in the Nix
# store, and only the file PATHS (never the secrets) live there.
#
# The consumer OWNS the sops file and declares each `sops.secrets.<name>`; this
# module references them by the names given in `services.carillon.sops.secrets`
# and marks them readable by the service user. To change backend (e.g. agenix),
# replace this file — ./module.nix does not change.
{
  config,
  lib,
  ...
}:
let
  inherit (lib)
    mkIf
    mkOption
    mkEnableOption
    mkMerge
    optionalAttrs
    types
    ;
  cfg = config.services.carillon.sops;
  s = cfg.secrets;
  user = config.services.carillon.user;
  secretPath = name: config.sops.secrets.${name}.path;
in
{
  options.services.carillon.sops = {
    enable = mkEnableOption "sops-nix secret provisioning for Carillon";

    secrets = mkOption {
      type = types.attrsOf types.str;
      default = { };
      example = {
        ageKey = "carillon-age-key";
        adminToken = "carillon-frontend-token";
        stripeSecretKey = "carillon-stripe-secret-key";
        stripeWebhookSecret = "carillon-stripe-webhook-secret";
        resendApiKey = "carillon-resend-api-key";
      };
      description = ''
        Map of a Carillon secret SLOT to the name of a `sops.secrets.<name>` you
        declare yourself. Recognised slots:

        - `ageKey` (**required**) — the app's age identity that decrypts stored
          IMAP/OAuth credentials. Generate it OFFLINE, back it up out-of-band;
          losing it bricks every watch, leaking it plus a DB dump is full
          credential compromise. Wired into `server.age_key_file`.
        - `adminToken` — `api.admin_token_file` (the fleet god token).
        - `stripeSecretKey` — `billing.stripe.secret_key_file`.
        - `stripeWebhookSecret` — `billing.stripe.webhook_secret_file`.
        - `resendApiKey` — `email.resend.api_key_file`.

        Only `ageKey` is required; omit any slot you do not use (e.g. a
        non-metered box needs no Stripe slots).
      '';
    };
  };

  config = mkIf (config.services.carillon.enable && cfg.enable) {
    assertions = [
      {
        assertion = s ? ageKey;
        message = "services.carillon.sops.secrets.ageKey must name the sops secret holding the age identity.";
      }
    ];

    # Every referenced secret must be readable by the service user.
    sops.secrets = lib.mapAttrs' (_slot: name: lib.nameValuePair name { owner = user; }) s;

    # Point each config option at its secret's runtime path. Only paths (never
    # secret values) land in the store-rendered settings.
    services.carillon.settings = mkMerge [
      { server.age_key_file = secretPath s.ageKey; }
      (optionalAttrs (s ? adminToken) { api.admin_token_file = secretPath s.adminToken; })
      (optionalAttrs (s ? stripeSecretKey) {
        billing.stripe.secret_key_file = secretPath s.stripeSecretKey;
      })
      (optionalAttrs (s ? stripeWebhookSecret) {
        billing.stripe.webhook_secret_file = secretPath s.stripeWebhookSecret;
      })
      (optionalAttrs (s ? resendApiKey) { email.resend.api_key_file = secretPath s.resendApiKey; })
    ];
  };
}
