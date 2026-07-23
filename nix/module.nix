# Carillon watch server — NixOS service module (backend-agnostic).
#
# This is Layer 1: it knows nothing about how secrets reach the box. It renders
# the non-secret `settings` to the Nix store and runs a hardened systemd unit.
# The `configFile` option is the secret SEAM — point it at a runtime path
# produced by a secret provider (sops-nix via ./sops.nix, agenix, or a systemd
# credential) and the daemon reads that full config instead. Left null, the
# non-secret `settings` are used directly (dev / non-metered self-host, where
# the app generates its own age key in the state dir).
#
# It deliberately does NOT manage the reverse proxy or the host firewall: the
# app binds loopback and something else (e.g. Caddy) terminates TLS in front.
# See cairn/spec/production.md for the surrounding host setup.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkIf
    mkOption
    mkEnableOption
    mkPackageOption
    mkDefault
    types
    getExe'
    optionalAttrs
    ;
  cfg = config.services.carillon;
  tomlFormat = pkgs.formats.toml { };
  settingsFile = tomlFormat.generate "carillon.toml" cfg.settings;
  # The full config the daemon reads: a secret-bearing file from a provider if
  # one is wired, else the non-secret settings rendered to the store.
  configPath = if cfg.configFile != null then cfg.configFile else settingsFile;
in
{
  options.services.carillon = {
    enable = mkEnableOption "the Carillon watch server (holds IMAP IDLE, emits content-free webhooks)";

    package = mkPackageOption pkgs "carillon-backend" { };

    user = mkOption {
      type = types.str;
      default = "carillon";
      description = "System user the daemon runs as.";
    };

    group = mkOption {
      type = types.str;
      default = "carillon";
      description = "System group the daemon runs as.";
    };

    settings = mkOption {
      type = tomlFormat.type;
      default = { };
      example = {
        server.max_concurrent_handshakes = 25;
        api.listen = "127.0.0.1:3000";
        api.public_url = "https://carillon.example.org";
        api.ui_dir = "/var/lib/carillon/ui";
      };
      description = ''
        Non-secret `carillon.toml` content, rendered to the (world-readable) Nix
        store. Do NOT put secrets here — the admin token, Stripe keys, Resend
        key and the age identity travel through {option}`services.carillon.configFile`
        (see ./sops.nix). Everything in `carillon.sample.toml` that is not a
        secret belongs here.
      '';
    };

    configFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Secret seam. Runtime path to the FULL config file (non-secret settings
        AND secrets) that `CARILLON_CONFIG` points at. A secret provider
        populates it: sops-nix (./sops.nix wires this automatically), agenix, or
        a systemd credential. When null, {option}`settings` is used directly
        with no secrets (dev / non-metered self-host).
      '';
    };

    logLevel = mkOption {
      type = types.str;
      default = "info,carillon_server=info";
      description = "Value of `RUST_LOG` for the daemon.";
    };

    maxOpenFiles = mkOption {
      type = types.int;
      default = 262144;
      description = "`LimitNOFILE` — one FD per held IMAP connection, plus short-lived delivery sockets.";
    };

    memoryMax = mkOption {
      type = types.str;
      default = "3G";
      description = ''
        Hard `MemoryMax`. Standing IDLE sockets are memory-bound (~60 KB each);
        leave headroom for the OS, the reverse proxy and backups. On a 4 GB box,
        3G is the ceiling.
      '';
    };

    memoryHigh = mkOption {
      type = types.str;
      default = "2.5G";
      description = "Soft `MemoryHigh` throttle, kept below {option}`memoryMax`.";
    };

    tuneKernel = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Apply sysctls for holding many idle sockets (file descriptors, ephemeral
        port range, TCP keepalive below typical NAT cutoffs). conntrack sizing
        and the firewall stay a host concern — see cairn/spec/production.md.
      '';
    };

    blockPrivateEgress = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Kernel-level SSRF backstop (atop the app's own `guard.rs`): deny outbound
        to the cloud metadata IP and RFC1918, while allowing loopback (for the
        reverse proxy) and the public internet (webhooks target arbitrary public
        hosts, so egress cannot be allow-listed). Disable only for a LAN
        self-host that also sets `server.allow_private_targets = true`.
      '';
    };
  };

  config = mkIf cfg.enable {
    # Keep the DB under the service's own StateDirectory (0700, writable).
    services.carillon.settings.server.db = mkDefault "/var/lib/carillon/carillon.db";
    # Dev / no-secret default: let the app generate its age key in the state
    # dir. ./sops.nix overrides this to a read-only, pre-generated secret path.
    services.carillon.settings.server.age_key_file = mkDefault "/var/lib/carillon/age.key";

    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      description = "Carillon watch server";
    };
    users.groups.${cfg.group} = { };

    boot.kernel.sysctl = mkIf cfg.tuneKernel {
      "fs.file-max" = mkDefault 1000000;
      "fs.nr_open" = mkDefault 1048576;
      "net.core.somaxconn" = mkDefault 4096;
      "net.ipv4.ip_local_port_range" = mkDefault "10240 65535";
      # Keepalive below common NAT/provider idle cutoffs so dead peers are
      # detected and live flows survive between IMAP IDLE re-issues.
      "net.ipv4.tcp_keepalive_time" = mkDefault 300;
      "net.ipv4.tcp_keepalive_intvl" = mkDefault 30;
      "net.ipv4.tcp_keepalive_probes" = mkDefault 5;
    };

    systemd.services.carillon = {
      description = "Carillon watch server";
      documentation = [ "https://github.com/pimalaya/carillon-backend" ];
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      environment = {
        CARILLON_CONFIG = "${configPath}";
        RUST_LOG = cfg.logLevel;
      };

      serviceConfig = {
        Type = "simple";
        ExecStart = "${getExe' cfg.package "carillon-backend"} serve";
        User = cfg.user;
        Group = cfg.group;
        Restart = "on-failure";
        RestartSec = 5;

        # Data dir: creates and owns /var/lib/carillon.
        StateDirectory = "carillon";
        StateDirectoryMode = "0700";
        ReadWritePaths = [ "/var/lib/carillon" ];

        # Capacity: the box holds a lot of idle sockets.
        LimitNOFILE = cfg.maxOpenFiles;
        MemoryHigh = cfg.memoryHigh;
        MemoryMax = cfg.memoryMax;
        TasksMax = 4096;

        # Sandbox.
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" ];
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
        ];
        CapabilityBoundingSet = "";
      }
      // optionalAttrs cfg.blockPrivateEgress {
        IPAddressAllow = "localhost";
        IPAddressDeny = [
          "169.254.0.0/16"
          "10.0.0.0/8"
          "172.16.0.0/12"
          "192.168.0.0/16"
        ];
      };
    };
  };
}
