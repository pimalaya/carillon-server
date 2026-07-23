# Throwaway NixOS config for a systemd-nspawn container that runs the Carillon
# module in dev / no-secret mode. Fast local testing on a NixOS host, WITHOUT
# touching your own OS config:
#
#   sudo nixos-container create carillon --flake .#container
#   sudo nixos-container start  carillon
#   sudo nixos-container run    carillon -- systemctl status carillon
#   sudo nixos-container run    carillon -- curl -sf http://127.0.0.1:3000/health
#   sudo nixos-container update carillon --flake .#container   # after edits
#   sudo nixos-container destroy carillon                      # host untouched
#
# See cairn/spec/nixos.md "Testing locally".
{
  boot.isContainer = true;

  services.carillon = {
    enable = true;
    # Dev mode: no sops, no secrets. The app generates its own age key in the
    # state dir; billing/email fall back to their keyless stubs.
    tuneKernel = false; # host sysctls are not settable from inside a container
    blockPrivateEgress = false; # don't block the container's own 10.x network
    settings = {
      api.listen = "127.0.0.1:3000";
      server.allow_private_targets = true;
    };
  };

  system.stateVersion = "25.11";
}
