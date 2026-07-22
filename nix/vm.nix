# Throwaway BOOTABLE VM for local module testing on a NixOS host:
#   nixos-rebuild build-vm --flake .#vm
#   ./result/bin/run-carillon-vm-vm          # auto-logs in as root
#   (inside) systemctl status carillon
#   (inside) curl -sf http://127.0.0.1:3000/health && echo
#   (inside) poweroff
#
# Scope: this tests the MODULE in dev mode — no sops, no secrets, no disko, no
# Caddy. Unlike the nspawn container, a real VM actually applies the sysctls
# (`tuneKernel`), so it's a slightly truer test. To rehearse the WHOLE prod host
# (disko + sops + Caddy), use the `watchbox` config with
# `nixos-anywhere --flake .#watchbox --vm-test` (in carillon-deploy).
{ ... }:
{
  services.carillon = {
    enable = true;
    settings.api.listen = "127.0.0.1:3000";
    settings.server.allow_private_targets = true;
  };

  networking.hostName = "carillon-vm";

  # Frictionless console access in the throwaway VM.
  users.users.root.password = "root";
  services.getty.autologinUser = "root";

  system.stateVersion = "25.11";
}
