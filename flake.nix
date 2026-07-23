{
  description = "Carillon backend";

  inputs = {
    nixpkgs = {
      url = "github:nixos/nixpkgs/nixos-25.11";
    };
    fenix = {
      url = "github:nix-community/fenix/monthly";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    pimalaya = {
      url = "github:pimalaya/nix";
      flake = false;
    };
  };

  outputs =
    inputs:
    (import inputs.pimalaya).mkFlakeOutputs inputs {
      shell = ./shell.nix;
      default = ./default.nix;
    }
    // {
      nixosModules = {
        default = import ./nix/module.nix;
        carillon = import ./nix/module.nix;
        sops = import ./nix/sops.nix;
      };

      # Adds `pkgs.carillon-backend` (this flake's build) so the module's default
      # `package` resolves. Consumers add this to `nixpkgs.overlays`.
      overlays.default = final: _prev: {
        carillon-backend = inputs.self.packages.${final.stdenv.hostPlatform.system}.default;
      };

      # Local dev/test targets (see docs/NIXOS.md "Testing locally"). Both run
      # the module in DEV mode — no secrets, no disko, no proxy:
      #   container: sudo nixos-container create carillon --flake .#container
      #   vm:        nixos-rebuild build-vm --flake .#vm
      # To rehearse the WHOLE prod host (disko + sops + Caddy), use the
      # `watchbox` config with `nixos-anywhere --flake .#watchbox --vm-test`.
      nixosConfigurations.container = inputs.nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          inputs.self.nixosModules.carillon
          { nixpkgs.overlays = [ inputs.self.overlays.default ]; }
          ./nix/container.nix
        ];
      };

      nixosConfigurations.vm = inputs.nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          inputs.self.nixosModules.carillon
          { nixpkgs.overlays = [ inputs.self.overlays.default ]; }
          ./nix/vm.nix
        ];
      };
    };
}
