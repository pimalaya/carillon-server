{
  description = "Carillon watch server prototype: holds IMAP IDLE and emits content-free webhooks, written in Rust";

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

      # Adds `pkgs.carillon-server` (this flake's build) so the module's default
      # `package` resolves. Consumers add this to `nixpkgs.overlays`.
      overlays.default = final: _prev: {
        carillon-server = inputs.self.packages.${final.stdenv.hostPlatform.system}.default;
      };

      # Throwaway host for local testing WITHOUT rebuilding your OS (see
      # docs/NIXOS.md "Testing locally"):
      #   sudo nixos-container create carillon --flake .#container
      # or a full VM:
      #   nix build .#nixosConfigurations.container.config.system.build.vm
      nixosConfigurations.container = inputs.nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          inputs.self.nixosModules.carillon
          { nixpkgs.overlays = [ inputs.self.overlays.default ]; }
          ./nix/container.nix
        ];
      };
    };
}
