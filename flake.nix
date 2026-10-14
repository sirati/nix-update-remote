{
  description = "Restricted, signed remote NixOS updates";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      nixosModules.default = import ./nix/module.nix;
      nixosModules.remote-update = self.nixosModules.default;

      packages = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = import ./package.nix { inherit pkgs; };
          remote-update = self.packages.${system}.default;
        });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/nix-update-remote";
        };
        remote-update = self.apps.${system}.default;
      });

      checks.x86_64-linux = {
        package = self.packages.x86_64-linux.default;
        integration = nixpkgs.legacyPackages.x86_64-linux.testers.runNixOSTest (
          import ./tests/nixos.nix { pkgs = nixpkgs.legacyPackages.x86_64-linux; }
        );
        rollback = nixpkgs.legacyPackages.x86_64-linux.testers.runNixOSTest (
          import ./tests/rollback.nix { pkgs = nixpkgs.legacyPackages.x86_64-linux; }
        );
        # A sandbox that makes /boot read-only for the broker fails evaluation.
        boot-writable-guard =
          let
            lib = nixpkgs.lib;
            fires = sandbox: builtins.any (check: !check.assertion && lib.hasInfix "keep /boot writable" check.message)
              (lib.nixosSystem {
                system = "x86_64-linux";
                modules = [ self.nixosModules.default {
                  services.nixUpdateRemote = { enable = true; trustedPublicKeys = [ "test:AAAA" ]; };
                  boot.loader.grub.enable = false;
                  fileSystems."/" = { device = "none"; fsType = "tmpfs"; };
                  system.stateVersion = "26.05";
                  systemd.services.nix-update-remote.serviceConfig = sandbox;
                } ];
              }).config.assertions;
          in
            assert fires { ProtectSystem = "full"; };
            assert fires { ProtectSystem = "strict"; };
            assert fires { PrivateMounts = true; };
            assert fires { ReadOnlyPaths = [ "/boot" ]; };
            assert !(fires { });
            nixpkgs.legacyPackages.x86_64-linux.runCommand "boot-writable-guard" { } "touch $out";
      };
    };
}
