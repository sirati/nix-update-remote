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
      };
    };
}
