{ pkgs }:

pkgs.rustPlatform.buildRustPackage {
  pname = "nix-update-remote";
  version = "0.1.0";
  src = ./.;
  cargoLock.lockFile = ./Cargo.lock;
  meta = {
    mainProgram = "nix-update-remote";
    license = pkgs.lib.licenses.mit;
    platforms = pkgs.lib.platforms.linux;
  };
}
