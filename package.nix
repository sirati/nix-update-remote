{ pkgs }:

pkgs.rustPlatform.buildRustPackage {
  pname = "nix-update-remote";
  version = "0.1.0";
  src = ./.;
  cargoLock.lockFile = ./Cargo.lock;
  NIX_UPDATE_ARTIFACT_TEST_SOURCE = pkgs.writeText "immutable-artifact-test-input" "public test artifact\n";
  meta = {
    mainProgram = "nix-update-remote";
    license = pkgs.lib.licenses.mit;
    platforms = pkgs.lib.platforms.linux;
  };
}
