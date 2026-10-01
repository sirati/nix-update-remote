{ pkgs }:

pkgs.rustPlatform.buildRustPackage {
  pname = "nix-update-remote";
  version = "0.1.0";
  src = ./.;
  cargoLock.lockFile = ./Cargo.lock;
  NIX_UPDATE_ARTIFACT_TEST_SOURCE = pkgs.writeText "immutable-artifact-test-input" "public test artifact\n";
  NIX_UPDATE_CANCELLATION_TOPLEVEL = pkgs.runCommand "cancellation-test-toplevel" {} ''
    mkdir -p "$out"
    printf 'public kernel fixture\n' > "$out/kernel"
    cp "$out/kernel" "$out/initrd"
  '';
  meta = {
    mainProgram = "nix-update-remote";
    license = pkgs.lib.licenses.mit;
    platforms = pkgs.lib.platforms.linux;
  };
}
