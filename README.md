# NixOS remote update

This flake provides a restricted Rust update client, SSH login program, and
privileged service for remotely deploying signed NixOS closures without root
SSH or sudo.

The `update` account has the binary as its login program. Both the
unprivileged side and the root service validate the requested closure, its
recursive signatures, allowed keys, and protocol fields. The privileged
service also checks the connecting process UID and executable identity before
staging or switching a generation.

```nix
{
  inputs.nix-update-remote.url = "github:sirati/nix-update-remote";

  outputs = { nixpkgs, nix-update-remote, ... }: {
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      modules = [ nix-update-remote.nixosModules.default ];
    };
  };
}
```

Configure `services.nixUpdateRemote`, place the dedicated SSH public key
in its runtime `authorizedKeysFile`, and install at least one closure-signing
public key. Signing private keys stay on the operator machine and outside the
Nix store.

```console
nix run github:sirati/nix-update-remote -- deploy \
  --target update@node.example.test \
  --installable .#nixosConfigurations.node.config.system.build.toplevel \
  --signing-key /run/keys/deployment.sec \
  --impure
```

`beforeHooks` and `afterHooks` are lists of immutable Nix store executables.
Hooks run without a shell under the configured unprivileged `hookUid` and
`hookGid`. A failed before hook prevents the profile change. After hooks run
after either a successful or failed activation; their failures are logged but
cannot reverse an activation. Each hook receives `UPDATE_PHASE` (`before` or
`after`), `UPDATE_RESULT` (`pending`, `success`, or `failure`), and
`UPDATE_SYSTEM` (the verified store path). The hook environment is otherwise
cleared except for the configured `hookPath`.

The integration VM covers the restricted SSH account, dual validation,
process identity checks, signature rejection, key replacement, closure copy,
hook ordering and privilege, and activation.
