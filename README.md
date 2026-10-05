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

The client keeps registered GC roots in the checkout until activation and any
configured `--post-command` finish. Pass repeated `--post-arg` values to request
secret deployment through your secret manager after a successful switch; the
updater has no dependency on that manager. Instead of `--signing-key`, a
`--sign-command` with repeated `--sign-arg` values requests detached signatures
from an external signer, keeping the private key in that signer. The native
protocol exchanges version-1 JSON containing canonical Nix path metadata and
returns one named Ed25519 signature per path. This metadata is requester supplied;
the protocol does not transfer or verify NAR contents. Signatures are imported
through Nix's metadata-only cache operation. Alternatively, a structured
`--key-command` with repeated `--key-arg` values can supply the key
through a pipe. `keygen NAME` generates an operator key with the private half
on stdout and the public half on descriptor 3; neither half is written to disk.

`beforeHooks` and `afterHooks` are immutable notification executables, delivered
asynchronously from a durable queue under the unprivileged hook identity.
Delivery failures remain queued and never prevent a verified recovery update.
Each hook receives `UPDATE_PHASE`, `UPDATE_RESULT`, `UPDATE_SYSTEM`, and the
original `UPDATE_EVENT_UNIX_SECONDS`; its environment is otherwise cleared
except for `hookPath`. See the durable notification semantics below.

The integration VM covers the restricted SSH account, dual validation,
process identity checks, signature rejection, key replacement, closure copy,
hook ordering and privilege, and activation.

## Signed artifact integration

`services.nixUpdateRemote.artifact.enable` selects the signed EROFS backend
instead of signed Nix closures. The same Rust login program and independently
peer-checked privileged service own both modes. Artifact integrations supply
only the mutable generation root, trusted public-key file, and immutable
signature verifier. The account has no shell or sudo permission. Artifact
headers, payload lengths, content hashes, sidecars, staging and atomic selection
are handled in Rust. Kernel, initrd, configuration, rescue and optional network
payload signatures are verified before selecting a generation. An unhealthy
unconfirmed attempt may be superseded, preserving the last tested fallback;
only boot health checking can mark a generation tested.

The complete operator transaction is:

```console
nix-update-remote deploy-generation \
  --installable .#nixosConfigurations.host --target update@node.example.test \
  --signing-key /run/keys/generation.key --sha512sum /path/to/sha512sum --reboot
```

The integration supplies the image/config/rescue/signer/system attribute mapping
with `--image-attribute`, `--config-attribute`, `--rescue-attribute`,
`--signer-attribute` and `--system-attribute`. The generic workflow defaults to
`system.build.updateArtifacts.*` and has no NMBL attribute dependency. Signer
executable location is supplied with `--signer-relative-path`; optional network
artifacts use `--network-attribute` and `--network-enabled-attribute`.
It builds those public outputs, registers GC
roots in a printed `system-update-roots-*` directory in the current checkout,
signs and uploads them, and removes roots on success or failure. A process crash
may leave that visible directory for explicit cleanup. `deploy-artifact` is the
same signing/upload operation for existing image, config, kernel, initrd and
rescue files. `--key-command PROGRAM` with repeated `--key-arg ARG` supplies a
structured runtime key provider through an OS pipe; no shell evaluates it and
no decrypted private key is written to disk. Repeated `--ssh-arg` options with
`--ssh-command PROGRAM` integrate an operator authentication provider. These
providers are operator-controlled; they do not cross the target's privilege
boundary.

## Durable notifications

Events are written and synced to the root-owned `reportQueue`
(default `/persistent/system-update-reports`): before events precede activation,
and outcome events follow activation and precede any requested reboot.
`beforeHooks` and `afterHooks` now deliver these events asynchronously through
`system-update-report-delivery.service` and its retry timer. Notification keys,
DNS or SMTP may be unavailable during bootstrap or recovery: verified updates
still proceed, with failed notifications remaining queued. Queue failures and
pending delivery are visible in the journal. Delivery retains the original
`UPDATE_EVENT_UNIX_SECONDS`, clears supplementary groups, drops to the
configured non-root hook UID/GID and executes only immutable hook programs.
A delivery outage is expected pending work and does not make the host unhealthy.

`UPDATE_PHASE=before`, `UPDATE_RESULT=pending` records the verified candidate
before mutation. `UPDATE_PHASE=after` records `success` or `failure` of
activation. For EROFS, success means the generation was selected for the next
boot; it is not proof of a healthy boot. Failed verification records an after
failure with candidate `unverified-artifact`, and never changes the selection.
Delivery is at least once: a crash after mail acceptance and before deleting an
event may cause a duplicate. Pending events remain on disk if hooks are removed.

The server repository's `system-update-reporting` VM check drives the canonical
Rust build/sign/SSH operator path and an actual SSH-to-SMTP report receiver. It
covers missing reporting keys during repair, delayed before/outcome delivery,
verification failure, and account restrictions. This repository's signed-Nix
closure VM check covers the same broker and asynchronous hook delivery in
closure mode.

### Bootstrap coherence and provisioning

With `artifact.bootstrap.enable`, each signed image must contain fixed regular
files `/nmbl-bootstrap/kernel` and `/nmbl-bootstrap/initrd`. After verifying the
image, the Rust adapter mounts it read-only with nodev/nosuid/noexec in a private
mount namespace and copies those files into the generation. Symlinked metadata
or missing bootstrap files are rejected. Bootloader integration selects these
files through the same atomic generation selector as the runtime configuration,
so rollback selects the matching bootstrap pair too. The caller supplies the
immutable verifier; utility programs only perform native hashing and mounts.

Initial rescue provisioning uses the same verification and activation code:

```console
nix-update-remote install-erofs ROOT PUBLIC_KEY SIGNER SHA512SUM \
  UNSHARE MOUNT UMOUNT --report-queue QUEUE < signed-bundle
```

The optional queue path must match the installed service (including the installation mount prefix).
This root-only role never requests reboot. Installed hosts use the restricted
update account and broker. `deploy-generation` accepts `--remote-command PROGRAM`
and repeated `--remote-arg ARG` for the initial rescue command; arguments are
quoted individually for SSH. No caller-selected shell code is used by the
installed restricted service.

Closure updates accept `--activation-command PROGRAM` and repeated
`--activation-arg ARG`. This callback runs once the restricted `current-system`
query reports the new configuration, while service startup may still be waiting
for credentials. The client waits for both the callback and the activation
result, retaining its checkout GC roots throughout. This lets a secrets provider
request operator approval without blocking behind services that need its values.

An integration may supply `--post-command PROGRAM` with repeated `--post-arg ARG`
for operator work after an update. With `--reboot`, the generation workflow waits
until the restricted SSH `current-system` query matches the built toplevel, then
executes that configured command. For example, the server integration requests
its secrets deployment through nix-secrets at this point. The independent
updater has no dependency on that provider. Without reboot, this post-operation
is deferred so new-schema secrets cannot be deployed into the old system.

### Configured operator client

`configured-deploy --installable FLAKE#CONFIG --plan FILE` evaluates a public
Nix metadata function against that configuration and runs the existing update
backend. The function supplies argument arrays for an external signing session,
SSH authentication, key provider, and postdeployment operation. The updater
remains independent of those providers.

`--installable`, `--target-host update@HOST`, and `--ssh-port PORT` can select a
runtime deployment configuration without rebuilding the application. The SSH
public key comes from that configuration; target overrides retain its identity
and strict host verification. `--no-reboot` suppresses a configured reboot.
Only the public SSH key is written temporarily beneath the checkout, and it is
removed on exit. Backend GC roots remain alive through the postdeployment step.

### Interrupted operator commands

SIGINT and SIGTERM cancel deployment, terminate and reap owned child process groups, and remove the command’s temporary signed artifacts, public SSH key files, and repository GC roots. Signing and upload pipes are closed before cleanup.

SIGKILL and machine failure cannot run cleanup. Their leftovers remain visible in the checkout (`system-update-*`); remove an abandoned transaction only after confirming its operator processes have stopped. Active transactions must retain their roots until completion.

The native client uses one operation-owned SSH connection for copying the
closure and signatures and applying it. Activation progress travels on the
apply stream; it opens no status connections. The private control socket and
connection are removed on completion or cancellation. Losing that connection
fails the operation instead of opening a new authentication request. Pass
connection options with repeated `--ssh-arg` arguments; these configure the
single connection used by every phase. Older receivers that return only a
final receipt remain supported, with the activation callback running after
successful completion. Such a receiver may require secrets to be deployed
before its first upgrade if service startup is waiting for them.
