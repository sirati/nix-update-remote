# NixOS remote update

This flake provides a restricted Rust update client, an SSH login program and
a privileged service. Together they deploy signed NixOS closures to remote
hosts without root SSH or sudo.

The binary is the login program of the `update` account. The unprivileged
side and the root service both validate the requested closure, its recursive
signatures, the allowed keys and the protocol fields. Before it stages or
switches a generation, the privileged service also checks the UID and
executable identity of the connecting process.

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

Configure `services.nixUpdateRemote`, put the dedicated SSH public key in its
runtime `authorizedKeysFile`, and install at least one public key for closure
signing. Private signing keys stay on the operator machine and outside the
Nix store.

```console
nix run github:sirati/nix-update-remote -- deploy \
  --target update@node.example.test \
  --installable .#nixosConfigurations.node.config.system.build.toplevel \
  --signing-key /run/keys/deployment.sec \
  --impure
```

The client keeps registered GC roots in the checkout until activation and any
configured `--post-command` have finished. To have your secret manager deploy
secrets after a successful switch, pass repeated `--post-arg` values. The
updater does not depend on that manager.

In place of `--signing-key`, `--sign-command` with repeated `--sign-arg`
values asks an external signer for detached signatures. The private key then
stays in that signer. The native protocol exchanges version-1 JSON that
contains canonical Nix path metadata, and the signer returns one named Ed25519
signature per path. The requester supplies this metadata. The protocol does
not transfer or verify NAR contents. Nix imports the signatures through its
metadata-only cache operation.

A structured `--key-command` with repeated `--key-arg` values can also supply
the key through a pipe. `keygen NAME` generates an operator key. It writes the
private half to stdout and the public half to descriptor 3, and writes neither
half to disk.

`beforeHooks` and `afterHooks` are immutable notification executables. The
service delivers to them asynchronously from a durable queue, under the
unprivileged hook identity. Failed deliveries stay queued and never block a
verified recovery update. Each hook receives `UPDATE_PHASE`, `UPDATE_RESULT`,
`UPDATE_SYSTEM` and the original `UPDATE_EVENT_UNIX_SECONDS`. The service
clears the rest of its environment except `hookPath`. The section on durable
notifications below gives the delivery rules.

The integration VM tests the restricted SSH account, validation on both sides,
process identity checks, signature rejection, key replacement, closure copy,
hook ordering and privilege, and activation.

## Signed artifact integration

`services.nixUpdateRemote.artifact.enable` switches from signed Nix closures to
the signed EROFS backend. Both modes run through the same Rust login program
and the same privileged service, which checks its peer independently. An
artifact integration supplies only the mutable generation root, the trusted
public-key file and the immutable signature verifier. The account has no shell
and no sudo permission. Rust code handles artifact headers, payload lengths,
content hashes, sidecars, staging and atomic selection. The service verifies
the signatures of the kernel, initrd, configuration, rescue and optional
network and rescue tools payloads before it selects a generation. Uploads use
NMBL's `NMBL-EROFS-BUNDLE-4` format; the service refuses the older
`NMBL-EROFS-BUNDLE-3`, and refuses a configuration that pins a rescue tools
image (`[rescue.tools]`) without it, or an image the configuration does not
pin. A new attempt may replace an
unhealthy unconfirmed attempt, and the last tested fallback stays in place.
Only the boot health check can mark a generation as tested.

The complete operator transaction is:

```console
nix-update-remote deploy-generation \
  --installable .#nixosConfigurations.host --target update@node.example.test \
  --signing-key /run/keys/generation.key --sha512sum /path/to/sha512sum --reboot
```

The integration maps the image, config, rescue, signer and system attributes
with `--image-attribute`, `--config-attribute`, `--rescue-attribute`,
`--signer-attribute` and `--system-attribute`. The generic workflow defaults to
`system.build.updateArtifacts.*` and does not depend on any NMBL attribute.
`--signer-relative-path` gives the location of the signer executable. Optional
network artifacts use `--network-attribute` and `--network-enabled-attribute`,
and an optional rescue tools image uses `--tools-attribute` and
`--tools-enabled-attribute`. Without the predicate, an optional artifact is
built when the configuration defines its attribute.

The command builds those public outputs and registers GC roots in a
`system-update-roots-*` directory in the current checkout, and prints that
directory. It then signs and uploads the outputs, and removes the roots on
success or failure. If the process crashes, the directory may remain and you
have to clean it up. `deploy-artifact` runs the same signing and upload for
existing image, config, kernel, initrd and rescue files.

`--key-command PROGRAM` with repeated `--key-arg ARG` supplies a structured
key provider at runtime through an OS pipe. No shell evaluates it, and no
decrypted private key is written to disk. `--ssh-command PROGRAM` with
repeated `--ssh-arg` options plugs in an operator authentication provider.
The operator controls these providers, and they stay on the operator side of
the target's privilege boundary.

## Durable notifications

The service writes events to the root-owned `reportQueue`
(default `/persistent/system-update-reports`) and syncs them to disk. Before
events come before activation. Outcome events come after activation and before
any requested reboot. `beforeHooks` and `afterHooks` now receive these events
asynchronously through `system-update-report-delivery.service` and its retry
timer. During bootstrap or recovery, notification keys, DNS or SMTP may be
unavailable. Verified updates still go ahead, and failed notifications stay
queued. The journal shows queue failures and pending deliveries. Delivery
keeps the original `UPDATE_EVENT_UNIX_SECONDS`, clears supplementary groups,
switches to the configured non-root hook UID/GID and runs only immutable hook
programs. A delivery outage counts as pending work and does not mark the host
unhealthy.

`UPDATE_PHASE=before`, `UPDATE_RESULT=pending` records the verified candidate
before any change. `UPDATE_PHASE=after` records `success` or `failure` of
activation. For EROFS, success means the service selected the generation for
the next boot. It does not prove that the boot was healthy. A failed
verification records an after failure with candidate `unverified-artifact` and
never changes the selection. Delivery is at least once. A crash after the mail
server accepts a message and before the event is deleted may cause a
duplicate. Pending events stay on disk if you remove the hooks.

The `system-update-reporting` VM check in the server repository runs the
canonical Rust operator path for build, sign and SSH, and a real SSH-to-SMTP
report receiver. It tests missing reporting keys during repair, delayed before
and outcome delivery, verification failure, and account restrictions. The
signed-Nix closure VM check in this repository tests the same broker and
asynchronous hook delivery in closure mode.

### Bootstrap coherence and provisioning

With `artifact.bootstrap.enable`, each signed image must contain the fixed
regular files `/nmbl-bootstrap/kernel` and `/nmbl-bootstrap/initrd`. After it
verifies the image, the Rust adapter mounts it read-only with
nodev/nosuid/noexec in a private mount namespace and copies those files into
the generation. The adapter rejects symlinked metadata and missing bootstrap
files. The bootloader integration selects these files through the same atomic
generation selector as the runtime configuration, so a rollback also selects
the matching bootstrap pair. The caller supplies the immutable verifier. The
utility programs only do native hashing and mounts.

Initial rescue provisioning uses the same verification and activation code:

```console
nix-update-remote install-erofs ROOT PUBLIC_KEY SIGNER SHA512SUM \
  UNSHARE MOUNT UMOUNT --report-queue QUEUE < signed-bundle
```

The optional queue path must match the installed service, including the
installation mount prefix. This root-only role never requests a reboot.
Installed hosts use the restricted update account and broker.
`deploy-generation` accepts `--remote-command PROGRAM` and repeated
`--remote-arg ARG` for the initial rescue command, and quotes each argument
separately for SSH. The installed restricted service runs no shell code that a
caller chooses.

Closure updates accept `--activation-command PROGRAM` and repeated
`--activation-arg ARG`. The client runs this callback as soon as the restricted
`current-system` query reports the new configuration. At that point service
startup may still be waiting for credentials. The client waits for both the
callback and the activation result, and keeps its checkout GC roots the whole
time. A secrets provider can then ask for operator approval without waiting
behind services that need its values.

An integration may supply `--post-command PROGRAM` with repeated `--post-arg ARG`
for operator work after an update. With `--reboot`, the generation workflow waits
until the restricted SSH `current-system` query matches the built toplevel, then
runs that command. For example, the server integration asks nix-secrets to
deploy its secrets at this point. The updater does not depend on that provider.
Without a reboot, the client defers this post-operation, so secrets in a new
schema cannot be deployed into the old system.

### Configured operator client

`configured-deploy --installable FLAKE#CONFIG --plan FILE` evaluates a public
Nix metadata function against that configuration and runs the existing update
backend. The function supplies argument arrays for an external signing session,
SSH authentication, a key provider and a post-deployment operation. The updater
does not depend on those providers.

`--installable`, `--target-host update@HOST` and `--ssh-port PORT` can select a
runtime deployment configuration without rebuilding the application. The SSH
public key comes from that configuration. Target overrides keep its identity
and strict host verification. `--no-reboot` suppresses a configured reboot.
The client writes only the public SSH key to a temporary file under the
checkout, and removes it on exit. Backend GC roots stay alive through the
post-deployment step.

### Interrupted operator commands

SIGINT and SIGTERM cancel the deployment, terminate and reap the child process groups the command owns, and remove the command's temporary signed artifacts, public SSH key files and repository GC roots. The client closes the signing and upload pipes before cleanup.

SIGKILL and machine failure leave no chance to clean up. Their leftovers stay in the checkout as `system-update-*`. Remove an abandoned transaction only after you confirm that its operator processes have stopped. An active transaction must keep its roots until it completes.

The native client uses one SSH connection per operation to copy the closure and
signatures and to apply it. Activation progress comes back on the apply stream,
and the client opens no status connections. The client removes the private
control socket and the connection on completion or cancellation. If that
connection drops, the operation fails and the client does not start a new
authentication request. Pass connection options with repeated `--ssh-arg`
arguments. They configure the single connection that every phase uses. Older
receivers that return only a final receipt still work, and the activation
callback then runs after successful completion. Such a receiver may need the
secrets deployed before its first upgrade if service startup waits for them.
