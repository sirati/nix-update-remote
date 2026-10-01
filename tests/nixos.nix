{ pkgs }:

let
  updater = import ../package.nix { inherit pkgs; };
  testHook = pkgs.runCommand "update-hook-fixture" { nativeBuildInputs = [ pkgs.rustc pkgs.stdenv.cc ]; } ''
    mkdir -p $out/bin
    rustc --edition 2024 ${./hook.rs} -o $out/bin/update-hook-fixture
  '';
  activationFixture = pkgs.runCommand "update-activation-fixture" { nativeBuildInputs = [ pkgs.rustc pkgs.stdenv.cc ]; } ''
    mkdir -p $out/bin
    rustc --edition 2024 ${./activation.rs} -o $out/bin/update-activation-fixture
  '';
  blockedHook = pkgs.runCommand "blocked-update-hook-fixture" { nativeBuildInputs = [ pkgs.rustc pkgs.stdenv.cc ]; } ''
    mkdir -p $out/bin
    rustc --edition 2024 --cfg blocked_report ${./hook.rs} -o $out/bin/update-hook-fixture
  '';
  wrongPeer = pkgs.writeText "remote-update-wrong-peer.py" ''
    import socket
    import sys

    peer = socket.socket(socket.AF_UNIX)
    peer.connect("/run/nix-update-remote/control.sock")
    request = f"NIX_UPDATE_REMOTE_1\nSWITCH\n{sys.argv[1]}\n".encode()
    try:
        peer.sendall(request)
        peer.shutdown(socket.SHUT_WR)
        assert peer.recv(128).startswith(b"ERR ")
    except BrokenPipeError:
        pass
  '';
in
{
  name = "restricted-rust-remote-update";

  nodes = {
    machine = {
      imports = [ ../nix/module.nix ];
      services.nixUpdateRemote = {
        enable = true;
        authorizedKeysFile = "/run/update-ssh/update";
        trustedPublicKeys = [
          "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
        ];
        trustedPublicKeysFile = "/run/nix-update-remote/trusted-public-keys";
        reportQueue = "/run/system-update-reports";
        beforeHooks = [ "${testHook}/bin/update-hook-fixture" ];
        afterHooks = [ "${testHook}/bin/update-hook-fixture" ];
      };
      services.openssh = {
        enable = true;
        settings.PermitRootLogin = "no";
      };
      environment.systemPackages = [ pkgs.python3 ];
      specialisation = {
        first.configuration.environment.etc."remote-update-generation".text = "first";
        second.configuration = {
          environment.etc."remote-update-generation".text = "second";
          systemd.services.nix-update-remote.environment.UPDATE_TEST_GENERATION = "second";
        };
        gated.configuration = {
          environment.etc."remote-update-generation".text = "gated";
          services.nixUpdateRemote.beforeHooks = pkgs.lib.mkForce [ "${blockedHook}/bin/update-hook-fixture" ];
          systemd.services.activation-gate = {
            wantedBy = [ "multi-user.target" ];
            serviceConfig = {
              Type = "oneshot";
              RemainAfterExit = true;
              ExecStart = "${activationFixture}/bin/update-activation-fixture server";
            };
          };
        };
        failed.configuration = {
          environment.etc."remote-update-generation".text = "failed";
          systemd.services.nix-update-remote.environment.UPDATE_TEST_GENERATION = "failed";
          systemd.services.activation-failure = {
            wantedBy = [ "multi-user.target" ];
            serviceConfig = { Type = "oneshot"; ExecStart = "${pkgs.coreutils}/bin/false"; };
          };
        };
        old-key.configuration.environment.etc."remote-update-generation".text = "old-key";
      };
      system.stateVersion = "26.05";
    };
    client = {
      environment.systemPackages = [ pkgs.nix pkgs.openssh ];
      system.stateVersion = "26.05";
    };
  };

  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("nix-update-remote.service")
    client.wait_for_unit("multi-user.target")

    machine.succeed("install -d -m 0700 -o root -g root /run/update-ssh")
    client.succeed("mkdir -p -m 0700 /root/.ssh")
    client.succeed("ssh-keygen -q -t ed25519 -N \"\" -f /root/.ssh/update-a")
    key_a = client.succeed("base64 -w0 /root/.ssh/update-a.pub").strip()
    machine.succeed(
      f"printf %s {key_a} | base64 -d > /run/update-ssh/update",
      "chmod 0400 /run/update-ssh/update",
    )

    shell = machine.succeed("getent passwd update | cut -d: -f7").strip()
    assert shell.endswith("/bin/nix-update-remote")
    assert not shell.endswith("/sh")
    machine.succeed("test $(stat -c %U:%G:%a /run/update-ssh/update) = root:root:400")
    machine.succeed("test $(stat -c %U:%G:%a /run/nix-update-remote) = root:update:2750")
    machine.succeed("test $(stat -c %U:%G:%a /run/nix-update-remote/control.sock) = root:update:660")
    machine.succeed("! nix --extra-experimental-features nix-command config show trusted-users | grep -w update")
    machine.fail("runuser -u update -- sudo -n true")

    effective = machine.succeed("sshd -T -C user=update,host=localhost,addr=127.0.0.1").lower()
    assert "authorizedkeysfile none" in effective
    assert "authorizedkeyscommand " in effective
    assert "nix-update-remote-authorized-keys authorized-keys /run/update-ssh/update %u update" in effective
    assert "disableforwarding yes" in effective
    assert "permittty no" in effective
    assert "permitrootlogin no" in machine.succeed(
      "sshd -T -C user=root,host=localhost,addr=127.0.0.1"
    ).lower()

    first = machine.succeed("readlink -f /run/current-system/specialisation/first").strip()
    second = machine.succeed("readlink -f /run/current-system/specialisation/second").strip()
    failed = machine.succeed("readlink -f /run/current-system/specialisation/failed").strip()
    gated = machine.succeed("readlink -f /run/current-system/specialisation/gated").strip()
    old_key = machine.succeed("readlink -f /run/current-system/specialisation/old-key").strip()

    machine.succeed(
      f"runuser -u update -- ${pkgs.python3}/bin/python3 ${wrongPeer} {first}"
    )
    machine.succeed(
      "journalctl -u nix-update-remote.service --no-pager | "
      "grep -F 'control peer is not this updater binary'"
    )

    ssh_common = (
      "-o BatchMode=yes -o StrictHostKeyChecking=no "
      "-o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes "
    )
    ssh_a = f"ssh {ssh_common}-i /root/.ssh/update-a update@machine"
    client.fail(f"{ssh_a} id")
    client.fail(
      f"printf 'NIX_UPDATE_REMOTE_1\\nSWITCH\\n/etc/passwd\\n' | {ssh_a} apply"
    )
    nix_ssh_a = ssh_common + "-i /root/.ssh/update-a"
    client.succeed(
      f"NIX_SSHOPTS='{nix_ssh_a}' nix --extra-experimental-features nix-command "
      "store ping --store ssh-ng://update@machine"
    )

    machine.succeed(
      "umask 077",
      "nix --extra-experimental-features nix-command key generate-secret "
      "--key-name update-a > /run/update-signing-a",
      "nix --extra-experimental-features nix-command key convert-secret-to-public "
      "< /run/update-signing-a > /run/nix-update-remote/trusted-public-keys",
      "chown root:update /run/nix-update-remote/trusted-public-keys",
      "chmod 0440 /run/nix-update-remote/trusted-public-keys",
      "cp /run/nix-update-remote/trusted-public-keys /run/update-public-a",
      "chown root:update /run/update-public-a",
      "chmod 0440 /run/update-public-a",
      f"nix --extra-experimental-features nix-command store sign -r "
      f"--key-file /run/update-signing-a {first} {old_key}",
    )
    client.succeed(
      f"printf 'NIX_UPDATE_REMOTE_1\\nSWITCH\\n{first}\\n' | {ssh_a} apply | "
      f"grep -Fx 'OK {first}'"
    )
    machine.succeed("grep -Fx first /etc/remote-update-generation")
    machine.succeed("systemctl start system-update-report-delivery.service")
    machine.wait_until_succeeds("test $(systemctl show system-update-report-delivery.service -p ActiveState --value) = inactive")
    events = machine.succeed("cat /tmp/update-hook-events").splitlines()
    assert events == [f"before pending {first}", f"after success {first}"]
    machine.succeed("test $(stat -c %U /tmp/update-hook-events) = update-notifier")

    client.succeed("ssh-keygen -q -t ed25519 -N \"\" -f /root/.ssh/update-b")
    key_b = client.succeed("base64 -w0 /root/.ssh/update-b.pub").strip()
    machine.succeed(
      f"printf %s {key_b} | base64 -d > /run/update-ssh/update.new",
      "chmod 0400 /run/update-ssh/update.new",
      "mv /run/update-ssh/update.new /run/update-ssh/update",
      "umask 077",
      "nix --extra-experimental-features nix-command key generate-secret "
      "--key-name update-b > /run/update-signing-b",
      "nix --extra-experimental-features nix-command key convert-secret-to-public "
      "< /run/update-signing-b > /run/nix-update-remote/trusted-public-keys.new",
      "chown root:update /run/nix-update-remote/trusted-public-keys.new",
      "chmod 0440 /run/nix-update-remote/trusted-public-keys.new",
      "mv /run/nix-update-remote/trusted-public-keys.new "
      "/run/nix-update-remote/trusted-public-keys",
      f"nix --extra-experimental-features nix-command store sign -r "
      f"--key-file /run/update-signing-b {second}",
    )
    client.fail(f"{ssh_a} id")
    ssh_b = ssh_a.replace("update-a", "update-b")
    nix_ssh_b = nix_ssh_a.replace("update-a", "update-b")
    client.succeed(
      f"NIX_SSHOPTS='{nix_ssh_b}' nix --extra-experimental-features nix-command "
      "store ping --store ssh-ng://update@machine"
    )

    client.fail(
      f"printf 'NIX_UPDATE_REMOTE_1\\nSWITCH\\n{old_key}\\n' | {ssh_b} apply"
    )
    machine.succeed("grep -Fx first /etc/remote-update-generation")

    # Deliberately give the unprivileged copy its old trust key. Its first
    # validation succeeds, but the independently configured root pass rejects.
    public_a = machine.succeed("cat /run/update-public-a").strip()
    machine.fail(
      f"printf 'NIX_UPDATE_REMOTE_1\\nSWITCH\\n{old_key}\\n' | "
      f"runuser -u update -- env NIX_UPDATE_REMOTE_STATIC_KEYS={public_a} "
      f"{shell} -c apply"
    )
    machine.succeed(
      "journalctl -u nix-update-remote.service --no-pager | "
      "grep -F 'rejected update: verifying closure failed'"
    )
    machine.succeed("grep -Fx first /etc/remote-update-generation")

    client.succeed(
      f"printf 'NIX_UPDATE_REMOTE_1\\nSWITCH\\n{second}\\n' | {ssh_b} apply | "
      f"grep -Fx 'OK {second}'"
    )
    machine.succeed("grep -Fx second /etc/remote-update-generation")
    # The unit changed during activation. Its new environment must only be
    # loaded after the successful response, without killing activation.
    machine.wait_until_succeeds("grep -zFx UPDATE_TEST_GENERATION=second /proc/$(systemctl show nix-update-remote.service -p MainPID --value)/environ")
    machine.succeed("systemctl start system-update-report-delivery.service")
    machine.wait_until_succeeds("test $(systemctl show system-update-report-delivery.service -p ActiveState --value) = inactive")
    events = machine.succeed("cat /tmp/update-hook-events").splitlines()
    assert events == [f"before pending {first}", f"after success {first}", f"before pending {second}", f"after success {second}"]

    # Exercise the production closure client and callback with real Nix/SSH.
    import shlex
    trusted_copy_key = machine.succeed("cat /run/nix-update-remote/trusted-public-keys").strip()
    client.succeed(f"NIX_SSHOPTS='{nix_ssh_b}' nix --extra-experimental-features nix-command --option trusted-public-keys {shlex.quote(trusted_copy_key)} copy --from ssh-ng://update@machine {second}")
    client.succeed("umask 077; ${updater}/bin/nix-update-remote keygen client-update > /root/client-update-key 3> /root/client-update.pub")
    client_public = client.succeed("cat /root/client-update.pub").strip()
    import shlex
    # Every closure path already exists remotely. Trust only the new client
    # key: copying content alone cannot satisfy recursive verification.
    machine.succeed("echo " + shlex.quote(client_public) + " > /run/nix-update-remote/trusted-public-keys; chown root:update /run/nix-update-remote/trusted-public-keys; chmod 0440 /run/nix-update-remote/trusted-public-keys")
    client.succeed("mkdir -p /root/.ssh; echo 'Host machine\n IdentityFile /root/.ssh/update-b\n IdentitiesOnly yes\n StrictHostKeyChecking no\n UserKnownHostsFile /dev/null\n BatchMode yes' > /root/.ssh/config")
    output = client.succeed(f"cd /root && NIX_SSHOPTS='{nix_ssh_b}' ${updater}/bin/nix-update-remote deploy --ssh-arg -o --ssh-arg BatchMode=yes --target update@machine --installable {second} --key-command ${pkgs.coreutils}/bin/cat --key-arg /root/client-update-key --post-command ${pkgs.findutils}/bin/find --post-arg /root --post-arg -maxdepth --post-arg 1 --post-arg -name --post-arg 'system-update-roots-*' --post-arg -exec --post-arg ${pkgs.coreutils}/bin/test --post-arg -L --post-arg '{{}}/system' --post-arg ';' --post-arg -print")
    assert "/root/system-update-roots-" in output, output
    client.succeed("test -z \"$(find /root -maxdepth 1 -name 'system-update-roots-*')\"")

    # A service waits for a deployment prerequisite. The real client must
    # invoke its external activation callback before the switch can finish.
    machine.succeed("touch /tmp/update-hook-block")
    machine.succeed(f"nix --extra-experimental-features nix-command store sign -r --key-file /run/update-signing-b {gated}")
    client.succeed(f"NIX_SSHOPTS='{nix_ssh_b}' nix --extra-experimental-features nix-command --option trusted-public-keys {shlex.quote(trusted_copy_key)} copy --from ssh-ng://update@machine {gated}")
    gated_command = f"cd /root && NIX_SSHOPTS='{nix_ssh_b}' ${updater}/bin/nix-update-remote deploy --ssh-arg -o --ssh-arg BatchMode=yes --target update@machine --installable {gated} --key-command ${pkgs.coreutils}/bin/cat --key-arg /root/client-update-key --activation-command ${activationFixture}/bin/update-activation-fixture --activation-arg client"
    client.succeed(f"(task_status=0; {gated_command} || task_status=$?; echo $task_status > /root/gated-update.status) > /root/gated-update.log 2>&1 </dev/null &")
    client.wait_until_succeeds("test -f /root/activation-callback-started", timeout=90)
    machine.succeed("grep -Fx gated /etc/remote-update-generation")
    machine.wait_until_succeeds("test -f /tmp/update-hook-blocked")
    assert machine.succeed("systemctl show activation-gate.service -p ActiveState --value").strip() == "activating"
    client.fail("test -f /root/gated-update.status")
    client.succeed("touch /root/activation-callback-finish")
    client.fail("test -f /root/gated-update.status")
    machine.succeed("touch /run/activation-gate-ready")
    client.wait_until_succeeds("test -f /root/gated-update.status", timeout=90)
    client.succeed("grep -Fx 0 /root/gated-update.status")
    machine.wait_for_unit("activation-gate.service")
    # Reporting is still blocked; the production update already succeeded.
    machine.succeed("test -f /tmp/update-hook-block; systemctl is-active system-update-report-delivery.service")
    machine.succeed("rm /tmp/update-hook-block")
    machine.wait_until_succeeds("test $(systemctl show system-update-report-delivery.service -p ActiveState --value) = inactive")
    client.succeed("test -z \"$(find /root -maxdepth 1 -name 'system-update-roots-*')\"")

    # Failure after /etc has changed must also refresh the broker. The next
    # restricted update must work without restarting services by hand.
    machine.succeed(f"nix --extra-experimental-features nix-command store sign -r --key-file /run/update-signing-b {failed}")
    client.succeed(f"NIX_SSHOPTS='{nix_ssh_b}' nix --extra-experimental-features nix-command --option trusted-public-keys {shlex.quote(trusted_copy_key)} copy --from ssh-ng://update@machine {failed}")
    retry_command = f"cd /root && NIX_SSHOPTS='{nix_ssh_b}' ${updater}/bin/nix-update-remote deploy --ssh-arg -o --ssh-arg BatchMode=yes --target update@machine --key-command ${pkgs.coreutils}/bin/cat --key-arg /root/client-update-key --installable"
    client.fail(f"{retry_command} {failed}")
    machine.succeed("grep -Fx failed /etc/remote-update-generation")
    machine.wait_until_succeeds("grep -zq UPDATE_TEST_GENERATION=failed /proc/$(systemctl show nix-update-remote.service -p MainPID --value)/environ")
    client.succeed(f"{retry_command} {second}")
    machine.succeed("grep -Fx second /etc/remote-update-generation")
    machine.wait_until_succeeds("grep -zq UPDATE_TEST_GENERATION=second /proc/$(systemctl show nix-update-remote.service -p MainPID --value)/environ")

    machine.succeed(
      "shred -u /run/update-signing-a /run/update-signing-b",
      "test ! -e /run/update-signing-a",
      "test ! -e /run/update-signing-b",
    )
  '';
}
