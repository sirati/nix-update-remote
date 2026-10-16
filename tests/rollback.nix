{ pkgs }:

# Every failed update ends in the previous system, fully restored: a unit
# that fails on start, a failing bootloader install, a daemon restarted in
# the middle of a switch and a closure without a trusted signature. A client
# that vanishes mid-switch does not stop a healthy update from completing.
let
  updater = import ../package.nix { inherit pkgs; };
  fixture = name: file: flags: pkgs.runCommand name { nativeBuildInputs = [ pkgs.rustc pkgs.stdenv.cc ]; } ''
    mkdir -p $out/bin
    rustc --edition 2024 ${flags} ${file} -o $out/bin/${name}
  '';
  activation = fixture "update-activation-fixture" ./activation.rs "";
  hook = fixture "update-hook-fixture" ./hook.rs "";
  boot = fixture "boot-fixture" ./boot.rs "";
  failingBoot = fixture "boot-fixture" ./boot.rs "--cfg failing_install";
  # The same updater under another store path: a system whose update login
  # is another binary than the one the daemon started with.
  skewedUpdater = pkgs.runCommand "nix-update-remote-skewed" { meta.mainProgram = "nix-update-remote"; } ''
    mkdir -p $out/bin
    cp ${updater}/bin/nix-update-remote $out/bin/
  '';
  generation = name: { environment.etc."rollback-generation".text = name; };
  # Specialisations inherit the base text; theirs replaces it.
  baseGeneration = { lib, ... }: { environment.etc."rollback-generation".text = lib.mkDefault "base"; };
  gate = path: {
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${activation}/bin/update-activation-fixture gate ${path}";
    };
  };
in
{
  name = "remote-update-rollback";

  nodes = {
    machine = { lib, ... }: {
      imports = [ ../nix/module.nix baseGeneration ];
      services.nixUpdateRemote = {
        enable = true;
        authorizedKeysFile = "/run/update-ssh/update";
        trustedPublicKeys = [ "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=" ];
        trustedPublicKeysFile = "/run/nix-update-remote/trusted-public-keys";
        reportQueue = "/run/system-update-reports";
        beforeHooks = [ "${hook}/bin/update-hook-fixture" ];
        afterHooks = [ "${hook}/bin/update-hook-fixture" ];
        health.settleSeconds = 3;
        # An outcome a rollback cannot change, such as a late backup.
        health.ignoredUnits = [ "outcome-check.service" ];
      };
      services.openssh.enable = true;
      # /boot as on ns1: a separate vfat partition with the same options.
      virtualisation.emptyDiskImages = [ 64 ];
      virtualisation.fileSystems."/boot" = {
        device = "/dev/vdb";
        fsType = "vfat";
        autoFormat = true;
        options = [ "umask=0077" "noatime" "nodev" "noexec" "nosuid" ];
      };
      # Broken since boot; every update keeps it broken.
      systemd.services.already-broken = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig = { Type = "oneshot"; ExecStart = "${pkgs.coreutils}/bin/false"; };
      };
      boot.loader.external = {
        enable = true;
        installHook = "${boot}/bin/boot-fixture";
      };
      specialisation = {
        good.configuration = generation "good";
        # Changes the broken unit, so the switch restarts it and exits 4.
        stillbroken.configuration = {
          imports = [ (generation "stillbroken") ];
          systemd.services.already-broken.environment.CHANGED = "1";
        };
        broken.configuration = {
          imports = [ (generation "broken") ];
          systemd.services.broken-on-start = {
            wantedBy = [ "multi-user.target" ];
            serviceConfig = { Type = "oneshot"; ExecStart = "${pkgs.coreutils}/bin/false"; };
          };
          # Like a secret waiter: holds the switch until secrets arrive.
          systemd.services.broken-waiter = gate "/run/broken-waiter-never";
        };
        bootfail.configuration = {
          imports = [ (generation "bootfail") ];
          boot.loader.external.installHook = lib.mkForce "${failingBoot}/bin/boot-fixture";
        };
        stuck.configuration = {
          imports = [ (generation "stuck") ];
          # A daemon restarted mid-switch starts this updater; the rollback
          # brings back the previous one.
          services.nixUpdateRemote.package = skewedUpdater;
          systemd.services.stuck-gate = gate "/run/stuck-gate-never";
        };
        skew.configuration = {
          imports = [ (generation "skew") ];
          services.nixUpdateRemote.package = skewedUpdater;
        };
        # Adds a check of an outside outcome that fails at once.
        outcome.configuration = {
          imports = [ (generation "outcome") ];
          systemd.services.outcome-check = {
            wantedBy = [ "multi-user.target" ];
            serviceConfig = { Type = "oneshot"; ExecStart = "${pkgs.coreutils}/bin/false"; };
          };
        };
        slow.configuration = {
          imports = [ (generation "slow") ];
          systemd.services.slow-gate = gate "/run/slow-gate-ready";
        };
      };
      system.stateVersion = "26.05";
    };
    client = {
      environment.systemPackages = [ pkgs.nix pkgs.openssh ];
      system.stateVersion = "26.05";
    };
  };

  testScript = ''
    import shlex
    start_all()
    machine.wait_for_unit("nix-update-remote.service")
    client.wait_for_unit("multi-user.target")

    def spec(name):
      return machine.succeed(f"readlink -f /run/current-system/specialisation/{name}").strip()
    base = machine.succeed("readlink -f /run/current-system").strip()
    systems = {name: spec(name) for name in ["good", "broken", "bootfail", "stuck", "slow", "stillbroken", "skew", "outcome"]}

    machine.succeed("install -d -m 0700 /run/update-ssh")
    client.succeed(
      "mkdir -p -m 0700 /root/.ssh",
      "ssh-keygen -q -t ed25519 -N \"\" -f /root/.ssh/update",
      "printf 'Host machine\\n IdentityFile /root/.ssh/update\\n IdentitiesOnly yes\\n StrictHostKeyChecking no\\n UserKnownHostsFile /dev/null\\n BatchMode yes\\n' > /root/.ssh/config",
      "umask 077; ${updater}/bin/nix-update-remote keygen trusted > /root/trusted-key 3> /root/trusted.pub",
      "umask 077; ${updater}/bin/nix-update-remote keygen untrusted > /root/untrusted-key 3> /root/untrusted.pub",
    )
    key = client.succeed("cat /root/.ssh/update.pub").strip()
    machine.succeed(f"echo {shlex.quote(key)} > /run/update-ssh/update; chmod 0400 /run/update-ssh/update")
    trusted = client.succeed("cat /root/trusted.pub").strip()
    machine.succeed(
      f"echo {shlex.quote(trusted)} > /run/nix-update-remote/trusted-public-keys",
      "chown root:update /run/nix-update-remote/trusted-public-keys",
      "chmod 0440 /run/nix-update-remote/trusted-public-keys",
    )
    # The specialisations are already in the machine's store; copying them
    # back makes them buildable on the client.
    for path in systems.values():
      client.succeed(f"nix --extra-experimental-features nix-command copy --no-check-sigs --from ssh-ng://update@machine {path}")

    def deploy(name, key="trusted", extra=""):
      return (
        f"cd /root && ${updater}/bin/nix-update-remote deploy --target update@machine "
        f"--installable {systems[name]} --key-command ${pkgs.coreutils}/bin/cat --key-arg /root/{key}-key "
        "--activation-command ${activation}/bin/update-activation-fixture --activation-arg secrets "
        "--failure-command ${activation}/bin/update-activation-fixture --failure-arg report "
        "--warning-command ${activation}/bin/update-activation-fixture --warning-arg warn "
        "--progress-command ${activation}/bin/update-activation-fixture --progress-arg progress "
        f"{extra}"
      )

    def state():
      return {
        "current": machine.succeed("readlink /run/current-system").strip(),
        "profile": machine.succeed("readlink /nix/var/nix/profiles/system || echo none").strip(),
        "boot": machine.succeed("cat /boot/test-boot-default 2>/dev/null || echo none").strip(),
        "etc": machine.succeed("cat /etc/rollback-generation").strip(),
      }

    def assert_reachable_and_clean():
      client.succeed("nix --extra-experimental-features nix-command store ping --store ssh-ng://update@machine")
      machine.succeed("systemctl is-active sshd.socket || systemctl is-active sshd.service")
      machine.succeed("test ! -e /var/lib/nix-update-remote/transaction.json")
      failed = machine.succeed("systemctl list-units --failed --plain --no-legend | cut -d' ' -f1").split()
      assert failed == ["already-broken.service"], failed

    def reset_client():
      client.succeed("rm -f /root/failure-reports /root/warning-reports /root/progress-reports /root/secrets-started /root/secrets-deployed /root/secrets-approve")

    def events():
      machine.succeed("systemctl start system-update-report-delivery.service")
      machine.wait_until_succeeds("test $(systemctl show system-update-report-delivery.service -p ActiveState --value) = inactive")
      return machine.succeed("cat /tmp/update-hook-events 2>/dev/null || true").splitlines()

    verifying = "verifying the closure signatures on the host"
    activating = "activating the new system"
    health = "checking the health of the new system"
    committing = "committing the new system to the profile and bootloader"
    rolling_back = "rolling back to the previous system"

    def assert_progress(*stages):
      lines = client.succeed("cat /root/progress-reports").splitlines()
      # The upload comes first, with its percentage.
      assert lines[0] == "--text uploading the closure --percent 0", lines
      assert any(line.endswith(" --percent 100") for line in lines), lines
      texts = [line.removeprefix("--text ") for line in lines if " --percent " not in line]
      assert texts == list(stages), lines

    # The daemon runs the updater that the update login of the current
    # system runs.
    same_updater = (
      "test \"$(readlink /proc/$(systemctl show -p MainPID --value nix-update-remote.service)/exe)\" = "
      "\"$(readlink -f $(getent passwd update | cut -d: -f7))\""
    )

    with subtest("a closure without a trusted signature changes nothing"):
      before = state()
      output = client.fail(deploy("good", key="untrusted") + " 2>&1")
      assert "host is unchanged" in output, output
      assert state() == before, state()
      client.succeed("test ! -e /root/secrets-started")
      client.succeed("grep -F 'host is unchanged' /root/failure-reports")
      assert_progress(verifying)
      assert_reachable_and_clean()
      reset_client()

    with subtest("a unit failing on start is rolled back and the secret step stopped"):
      before = state()
      # The waiter would hold the switch for its full 120 s; the failed unit
      # ends it within seconds instead.
      output = client.fail(deploy("broken") + " 2>&1", timeout=90)
      assert "rolled back" in output and "broken-on-start.service" in output, output
      assert "units failed during activation" in output, output
      assert_progress(verifying, activating, rolling_back)
      assert state() == before, state()
      assert before["etc"] == "base"
      # The secret deployment had started and was stopped before it ran.
      client.succeed("test -e /root/secrets-started")
      client.succeed("touch /root/secrets-approve; sleep 2; test ! -e /root/secrets-deployed")
      reports = client.succeed("cat /root/failure-reports")
      assert "rolling back" in reports.splitlines()[0], reports
      assert "restored and verified" in reports.splitlines()[-1], reports
      machine.fail("systemctl cat broken-on-start.service")
      assert_reachable_and_clean()
      assert f"after rolled-back {systems['broken']}" in events()
      reset_client()

    with subtest("a healthy update commits the profile and the boot entry"):
      client.succeed("touch /root/secrets-approve")
      client.succeed(deploy("good"))
      good = state()
      assert good["current"] == systems["good"] and good["etc"] == "good", good
      assert machine.succeed("readlink -f /nix/var/nix/profiles/system").strip() == systems["good"]
      assert good["boot"] == systems["good"], good
      assert_progress(verifying, activating, health, committing)
      client.succeed("test -e /root/secrets-deployed")
      assert_reachable_and_clean()
      reset_client()

    with subtest("a failing bootloader install restores profile, boot entry and system"):
      output = client.fail(deploy("bootfail") + " 2>&1")
      assert "installing the bootloader failed" in output and "rolled back" in output, output
      assert state() == good, state()
      assert_reachable_and_clean()
      assert f"after rolled-back {systems['bootfail']}" in events()
      reset_client()

    with subtest("a daemon restarted in the middle of a switch rolls it back on start"):
      client.succeed("touch /root/secrets-approve")
      client.succeed(f"(set +e; {deploy('stuck')} > /root/stuck.log 2>&1; echo $? > /root/stuck.status) > /dev/null 2>&1 < /dev/null &")
      machine.wait_until_succeeds(f"test $(readlink /run/current-system) = {systems['stuck']}", timeout=120)
      machine.wait_until_succeeds("test $(systemctl show stuck-gate.service -p ActiveState --value) = activating")
      machine.succeed("test -e /var/lib/nix-update-remote/transaction.json")
      machine.succeed("systemctl restart nix-update-remote.service")
      machine.wait_until_succeeds(f"test $(readlink /run/current-system) = {good['current']}", timeout=180)
      machine.wait_until_succeeds("test ! -e /var/lib/nix-update-remote/transaction.json", timeout=180)
      try:
        client.wait_until_succeeds("test -e /root/stuck.status", timeout=120)
      finally:
        print(client.execute("cat /root/stuck.log; ps -eo pid,ppid,pgid,sid,stat,args")[1])
        print(machine.execute("ps -eo pid,ppid,stat,args | grep -v '\\['; journalctl -u nix-update-remote.service -o cat | tail -n 30")[1])
      client.fail("grep -x 0 /root/stuck.status")
      client.succeed("grep -F 'lost the update connection' /root/stuck.log")
      assert state() == good, state()
      machine.succeed("journalctl -u nix-update-remote.service -o cat | grep -F 'update daemon was interrupted'")
      machine.wait_for_unit("nix-update-remote.service")
      assert_reachable_and_clean()
      # The interrupted switch had started the updater of the new system;
      # after its rollback the daemon runs the previous one again.
      machine.wait_until_succeeds(same_updater, timeout=60)
      assert f"after rolled-back {systems['stuck']}" in events()
      reset_client()

    with subtest("a client that vanishes mid-switch does not stop a healthy update"):
      client.succeed("touch /root/secrets-approve")
      # Its own session holds the client and every SSH process it started.
      client.succeed(f"setsid sh -c {shlex.quote('echo $$ > /root/slow.sid; ' + deploy('slow') + ' > /root/slow.log 2>&1')} > /dev/null 2>&1 < /dev/null &")
      machine.wait_until_succeeds(f"test $(readlink /run/current-system) = {systems['slow']}", timeout=120)
      client.wait_until_succeeds("test -s /root/slow.sid")
      sid = client.succeed("cat /root/slow.sid").strip()
      client.succeed(f"pkill -KILL -s {sid}")
      client.wait_until_succeeds(f"! pgrep -s {sid}")
      machine.succeed("touch /run/slow-gate-ready")
      machine.wait_until_succeeds("test ! -e /var/lib/nix-update-remote/transaction.json", timeout=180)
      slow = state()
      assert slow["current"] == systems["slow"] and slow["boot"] == systems["slow"], slow
      assert machine.succeed("readlink -f /nix/var/nix/profiles/system").strip() == systems["slow"]
      assert f"after success {systems['slow']}" in events()
      machine.wait_for_unit("nix-update-remote.service")
      assert_reachable_and_clean()

    with subtest("a unit already broken before the update stays broken: the update commits with a warning"):
      reset_client()
      client.succeed("touch /root/secrets-approve")
      output = client.succeed(deploy("stillbroken") + " 2>&1")
      assert "already-broken.service was already failed before the update and still is" in output, output
      assert "exited with status 4" in output, output
      kept = state()
      assert kept["current"] == systems["stillbroken"] and kept["etc"] == "stillbroken", kept
      assert kept["boot"] == systems["stillbroken"], kept
      assert machine.succeed("readlink -f /nix/var/nix/profiles/system").strip() == systems["stillbroken"]
      client.succeed("grep -F 'updated with warnings' /root/warning-reports | grep -F already-broken.service")
      client.succeed("test ! -e /root/failure-reports")
      client.succeed("test -e /root/secrets-deployed")
      assert f"after success {systems['stillbroken']}" in events()
      assert_reachable_and_clean()

    with subtest("after a switch outside the updater, the daemon follows the new update login"):
      reset_client()
      client.succeed("touch /root/secrets-approve")
      # As on ns1: the system changes without the daemon, which keeps the
      # updater it started with, while sshd runs the new system's login.
      machine.succeed(f"{systems['skew']}/bin/switch-to-configuration test || true")
      assert machine.succeed("readlink /run/current-system").strip() == systems["skew"]
      machine.fail(same_updater)
      client.succeed(deploy("good"))
      updated = state()
      assert updated["current"] == systems["good"] and updated["boot"] == systems["good"], updated
      # The daemon named both binaries and restarted; the login went on.
      machine.succeed(
        "journalctl -u nix-update-remote.service -o cat | grep -F 'restarting into the current updater' "
        "| grep -F 'the update login of the current system is /nix/store/' | grep -F nix-update-remote-skewed"
      )
      machine.wait_until_succeeds(same_updater, timeout=60)
      assert_reachable_and_clean()

    with subtest("the broker can write /boot; a sandboxed transient unit cannot"):
      for prop in ["ProtectSystem", "PrivateMounts", "ReadOnlyPaths", "InaccessiblePaths"]:
        value = machine.succeed(f"systemctl show nix-update-remote.service -p {prop} --value").strip()
        assert value in ("no", ""), (prop, value)
      current = machine.succeed("readlink /run/current-system").strip()
      machine.succeed(f"systemd-run --wait --collect --quiet ${boot}/bin/boot-fixture {current}")
      # What failed on ns1: the probe under ProtectSystem, which remounts
      # /boot read-only although the host mounts it read-write.
      machine.fail(f"systemd-run --wait --collect --quiet -p ProtectSystem=full ${boot}/bin/boot-fixture {current}")
      machine.succeed("journalctl -o cat | grep -F '/boot is not writable'")
      machine.succeed("findmnt -no OPTIONS /boot | grep -w rw")

    with subtest("an ignored unit failing in the new system does not roll it back"):
      reset_client()
      client.succeed("touch /root/secrets-approve")
      client.succeed(deploy("outcome"))
      kept = state()
      assert kept["current"] == systems["outcome"] and kept["boot"] == systems["outcome"], kept
      assert machine.succeed("systemctl is-failed outcome-check.service").strip() == "failed"
      client.succeed("test ! -e /root/failure-reports")
      assert f"after success {systems['outcome']}" in events()
  '';
}
