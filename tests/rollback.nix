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
      };
      services.openssh.enable = true;
      boot.loader.external = {
        enable = true;
        installHook = "${boot}/bin/boot-fixture";
      };
      specialisation = {
        good.configuration = generation "good";
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
          systemd.services.stuck-gate = gate "/run/stuck-gate-never";
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
    systems = {name: spec(name) for name in ["good", "broken", "bootfail", "stuck", "slow"]}

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
        f"{extra}"
      )

    def state():
      return {
        "current": machine.succeed("readlink /run/current-system").strip(),
        "profile": machine.succeed("readlink /nix/var/nix/profiles/system || echo none").strip(),
        "boot": machine.succeed("cat /var/lib/test-boot/default 2>/dev/null || echo none").strip(),
        "etc": machine.succeed("cat /etc/rollback-generation").strip(),
      }

    def assert_reachable_and_clean():
      client.succeed("nix --extra-experimental-features nix-command store ping --store ssh-ng://update@machine")
      machine.succeed("systemctl is-active sshd.socket || systemctl is-active sshd.service")
      machine.succeed("test ! -e /var/lib/nix-update-remote/transaction.json")
      machine.succeed("test -z \"$(systemctl list-units --failed --plain --no-legend)\"")

    def reset_client():
      client.succeed("rm -f /root/failure-reports /root/secrets-started /root/secrets-deployed /root/secrets-approve")

    def events():
      machine.succeed("systemctl start system-update-report-delivery.service")
      machine.wait_until_succeeds("test $(systemctl show system-update-report-delivery.service -p ActiveState --value) = inactive")
      return machine.succeed("cat /tmp/update-hook-events 2>/dev/null || true").splitlines()

    with subtest("a closure without a trusted signature changes nothing"):
      before = state()
      output = client.fail(deploy("good", key="untrusted") + " 2>&1")
      assert "host is unchanged" in output, output
      assert state() == before, state()
      client.succeed("test ! -e /root/secrets-started")
      client.succeed("grep -F 'host is unchanged' /root/failure-reports")
      assert_reachable_and_clean()
      reset_client()

    with subtest("a unit failing on start is rolled back and the secret step stopped"):
      before = state()
      # The waiter would hold the switch for its full 120 s; the failed unit
      # ends it within seconds instead.
      output = client.fail(deploy("broken") + " 2>&1", timeout=90)
      assert "rolled back" in output and "broken-on-start.service" in output, output
      assert "units failed during activation" in output, output
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
  '';
}
