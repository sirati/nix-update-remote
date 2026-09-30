{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.nixUpdateRemote;
  bundledUpdater = import ../package.nix { inherit pkgs; };
  updaterExe = lib.getExe cfg.package;
  staticKeysEnv = lib.concatStringsSep "," cfg.trustedPublicKeys;
  artifactArgs = [ cfg.artifact.stateRoot cfg.artifact.publicKeyFile cfg.artifact.verifier "${pkgs.coreutils}/bin/sha512sum" ]
    ++ lib.optionals cfg.artifact.bootstrap.enable [ "${pkgs.util-linux}/bin/unshare" "${pkgs.util-linux}/bin/mount" "${pkgs.util-linux}/bin/umount" ];
  runtimeKeysEnv = lib.optionalString (cfg.trustedPublicKeysFile != null) (
    "NIX_UPDATE_REMOTE_RUNTIME_KEYS=${cfg.trustedPublicKeysFile}"
  );
in
{
  options.services.nixUpdateRemote = {
    enable = lib.mkEnableOption "restricted, signed remote system updates";
    package = lib.mkOption {
      type = lib.types.package;
      default = bundledUpdater;
      defaultText = lib.literalExpression "the bundled safe Rust updater";
    };
    user = lib.mkOption {
      type = lib.types.str;
      default = "update";
    };
    uid = lib.mkOption {
      type = lib.types.int;
      default = 2990;
    };
    authorizedKeysFile = lib.mkOption {
      type = lib.types.str;
      default = "/persistent/ssh/authorized_keys.d/update";
      description = "Root-owned mode-0400 SSH public keys for the update account.";
    };
    trustedPublicKeys = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Nix public keys allowed to sign complete deployable closures.";
    };
    trustedPublicKeysFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Optional root-owned, update-group-readable mode-0440 file with
        additional activation verification keys. A key used to import a new
        closure must first be installed in Nix's trusted-public-keys by a
        generation signed with an existing trusted key.
      '';
    };
    artifact = {
      enable = lib.mkEnableOption "the signed EROFS artifact backend instead of signed Nix closures";
      stateRoot = lib.mkOption { type = lib.types.str; default = "/persistent/system-generations"; };
      publicKeyFile = lib.mkOption { type = lib.types.str; default = "/etc/system-update/trusted.pub"; };
      bootstrap.enable = lib.mkEnableOption "required authenticated bootstrap kernel/initrd metadata in each signed image";
      verifier = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = "Immutable signature verifier executable supplied by the artifact integration.";
      };
    };
    reportQueue = lib.mkOption {
      type = lib.types.str;
      default = "/persistent/system-update-reports";
      description = "Durable root-owned events awaiting asynchronous notification; reporting never blocks recovery updates.";
    };
    hookUser = lib.mkOption { type = lib.types.str; default = "update-notifier"; };
    hookUid = lib.mkOption { type = lib.types.int; default = 2993; };
    hookGid = lib.mkOption { type = lib.types.int; default = cfg.hookUid; };
    hookPath = lib.mkOption { type = lib.types.str; default = "/run/current-system/sw/bin"; };
    beforeHooks = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Notification executables for durable before events, delivered asynchronously as hookUser; outages never abort updates.";
    };
    afterHooks = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Notification executables for durable activation outcomes, retried asynchronously as hookUser.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = !cfg.artifact.enable || (lib.hasPrefix "/" cfg.artifact.stateRoot && !(lib.hasPrefix "/nix/store" cfg.artifact.stateRoot)
          && lib.hasPrefix "/" cfg.artifact.publicKeyFile && lib.hasPrefix "/nix/store/" cfg.artifact.verifier);
        message = "Artifact updates need a mutable absolute state root, absolute public key, and immutable verifier.";
      }
      {
        assertion =
          lib.hasPrefix "/" cfg.authorizedKeysFile
          && !(lib.hasPrefix "/nix/store/" cfg.authorizedKeysFile)
          && baseNameOf cfg.authorizedKeysFile == cfg.user;
        message = "remoteUpdate.authorizedKeysFile must be an absolute mutable file named after the user.";
      }
      {
        assertion = cfg.artifact.enable || cfg.trustedPublicKeys != [ ] || cfg.trustedPublicKeysFile != null;
        message = "remoteUpdate requires a static or runtime deployment signing public key.";
      }
      {
        assertion =
          cfg.trustedPublicKeysFile == null
          || (lib.hasPrefix "/" cfg.trustedPublicKeysFile
            && !(lib.hasPrefix "/nix/store/" cfg.trustedPublicKeysFile));
        message = "remoteUpdate.trustedPublicKeysFile must be an absolute mutable path.";
      }
      {
        assertion = lib.all (lib.hasPrefix "/nix/store/") (cfg.beforeHooks ++ cfg.afterHooks);
        message = "remoteUpdate hooks must be absolute Nix store executables.";
      }
      {
        assertion = cfg.hookUid > 0 && cfg.hookGid > 0;
        message = "remoteUpdate hooks must run with non-root UID and GID.";
      }
    ];

    users.groups.${cfg.user}.gid = cfg.uid;
    users.groups.${cfg.hookUser}.gid = cfg.hookUid;
    users.users.${cfg.hookUser} = {
      isSystemUser = true;
      uid = cfg.hookUid;
      group = cfg.hookUser;
    };
    users.users.${cfg.user} = {
      isSystemUser = true;
      uid = cfg.uid;
      group = cfg.user;
      home = "/var/empty";
      shell = updaterExe;
      # `!` makes OpenSSH reject even public-key authentication before it can
      # run the restricted login program. `*` is not a valid password hash,
      # while the Match block below also disables every password mechanism.
      hashedPassword = "*";
    };
    environment.shells = [ updaterExe ];

    security.wrappers.nix-update-remote-authorized-keys = {
      source = updaterExe;
      owner = "root";
      group = "root";
      permissions = "u=rwx,g=rx,o=rx";
    };

    services.openssh.extraConfig = ''
      Match User ${cfg.user}
        AuthorizedKeysFile none
        AuthorizedKeysCommand /run/wrappers/bin/nix-update-remote-authorized-keys authorized-keys ${cfg.authorizedKeysFile} %u ${cfg.user}
        AuthorizedKeysCommandUser root
        AuthenticationMethods publickey
        PasswordAuthentication no
        KbdInteractiveAuthentication no
        SetEnv NIX_UPDATE_REMOTE_MODE=${if cfg.artifact.enable then "artifact" else "closure"} NIX_UPDATE_REMOTE_STATIC_KEYS=${staticKeysEnv} ${runtimeKeysEnv}
        DisableForwarding yes
        PermitTTY no
        PermitUserRC no
        X11Forwarding no
      Match all
    '';
    nix.settings.trusted-public-keys = cfg.trustedPublicKeys;

    systemd.services.nix-update-remote = {
      description = "Verified NixOS remote switch broker";
      # Activation runs inside this service. Stopping it during its own update
      # would kill activation before reporting and replying to the client.
      restartIfChanged = false;
      stopIfChanged = false;
      wantedBy = [ "multi-user.target" ];
      after = [ "nix-daemon.service" ];
      serviceConfig = {
        Type = "simple";
        User = "root";
        Group = cfg.user;
        UMask = "0007";
        Restart = "on-failure";
        ExecStart = lib.escapeShellArgs (
          [
            updaterExe
            "daemon"
            "--nix"
            (lib.getExe pkgs.nix)
            "--nix-env"
            "${pkgs.nix}/bin/nix-env"
            "--update-uid"
            (toString cfg.uid)
            "--report-queue" cfg.reportQueue
            "--restart-command" "${pkgs.systemd}/bin/systemctl"
            "--restart-arg" "try-restart"
            "--restart-arg" "--no-block"
            "--restart-arg" "nix-update-remote.service"
          ]
          ++ lib.optionals cfg.artifact.enable (
            [ "--artifact-prepare" updaterExe "--artifact-activate" updaterExe "--reboot-command" "${pkgs.systemd}/bin/systemctl" ]
            ++ lib.concatMap (arg: [ "--artifact-prepare-arg" arg ]) ([ "prepare-erofs" ] ++ artifactArgs)
            ++ lib.concatMap (arg: [ "--artifact-activate-arg" arg ]) ([ "activate-erofs" ] ++ artifactArgs)
          )
          ++ lib.concatMap (key: [ "--trusted-key" key ]) cfg.trustedPublicKeys
          ++ lib.optionals (cfg.trustedPublicKeysFile != null) [
            "--trusted-key-file"
            cfg.trustedPublicKeysFile
          ]
          ++ lib.optionals (cfg.beforeHooks != [ ] || cfg.afterHooks != [ ]) [
            "--hook-uid" (toString cfg.hookUid)
            "--hook-gid" (toString cfg.hookGid)
            "--hook-path" cfg.hookPath
          ]
          ++ lib.concatMap (hook: [ "--before-hook" hook ]) cfg.beforeHooks
          ++ lib.concatMap (hook: [ "--after-hook" hook ]) cfg.afterHooks
        );
      };
    };

    systemd.services.system-update-report-delivery = lib.mkIf (cfg.beforeHooks != [ ] || cfg.afterHooks != [ ]) {
      description = "Deliver queued system update notifications";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        Type = "oneshot";
        User = "root";
        UMask = "0077";
        ExecStart = lib.escapeShellArgs (
          [ updaterExe "deliver-reports" "--queue" cfg.reportQueue
            "--hook-uid" (toString cfg.hookUid) "--hook-gid" (toString cfg.hookGid)
            "--hook-path" cfg.hookPath ]
          ++ lib.concatMap (hook: [ "--before-hook" hook ]) cfg.beforeHooks
          ++ lib.concatMap (hook: [ "--after-hook" hook ]) cfg.afterHooks
        );
        # Pending delivery is expected while keys, DNS or mail are unavailable.
        SuccessExitStatus = [ 1 ];
        TimeoutStartSec = "2min";
      };
    };
    systemd.timers.system-update-report-delivery = lib.mkIf (cfg.beforeHooks != [ ] || cfg.afterHooks != [ ]) {
      wantedBy = [ "timers.target" ];
      timerConfig = { OnBootSec = "10s"; OnUnitInactiveSec = "30s"; };
    };
    systemd.tmpfiles.rules = [
      "d ${builtins.dirOf cfg.authorizedKeysFile} 0700 root root - -"
      "d ${cfg.reportQueue} 0700 root root - -"
      "d /run/nix-update-remote 2750 root ${cfg.user} - -"
    ] ++ lib.optionals cfg.artifact.enable [
      "d ${cfg.artifact.stateRoot} 0700 root root - -"
    ] ++ lib.optional (cfg.trustedPublicKeysFile != null)
      "d ${builtins.dirOf cfg.trustedPublicKeysFile} 0750 root ${cfg.user} - -";

    environment.systemPackages = [ cfg.package ];
  };
}
