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
    hookUser = lib.mkOption { type = lib.types.str; default = "update-notifier"; };
    hookUid = lib.mkOption { type = lib.types.int; default = 2993; };
    hookGid = lib.mkOption { type = lib.types.int; default = cfg.hookUid; };
    hookPath = lib.mkOption { type = lib.types.str; default = "/run/current-system/sw/bin"; };
    beforeHooks = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Immutable executables run as hookUser after verification and before the profile switch; failure aborts the update.";
    };
    afterHooks = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Immutable executables run as hookUser after activation succeeds or fails; failure is logged without changing the activation result.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion =
          lib.hasPrefix "/" cfg.authorizedKeysFile
          && !(lib.hasPrefix "/nix/store/" cfg.authorizedKeysFile)
          && baseNameOf cfg.authorizedKeysFile == cfg.user;
        message = "remoteUpdate.authorizedKeysFile must be an absolute mutable file named after the user.";
      }
      {
        assertion = cfg.trustedPublicKeys != [ ] || cfg.trustedPublicKeysFile != null;
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
        SetEnv NIX_UPDATE_REMOTE_STATIC_KEYS=${staticKeysEnv} ${runtimeKeysEnv}
        DisableForwarding yes
        PermitTTY no
        PermitUserRC no
        X11Forwarding no
      Match all
    '';
    nix.settings.trusted-public-keys = cfg.trustedPublicKeys;

    systemd.services.nix-update-remote = {
      description = "Verified NixOS remote switch broker";
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
          ]
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

    systemd.tmpfiles.rules = [
      "d ${builtins.dirOf cfg.authorizedKeysFile} 0700 root root - -"
      "d /run/nix-update-remote 2750 root ${cfg.user} - -"
    ] ++ lib.optional (cfg.trustedPublicKeysFile != null)
      "d ${builtins.dirOf cfg.trustedPublicKeysFile} 0750 root ${cfg.user} - -";

    environment.systemPackages = [ cfg.package ];
  };
}
