# Harden as code

`sdw-armor harden` turns failing controls into a reviewed, opt-in plan and converges it with a native Chef run. It never runs a generated shell script.

## Workflow

```text
audit (or --from report.json)
  → candidates: failing, erroring or runtime-only controls with an automatic fix
  → you choose: per rule (y/n/a/q/?), or --rules / --fix-pillar / --all
  → plan (optionally saved with --plan-out and re-applied later with --plan)
  → safety guards: a rule that could lock you out or cut a service is left out
  → cinc-client --local-mode on the target (why-run with --dry-run)
  → the fixed controls are audited again; before → after and the new grade
  → with --reboot (ssh://): reboot, wait for the new boot, re-scan everything:
    reboot-proven fixes, pending fixes confirmed, anything lost at the reboot
```

```sh
sdw-armor harden ssh://web01 --sudo                                  # interactive
sdw-armor harden ssh://web01 --sudo --rules SA-06.02,SA-06.04 --yes  # non-interactive
sdw-armor harden ssh://web01 --sudo --all --dry-run                  # show what would change
sdw-armor harden ssh://web01 --sudo --from scan.json --all --plan-out plan.json
sdw-armor harden ssh://web01 --sudo --plan plan.json --yes -o json:after.json
sdw-armor harden ssh://web01 --sudo --rules SA-05.04,SA-06.01 --reboot   # prove it across a reboot
```

Exit code `1` when some fixed control is still not durably compliant (for example `pending` until a reboot), or, with `--reboot`, when a fixed control fails after the reboot or a pass was lost at it.

## Prove it across a reboot

Reading the boot configuration proves what the next boot should do; `--reboot` proves what it does. After converging and re-auditing, Shadow-Armor asks (unless `--yes`), reboots the target with `systemctl reboot`, waits for it to answer with a **new boot ID** (`--reboot-timeout`, 15 minutes by default), waits for `systemctl is-system-running --wait`, then scans every selected control again with the pre-reboot state as baseline:

```text
 AFTER THE REBOOT
  ✓ SA-05.04  Processes started before auditd are audited     pass/durable (fixed by the reboot)
  ✓ SA-06.02  No SSH login path relies on a password alone     pass/durable, reboot-proven

 71 pass(es) reboot-proven
 grade C (70.0) → C (74.8) after harden → B (81.3) after the reboot
```

- fixes that only take effect at boot (kernel command line, immutable audit rules) are confirmed: *pending* becomes *pass*;
- every control that passed before and after is **reboot-proven** (see [SCORING.md](SCORING.md#4-reboot-proven-the-empirical-proof));
- a pass that disappears is reported **lost at the reboot**.

`--reboot` needs an `ssh://` target: it cannot reboot the machine sdw-armor runs on, and a container has no boot of its own. For those, save a report (`-o json:before.json`), reboot yourself, then `sdw-armor scan --reboot-baseline before.json`.

## Requirements

- Root on the target (`--sudo` with non-interactive sudo, or connect as root).
- [CINC Client](https://cinc.sh/start/client/) (or Chef Infra Client) on the target. If it is missing Shadow-Armor stops. `sdw-armor install-cinc ssh://web01 --client --sudo` installs it beforehand, `--bootstrap-cinc` during the run: in both cases a package resolved on omnitruck, downloaded on your machine, SHA-256 verified, then installed with `dpkg`/`rpm`, never an installer script. `--cinc-package cinc_19.3.14-1_amd64.deb` uses a package you provide (see [INSTALL.md](INSTALL.md#4-the-scan-engine-cinc-auditor)).

## Safety guards

Some fixes can lock you out, or cut a service that works. Right before converging, Shadow-Armor checks the target; a rule whose guard fails is **left out of the run** (the others are applied) and the guard says what to do first. `--force` applies it anyway: use it only if you have another way in (console, out-of-band access).

| Guard | Used by | Stops the rule when |
|---|---|---|
| `root_key_login` | SA-06.01 (no root password over SSH) | root logs in with a password, has no SSH key, and no administrator account (key + sudo) can reach root |
| `ssh_not_root_session` | SA-06.21 (no root login at all) | you are logged in over SSH as root (an `ssh://` target, or a local run from an SSH session) |
| `admin_account_ready` | SA-06.21 | no account other than root can log in with an SSH key and use sudo |
| `ssh_key_access` | SA-06.02 (no password-only SSH) | you are logged in over SSH without a key, or no account at all can log in with a key; password-only accounts that will lose SSH are listed |
| `su_has_alternative` | SA-07.05 (su restricted) | users with a login shell exist and none of them can use sudo: su is their only way to root |
| `firewall_safe` | SA-02.19 (default-deny firewall) | the host is a Kubernetes node or a Proxmox VE host, or another firewall manager is active. Otherwise it lists the ports kept open: everything listening now, the sshd ports, `sdw_allowed_listening_ports` |
| `forwarding_unused` | SA-02.11 (IP forwarding off) | a container runtime, a VM or container bridge, a VPN, a routing daemon or NAT rules need forwarding |
| `removal_contained` | every package removal | removing the package would take other packages with it (for example `gcc` and `dkms`) |

Accounts are read the way sshd reads them: keys in every `AuthorizedKeysFile` location (an `AuthorizedKeysCommand` counts as a key source), sudo rights from `sudo -l -U`.

Other fixes protect themselves in the cookbook:

- root never gets a maximum password age or an inactivity limit (an expired root password also blocks key logins), and no account is expired or disabled the moment the fix is applied: those are listed for review;
- `PermitRootLogin` is never relaxed by a later run (`no` stays `no`);
- `/etc/cron.allow` lists root and every user that has a crontab when it is created;
- system accounts that own a crontab or an `authorized_keys` file keep their shell;
- packages are installed without their recommended packages (AIDE does not pull in a mail server);
- the world-writable and sticky-bit fixes skip container and VM storage (Docker, containerd, kubelet, LXC/LXD/Incus, Proxmox guest volumes, libvirt): harden the guests themselves.

## What the fixes change

Shadow-Armor prefers **files it owns** over editing vendor files. Deleting one of these files reverts the corresponding settings (then reload the service or reboot):

| File | Content |
|---|---|
| `/etc/ssh/sshd_config.d/00-shadow-armor.conf` | sshd settings; read first because sshd keeps the first value it sees. If sshd_config does not start with `Include /etc/ssh/sshd_config.d/*.conf`, a one-line `Include` of this file is inserted at the top. Validated with `sshd -t` before being written. OpenSSH < 8.2: a marked block at the top of sshd_config instead. |
| `/etc/sysctl.d/99-zz-shadow-armor.conf` | kernel parameters, applied live with `sysctl -w`; conflicting lines of `/etc/sysctl.conf` are commented |
| `/etc/modprobe.d/60-shadow-armor.conf` | `install <module> /bin/false` + `blacklist` |
| `/etc/audit/rules.d/60-shadow-armor.rules`, `99-zz-shadow-armor-finalize.rules` | audit rules, `-e 2` (loaded with `augenrules --load`) |
| `/etc/sudoers.d/zz-shadow-armor` | sudo `Defaults`, validated with `visudo -c` |
| `/etc/security/pwquality.conf.d/60-shadow-armor.conf` | password quality |
| `/etc/systemd/*.conf.d/60-shadow-armor.conf` | journald, coredump settings |
| `/etc/profile.d/60-shadow-armor-*.sh` | TMOUT, umask |
| `/etc/ssh/ssh_config.d/00-shadow-armor.conf` | SSH client defaults |
| `/usr/share/pam-configs/sdw-*` (Debian/Ubuntu) | pam_faillock / pam_pwhistory profiles enabled with `pam-auth-update` (RHEL-family: `authselect enable-feature`) |

Some fixes edit files in place (`/etc/login.defs`, `/etc/audit/auditd.conf`, `/etc/fstab`, `/etc/default/grub`, `/etc/pam.d/su`), remove packages, mask units or change permissions. Every file Chef modifies is backed up under `/var/lib/shadow-armor/backup`, and every run writes its plan to `/var/lib/shadow-armor/journal/<run_id>.json`.

Review any fix before applying it: `sdw-armor explain <id>` lists its declarative actions; `--dry-run` shows the exact Chef resources that would change, with diffs.

## Runtime vs persistence

The cookbook always writes the persistent configuration first, then tries to apply it live (sysctl, remount, reload, start). When the live step is impossible (read-only `/proc/sys` in a container, audit rules locked with `-e 2`, a kernel parameter that needs a reboot) the run continues and the re-audit reports the control as **pending**: the persisted state is right, a reboot or reload finishes the job. A package that cannot be installed (no repository access) does not stop the other fixes either; the re-audit reports what is still missing.

## Not automated, on purpose

Some controls only get documented manual steps (`sdw-armor explain <id>`): encrypting data volumes and swap, enabling SELinux/AppArmor, Secure Boot and GRUB passwords, removing NOPASSWD from sudoers, enrolling users in OTP/FIDO2 MFA, replacing weak host keys, choosing your log collector. Doing those unattended would be either impossible on a running system or too likely to lock someone out.

## The cookbook

The embedded cookbook (`sdw-armor export cookbook ./shadow_armor`) is an interpreter for the catalog's declarative actions (`profile/files/catalog.json`, `remediation.actions`). Each action kind maps to native Chef resources:

`sshd_config`, `sysctl`, `packages_absent`, `packages_present`, `services_disabled`, `services_enabled`, `file_mode`, `kv_file`, `systemd_dropin`, `modprobe_disable`, `audit_rules`, `sudoers_defaults`, `file_content`, `cron_allow`, `line_in_file`, `grub_cmdline`, `mount_options`, `firewall`, `pam_feature`, `group_present`, `group_members_empty`, `command`, `account_inactive`, `password_aging`, `lock_empty_passwords`, `expire_weak_hashes`, `system_accounts_nologin`, `home_permissions`, `dotfile_permissions`, `user_secret_permissions`, `private_key_permissions`, `mfa_secret_permissions`, `strip_world_writable`, `sticky_world_writable_dirs`, `aide_init`, `automatic_updates`, `security_updates`.

Values such as `{{sdw_ssh_max_auth_tries}}` are resolved from the same inputs the audit used, so the fix always matches the check.
