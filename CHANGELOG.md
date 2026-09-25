# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.1] - 2026-09-25

First public release.

### Added

- `sdw-armor`, a single static binary (Linux and macOS, amd64 and arm64) with the InSpec profile and the Chef cookbook embedded; `.deb` and `.rpm` packages; a CycloneDX 1.6 SBOM (Go toolchain, embedded profile and cookbook with tree hashes); SLSA build provenance and SBOM attestations; Sigstore-signed `SHA256SUMS`.
- 162 controls organised in 12 hardening pillars, including data encryption at rest and crypto / FIDO / OTP multi-factor policies, each mapped to CIS Controls v8 and CIS Benchmark recommendations, ANSSI BP-028 v2.0, NIST SP 800-53 Rev. 5, NIST SP 800-171 Rev. 2, PCI DSS v4.0 and DISA SRG.
- Effective-state probes: `sshd -T` with the origin of each keyword and Match-block analysis, sysctl live vs boot value (systemd-sysctl precedence), systemd units, `auditctl` vs rules.d (augenrules order), PAM stacks with includes, sudoers with includes, `modprobe --showconfig`, `systemd-analyze cat-config`, mounts vs fstab/mount units, dm-crypt chains, OpenSSL protocol floor, SSH algorithms and host keys, MFA posture, deleted libraries in memory.
- Qualified verdicts (durable, runtime-only, pending) with three proof columns per control (running now, on disk, after a reboot) built from declared evidence kinds (live, boot, resolved config, inventory, files, transient), checked against the control code by a test; fail-closed errors, container-aware scoping.
- Reboot-proven verdicts: reports record the boot identity; `scan --reboot-baseline`, `harden --reboot` and a reboot-aware `diff` prove what survives a real reboot and flag what is lost at it.
- Published A-E scoring formula with severity weights, a critical cap and a runtime cap that applies when the A rests on runtime-only passes; per-pillar grades and standard lenses; identical Go and JavaScript implementations.
- Targets `local`, `ssh://` (your `~/.ssh/config`) and `docker://`; native, `--on-target` and Docker engine modes (`--engine docker` runs CINC Auditor from its pinned container image, digest recorded in the report).
- `install-cinc`, `--bootstrap-cinc` and `--cinc-package`: explicit CINC installation from a package resolved on omnitruck, downloaded on the control host, SHA-256 verified before anything runs and installed with dpkg/rpm, never an installer script.
- Reports: terminal, self-contained HTML (offline, hash-based CSP), JSON, SARIF, JUnit, Markdown; `report` re-rendering and `diff` drift detection with CI exit codes. Failures read as "found X · expected Y".
- `harden`: per-rule opt-in, plan files, why-run dry runs, `cinc-client --local-mode` convergence, closed-loop re-audit with before/after grade, backups and run journal.
- Safety guards run before every converge and leave out the rules that could lock you out or cut a running service: root password logins (`root_key_login`), root login over SSH (`ssh_not_root_session`, `admin_account_ready`), password authentication (`ssh_key_access`), su restriction (`su_has_alternative`), default-deny firewall (`firewall_safe`: every port listening now stays open), IP forwarding (`forwarding_unused`), package removals that would take other packages with them (`removal_contained`).
- Terminal interface: banner, live progress on every engine, result screen with the grade, the proof behind the passes, pillar bars and the grade `harden` can reach; plain text off a terminal or with `--no-color`.
- `sdw-armor update`: says whether a newer release is published; installs nothing (exit 0 up to date, 1 a newer release exists).
- `sdw-armor upgrade`: downloads the latest release (or `--version vX.Y.Z`), refuses it unless its SHA-256 matches the release's `SHA256SUMS`, verifies the Sigstore signature of `SHA256SUMS` when cosign is installed (or the build provenance with a logged-in GitHub CLI; `--strict` requires one of them), checks that the new binary runs, then replaces the running binary with an atomic rename. A binary installed by the `.deb` or `.rpm` package is upgraded with `dpkg` or `rpm`.
- `explain` (with what a PASS proves), `list`, `doctor`, `export`, `version`.

### Security

- SSH root login: level 1 (SA-06.01) refuses root **passwords** and accepts `prohibit-password`, so a host reached as root with a key keeps working; refusing root entirely is a separate level 2 control (SA-06.21) whose fix is refused unless an administrator account can log in with a key and use sudo.
- Root never gets a password maximum age or an inactivity limit (an expired root password also blocks key logins); no account is expired or disabled the moment a fix is applied.
- `/etc/cron.allow` keeps every user that has a crontab; system accounts that own a crontab or an `authorized_keys` file keep their shell; packages are installed without their recommended packages; world-writable fixes skip container and VM storage.
