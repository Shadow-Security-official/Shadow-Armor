# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.5.0] - 2026-09-26

Three new pillars: web services and TLS, databases, hardware and firmware. 35 controls, 197 in all.

### Added

- Pillar 13, **Web services & TLS** (13 controls). nginx through `nginx -T`, Apache through its include tree and run settings (`DUMP_INCLUDES`, `DUMP_RUN_CFG`), the HAProxy files the running process was given, Caddy through `caddy adapt`, lighttpd through `lighttpd -p`, Tomcat through the `server.xml` of each running instance: version banners, directory listing, TLS 1.2 floor (the default of each server version counts, and the system OpenSSL floor when the list is left at its default), root workers (configured and running), Apache TRACE, the HAProxy statistics page, the Caddy admin API, the Tomcat shutdown port and manager applications. Every local port that completes a TLS handshake is also probed from the target with `openssl s_client`, as a client sees it: TLS 1.0/1.1 refused, certificate valid for at least `sdw_tls_min_days` days, key size, HSTS.
- Pillar 14, **Databases** (12 controls). PostgreSQL (`pg_hba_file_rules`, `pg_settings` through psql as its OS user), MySQL and MariaDB (accounts, global variables, and `mysqld --verbose --help` for what the next start applies), Redis and Valkey, MongoDB, Memcached, Elasticsearch and OpenSearch: authentication everywhere, checked in the configuration and by an unauthenticated request; SCRAM for PostgreSQL; TLS for servers reachable over the network; no remote administrator; `local_infile` and `secure_file_priv`; dangerous Redis commands; Memcached UDP; MongoDB server-side JavaScript; no server running as root; private data directories. A server that runs but cannot be queried fails.
- Pillar 15, **Hardware & firmware** (10 controls): CPU flaw mitigations and the boot parameters that disable them, SMT where flaws require it, microcode packages, IOMMU, Thunderbolt security level, FireWire modules (fixed by `harden`), TPM 2.0, the BMC (IPMI cipher suite 0 and NONE authentication), pending firmware updates (fwupd), USBGuard. Controls that only mean something on physical hardware are not applicable in a virtual machine.
- Inputs `sdw_tls_min_days`, `sdw_tls_min_rsa_bits`, `sdw_hsts_min_age`, `sdw_postgres_os_user`, `sdw_mysql_client_options`.
- Unit tests of the profile's parsers (`ruby profile/test/parse_test.rb`), on outputs captured from nginx, PostgreSQL, MySQL and MariaDB; run in CI.

### Changed

- The score, the report (radar, pillar cards) and the CLI follow the pillars of the catalog instead of a fixed twelve.
- A control that is not applicable for several reasons reports the first one: a host control scanned inside a container says so, instead of a later condition.

## [0.4.0] - 2026-09-26

Install page, and a clear word on how strict the grading is.

### Added

- Install page, [armor.shadow-security.fr](https://armor.shadow-security.fr): pick a published release, a system (Debian and Ubuntu, RHEL family, other Linux, macOS), an architecture and a format; it writes one command for bash, zsh or sh that downloads the file, checks its SHA-256 (the digest GitHub publishes for the asset, or the release's `SHA256SUMS`; optionally the Sigstore signature with cosign) and installs it. Nothing is piped into a shell, and a checksum mismatch stops the command before the install. The README and `docs/INSTALL.md` point to it.

### Changed

- README (English and French): a note at the top says the scores are deliberately strict, that the top grade is close to impossible on a real production system, and that the grading is a clear grid of improvements to target security priorities, not a sanction of an architecture; accepted deviations are declared in a waiver file.

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
