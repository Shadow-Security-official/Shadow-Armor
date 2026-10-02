# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.6.0] - 2026-10-01

Scan profiles: every scan runs one, chosen at launch.

### Added

- Three scan profiles, independent of the standards, each one running the controls of the lighter ones: **basic** (41 controls, the essential checks: remote access, accounts, updates, exposed services; for a private, temporary development server), **advanced** (147, the essentials plus targeted checks; for a private server that is not exposed) and **complete** (197, every control; for a production server, exposed to the Internet or running critical applications). `sdw-armor scan --profile basic|advanced|complete`, `sdw-armor list --profiles`, `sdw-armor list --profile basic`.
- Without `--profile`, `scan` and `harden` (when it audits first) show the three profiles, their scope, the number of controls each one runs under the other filters and an example server, and ask. The answer can be a number, a key or a title in English or French.
- Reports show the profile next to the grade (terminal, HTML, Markdown) and record it in the JSON (`selection.profile`, `controls[].profile`); `sdw-armor diff` warns when two reports ran different profiles, since their grades do not compare. `scan --reboot-baseline` reuses the profile of the baseline.

### Changed

- A scan needs a profile. Without a terminal (CI, cron, a script), a scan or a harden that audits first stops with exit code 2 and lists the profiles: add `--profile`. `--level 1` and `--level 2` are still accepted, as `advanced` and `complete`.
- The catalog gives each control the lightest profile that runs it (`profile`) instead of a level; the InSpec tags carry `profile`, and `level` as before. `docs/CONTROLS.md` has a profile column and the profile table.
- README (English and French): both have the same sections (the French one gains how it works, targets and modes, CI, inputs and waivers, requirements, security and privacy). The quick start installs through [armor.shadow-security.fr](https://armor.shadow-security.fr) and leaves the manual download and verification to `docs/INSTALL.md`; its examples show the web, database and hardware pillars (`--pillar web|databases|hardware`), the TLS and MySQL inputs, and that web server, database and firmware settings are fixed by hand.
- README screenshots retaken with 0.6.0 on an Ubuntu 24.04 web server: the profile question in the live scan, the 15 pillars, a web and database scan, a container scan, `harden`, `explain` and `diff`. The home screen (`sdw-armor` alone) names the scan profiles and the web and database probes.
- `LICENSE` carries its copyright notice, Copyright 2026 Shadow Security, in place of the template line of the Apache License 2.0 appendix.

### Fixed

- `harden` on Debian and Ubuntu refreshes the package lists before any install, not only for `packages_present`: on a host whose lists were never fetched (minimal and container images), `libpam-pwquality` (SA-09.01, and SA-09.02 with it), `ufw` and `unattended-upgrades` could not be located and the fix failed silently, leaving the control failing at the re-audit.
- Terminal output on narrow terminals: the scan profile question, the harden summary (warning and journal lines), the report footer and the NEXT steps no longer wrap in the middle of a word; the harden header aligns its two grade lines.

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
