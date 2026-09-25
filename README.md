# Shadow-Armor

**Effective Linux compliance & hardening, over CINC / InSpec.**

Shadow-Armor audits the configuration your services *actually run* (`sshd -T`, `sysctl`, `systemctl`, `auditctl`), not just the files on disk. It maps each control to every applicable standard (CIS, ANSSI BP-028, NIST 800-53 / 800-171, PCI-DSS, DISA STIG), grades the host from A to E, and hardens it as code. One static binary: `sdw-armor`.

🇫🇷 [Lire en français](README.fr.md)

<p align="center"><img src="docs/img/home.png" alt="sdw-armor: the shield emblem and SHADOW-ARMOR in relief block letters, violet to cyan, above the command list" width="880"></p>

<p align="center"><img src="docs/img/scan.gif" alt="A live scan over SSH: steps ticking off, a spinner and a shimmering verb following the pillar being audited, a progress line with running pass and fail counts, then the result screen" width="720"></p>

<table>
<tr>
<td width="50%"><img src="docs/img/result.png" alt="The result screen: the grade C in big relief letters, the score gauge with its A to E bands, findings by severity, what the passes prove, the grade of each of the 12 pillars, and the harden path from D 62.8 to A 94.3"></td>
<td width="50%"><img src="docs/img/harden.png" alt="sdw-armor harden: the harden path, the plan as a tree with the risk of each fix, the safety guards, one line per changed resource, the re-audit and the grade transition in big letters"></td>
</tr>
<tr>
<td><b>scan</b>: the grade, the proof behind it, every pillar, and the grade <code>harden</code> can reach</td>
<td><b>harden</b>: plan, guards, converge, re-audit, the grade moving</td>
</tr>
<tr>
<td><img src="docs/img/explain.png" alt="sdw-armor explain SA-06.01: why the control matters, the effective probe, what a pass proves, its CIS, ANSSI, NIST, PCI DSS and DISA mappings, and its automatic remediation"></td>
<td><img src="docs/img/diff.png" alt="sdw-armor diff: D 62.8 before, C 68.1 after, 9 fixed controls, none regressed"></td>
</tr>
<tr>
<td><b>explain</b>: why, how it is checked, what a PASS proves, every mapping, the fix</td>
<td><b>diff</b>: fixed, regressed, drifted, lost at a reboot</td>
</tr>
</table>

## Features

- **Effective, not file-based.** A control on a service reads the resolved state: `sshd -T`, live `sysctl` values, `systemctl show`, `auditctl -l`, PAM stacks with every `@include` expanded, sudoers with every `#includedir`, `modprobe --showconfig`, `systemd-analyze cat-config`. It sees the `Include`s and drop-ins a file read misses (a permissive `50-cloud-init.conf` overriding a stricter main config) and **names the file and line that set the effective value**.
- **One control, every applicable mapping.** 162 neutral controls, each carrying its CIS Controls v8 safeguards and CIS Benchmark recommendation, ANSSI BP-028 v2.0, NIST SP 800-53 Rev. 5 and SP 800-171, PCI DSS v4.0 and DISA SRG references.
- **12 hardening pillars**, each with its own grade (table below), including data encryption at rest and crypto / FIDO / OTP multi-factor policies.
- **A qualified verdict: what a PASS proves.** Every verdict carries three proof columns, **running now · on disk · after a reboot**, built from the kind of state each assertion reads (live, boot configuration, resolved config, inventory, files). A PASS is **durable** or **runtime-only** (the persisted state contradicts it, or nothing on disk proves it); a FAIL can be **pending** (already fixed on disk, waiting for a reboot or reload). Persistence is folded into the checks wherever it has a clean source (sysctl.d, enabled units, modprobe.d, fstab, boot command line, rules.d, firewall and MAC at boot, lockdown, swap), and a test keeps each control's declared evidence honest against its code. An A that rests on runtime-only passes is capped at B, and only when it rests on them, so failing a control never grades better than passing it.
- **Reboot-proven.** Every report records the boot it observed. `scan --reboot-baseline before.json` compares two scans of the same machine across a real reboot: what survived is **reboot-proven**, what vanished is **lost at the reboot**. `harden --reboot` does it end to end: fix, re-audit, reboot, wait for the new boot, prove.
- **A:E grade.** A [published formula](docs/SCORING.md) (severity-weighted, critical-capped, fail-closed), computed identically in the CLI and in the HTML report. Re-grade the same scan through a single standard with a **standard lens** (`--lens anssi`, `--lens pci`...).
- **Harden as code.** `sdw-armor harden` plans the fixes, you opt in per rule, safety guards leave out any rule that would lock you out or cut a running service, and a native Chef run (`cinc-client --local-mode`) converges declarative remediations. The fixed controls are then **audited again**. Why-run dry runs, reviewable plan files, backups of every edited file, a journal of every run.
- **Nothing installed behind your back.** Runs `cinc-auditor` against `local`, `ssh://` or `docker://` targets with your own `~/.ssh/config`; no agent, no daemon. `--on-target` needs the engine on the target and stops if it is missing. CINC is installed only on request (`install-cinc`, `--bootstrap-cinc`): a package downloaded on your machine, checked against its published SHA-256, installed with `dpkg`/`rpm`; the target needs no Internet access, air-gapped sites bring their own package.
- **Verifiable releases.** Static binaries, `.deb` and `.rpm` packages, a CycloneDX SBOM (with hashes of the embedded profile and cookbook), SLSA build provenance and SBOM attestations, Sigstore-signed checksums. No third-party Go module.
- **Container-aware.** In a container, host-level controls (kernel, boot chain, firewall, audit subsystem) are *not applicable*; package, account, SSH, sudo, crypto and patch controls still run. `--input sdw_assume_host=true` evaluates everything (system containers such as LXC).
- **Outputs.** Terminal, self-contained offline HTML, JSON, SARIF (GitHub code scanning), JUnit, Markdown; `--fail-under C` gates a build, `sdw-armor diff --fail-on-regression` catches drift between two scans.

## Quick start

### 1. Download

```sh
VERSION=v0.3.1   # see https://github.com/Shadow-Security-official/Shadow-Armor/releases
ARCH=amd64       # or arm64
BASE=https://github.com/Shadow-Security-official/Shadow-Armor/releases/download/$VERSION
curl -fsSLO "$BASE/sdw-armor-linux-$ARCH"
curl -fsSLO "$BASE/SHA256SUMS"
```

`.deb` and `.rpm` packages are published too: [docs/INSTALL.md](docs/INSTALL.md).

### 2. Verify

```sh
sha256sum --ignore-missing --check SHA256SUMS                                           # integrity
gh attestation verify "sdw-armor-linux-$ARCH" --repo Shadow-Security-official/Shadow-Armor   # who built it (SLSA)
sudo install -m 0755 "sdw-armor-linux-$ARCH" /usr/local/bin/sdw-armor
```

The checksum proves the file did not change; the provenance proves it came out of this repository's release workflow (`gh` 2.49 or newer). Cosign-signed checksums and the SBOM: [docs/INSTALL.md](docs/INSTALL.md).

### 3. Scan

Shadow-Armor drives [CINC Auditor](https://cinc.sh/start/auditor/), the free build of Chef InSpec (Chef InSpec 5+ works too). It is in no distribution repository; install it from a SHA-256 verified package:

```sh
sdw-armor install-cinc --sudo        # asks first; `--print` shows the same steps as shell commands
sdw-armor doctor                     # engine, privileges, and the fix of every gap
```

```sh
sudo sdw-armor scan                                    # this host
sdw-armor scan ssh://admin@web01 --sudo                # over SSH, with your ~/.ssh/config
sdw-armor scan ssh://web01 --sudo --on-target          # engine runs on the target: much faster
sdw-armor scan docker://my-app                         # a running container
sdw-armor scan ssh://web01 --sudo --engine docker      # no engine installed here: run it from its Docker image
sdw-armor scan ssh://web01 --sudo -o html:web01.html -o json:web01.json
sdw-armor scan --level 2 --lens anssi                  # hardened level, graded through ANSSI BP-028
```

### 4. Fix

```sh
sdw-armor harden ssh://web01 --sudo                    # audit, then opt in rule by rule
sdw-armor harden ssh://web01 --sudo --from web01.json --rules SA-06.02,SA-06.04 --dry-run
sdw-armor harden ssh://web01 --sudo --from web01.json --all --plan-out plan.json   # review first
sdw-armor harden ssh://web01 --sudo --plan plan.json --yes                         # then apply it
sdw-armor harden ssh://web01 --sudo --rules SA-05.04,SA-06.02 --reboot              # and prove it survives a reboot
```

`harden` needs [CINC Client](https://cinc.sh/start/client/) on the target (`sdw-armor install-cinc ssh://web01 --client --sudo`, or `--bootstrap-cinc`). Before converging, safety guards check the target and leave out any rule that would lock you out (root login, password authentication, su) or cut something that runs (firewall, IP forwarding, package removals): [docs/HARDENING.md](docs/HARDENING.md).

### 5. Stay up to date

```sh
sdw-armor update          # is a newer release published? installs nothing
sudo sdw-armor upgrade    # download, verify (SHA-256, and Sigstore with cosign), install
```

## The 12 pillars

| # | Pillar | Règle | Controls |
|---|---|---|---|
| 01 | Application security & least privilege | Contrôlez la sécurité et limitez les droits applicatifs | MAC enforcing, ASLR, ptrace, kernel pointers, eBPF, core dumps, systemd sandboxing, NX |
| 02 | Attack surface & non-essential services | Réduisez la surface d'attaque, désactivez les services non essentiels | legacy servers, listening ports, modules, network sysctls, default-deny firewall, /tmp /dev/shm options |
| 03 | Risky application clients | Supprimez les clients applicatifs à risque | telnet, rsh, NIS, FTP/TFTP, netcat -e, compilers, SSH client agent/X11 forwarding |
| 04 | Server configuration integrity | Auditez vos configurations serveurs | AIDE and its schedule, sensitive file permissions, boot loader, cron, Secure Boot, lockdown, world-writable and orphan files |
| 05 | Logging & audit trail | Activez les logs, première étape vers la conformité | logger, persistent journal, auditd and its rules (loaded *and* persisted), immutable audit, remote logging, time sync |
| 06 | SSH access | Renforcez la sécurité et la configuration des accès SSH | everything from `sshd -T`, Match blocks that relax settings, config and host key permissions |
| 07 | Privilege escalation | Contrôlez l'escalade de privilèges | sudo (effective policy), NOPASSWD, use_pty, logging, su restriction, setuid allowlist |
| 08 | Local users & groups | Contrôlez la configuration des utilisateurs et groupes locaux | UID 0, empty passwords, system accounts, homes, dot files, dormant accounts, umask, TMOUT |
| 09 | Local password policy | Appliquez une politique de sécurité des mots de passe | pwquality as PAM enforces it, history, lockout, hashing *and the hashes actually stored*, nullok |
| 10 | Updates & patching | Vérifiez les mises à jour applicatives | pending security updates, metadata age, unattended upgrades, signatures, reboot debt, deleted libraries in memory, EOL release |
| 11 | Data encryption at rest | Chiffrez vos données et les données métier de vos applications | dm-crypt/LUKS behind data mounts, swap, LUKS2/argon2id, crash dumps, private keys, application data, user credentials |
| 12 | Crypto policy, FIDO & MFA | Instaurez des politiques crypto / FIDO / MFA par OTP | system crypto policy, TLS floor probed with OpenSSL, SSH algorithms, post-quantum KEX, SSH MFA (OTP, FIDO2), MFA for sudo, OTP seed protection, FIPS |

The full matrix, with every mapping, is in [docs/CONTROLS.md](docs/CONTROLS.md). `sdw-armor explain SA-06.17` shows the rationale, the effective probe, the mappings and the fix of any control.

## How it works

```text
            sdw-armor (static Go binary, no dependency)
 ┌───────────────────────────────────────────────────────────────┐
 │ embedded InSpec profile ── catalog.json (single source) ──┐   │
 │ embedded Chef cookbook                                    │   │
 └──────┬──────────────────────────────────┬─────────────────┼───┘
        │ scan                             │ harden          │ mappings, inputs,
        ▼                                  ▼                 │ remediations
 cinc-auditor exec ── local:// ssh:// docker://     cinc-client --local-mode
   (here, or on the target with --on-target)          (on the target)
        │                                  │
        ▼                                  ▼
 effective probes: sshd -T, /proc/sys +    declarative actions → native resources
 sysctl.d, systemctl, auditctl + rules.d,  (drop-ins, validated edits, backups)
 PAM, sudoers, mounts, lsblk, openssl...   → re-audit of the fixed controls
        │
        ▼
 qualified verdicts → A-E score → text · HTML · JSON · SARIF · JUnit · Markdown
```

- **Profile** (`profile/`): 162 controls in 12 files, effective-state resources in `libraries/`, and `files/catalog.json`, the single source of truth for metadata, mappings, inputs and remediations. It also runs standalone: `sdw-armor export profile ./p && cinc-auditor exec ./p`.
- **Cookbook** (`cookbook/shadow_armor/`): a small interpreter that turns the catalog's declarative remediations into native Chef resources.
- **CLI** (`internal/`): target transports (`sh`, the system `ssh` client, `docker exec`), engine driver, qualification, scoring, renderers, harden planning. Standard library only.

## Targets and modes

| Mode | Command | Engine runs | Needs |
|---|---|---|---|
| local | `sdw-armor scan` | here | cinc-auditor here, root or `--sudo` |
| remote | `sdw-armor scan ssh://host --sudo` | here, commands over SSH | cinc-auditor here; SSH access (your `~/.ssh/config` applies) |
| on-target | `sdw-armor scan ssh://host --sudo --on-target` | on the target | cinc-auditor on the target (`install-cinc ssh://host` or `--bootstrap-cinc` installs a verified package) |
| container | `sdw-armor scan docker://name` | here, via the Docker API | Docker access |
| Docker engine | `sdw-armor scan ssh://host --sudo --engine docker` | here, in the `cincproject/auditor` container | Docker only: nothing else to install (`ssh://` and `docker://` targets) |

Most probes need root (`/etc/shadow`, `sshd -T`, `auditctl`, `/proc/*/maps`). Without it they report **errors, which count as failures** (fail-closed), never silent passes. Non-interactive sudo is expected; `SDW_SUDO_PASSWORD` is read when sudo needs a password.

## Qualified verdicts and scoring

| Verdict | Meaning | Score |
|---|---|---|
| `pass` · durable | compliant now, and the persisted state keeps it after a reboot (or a real reboot proved it: *reboot-proven*) | counts as pass |
| `pass` · runtime-only | compliant now, but the persisted state would undo it, or nothing on disk proves it | counts as pass; an A that rests on it is capped at **B** |
| `fail` · pending | wrong now, already fixed on disk (reboot / reload pending) | counts as fail |
| `fail` | wrong | counts as fail |
| `error` | could not be evaluated (e.g. no root) | counts as **fail** |
| `n/a` | not applicable on this target | excluded |
| `waived` | accepted risk (InSpec waiver file) | excluded, listed |

`score = 100 × Σ weight(pass) / Σ weight(evaluated)` with weights critical 10, high 5, medium 3, low 1; A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, E below; a failing critical control caps the grade at D; an A that would not survive its runtime-only passes failing after a reboot is capped at B. Every verdict also says what it proves: *now ✓ · on disk ✓ · after reboot ✓ expected*. Details and rationale: [docs/SCORING.md](docs/SCORING.md).

## In CI

```yaml
- name: Audit the golden image
  run: |
    docker run -d --name candidate my-registry/app:${{ github.sha }} sleep infinity
    sdw-armor scan docker://candidate -o sarif:shadow-armor.sarif -o json:scan.json --fail-under C
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: shadow-armor.sarif
- name: No drift since the last release
  run: sdw-armor diff baseline.json scan.json --fail-on-regression
```

Exit codes: `0` ok, `1` policy not met (`--fail-under`, `--fail-on-regression`, harden left failures), `2` usage, `3` prerequisite missing (engine, reachability), `4` engine error.

## Tuning: inputs and waivers

Thresholds are inputs with documented defaults (`sdw-armor list --inputs`):

```sh
sdw-armor scan --input sdw_password_min_length=15 --input sdw_allowed_listening_ports='[22,443]'
sdw-armor scan --inputs examples/policy-pci-dss.json     # presets: policy-cis, policy-pci-dss, policy-disa-stig
```

The same values drive `harden`, so a fix always matches the threshold it was checked against.

Accepted risks go in a standard InSpec waiver file; expired waivers are evaluated again automatically:

```yaml
# waivers.yml
SA-02.19:
  justification: "Filtering enforced by the cloud security group sg-0abc (SEC-142)"
  expiration_date: 2027-06-30
  run: false
```

```sh
sdw-armor scan ssh://web01 --sudo --waivers waivers.yml
```

## Requirements

- Linux targets: Debian/Ubuntu and RHEL-family (RHEL, Rocky, Alma, Oracle, CentOS Stream, Fedora, Amazon Linux) are first-class; other distributions work with the probes that apply.
- Engine: CINC Auditor or Chef InSpec 5+ (tested with CINC Auditor 7.2 and InSpec 5.24). Harden: CINC Client 16+ on the target.
- Runs from Linux or macOS (static binaries for amd64 and arm64).
- Tested on Ubuntu 24.04, Debian 12 and Rocky Linux 9 with CINC Auditor 7.2.1 and CINC Client 19. Supported systems and common errors: [docs/INSTALL.md](docs/INSTALL.md).

## Security and privacy

No telemetry, no network calls besides your targets, omnitruck when you ask for a CINC package, and GitHub when you run `update` or `upgrade`. Reports are written with mode `0600`. The HTML report is offline, with a hash-based Content-Security-Policy, and renders scanned data as text only. Vulnerability reports: [SECURITY.md](SECURITY.md).

## Documentation

- [docs/INSTALL.md](docs/INSTALL.md): download, verify (checksums, provenance, SBOM), the CINC engine, supported systems, common errors
- [docs/CONTROLS.md](docs/CONTROLS.md): every control, what it proves and its mappings
- [docs/SCORING.md](docs/SCORING.md): evidence kinds, proof columns, reboot-proven verdicts and the A-E formula
- [docs/HARDENING.md](docs/HARDENING.md): harden workflow, guards, what each fix changes, how to revert
- [docs/CLI.md](docs/CLI.md): commands, flags, exit codes
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how the pieces fit, how to add a control
- [examples/](examples/): input presets per standard, a waiver file, a GitHub Actions workflow
- [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Apache License 2.0. Copyright © Shadow Security.

Shadow-Armor builds on [CINC](https://cinc.sh) (free distributions of Chef InSpec and Chef Infra). Standard names belong to their owners (CIS®, ANSSI, NIST, PCI SSC, DISA); mappings are guidance for evidence collection, not a certification.
