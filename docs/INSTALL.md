# Install Shadow-Armor

Two things run a scan: the `sdw-armor` binary, and the scan engine it drives, [CINC Auditor](https://cinc.sh/start/auditor/) (the free build of Chef InSpec). This page covers both, how to verify what you download, the supported systems and the common errors. Already installed? Run `sdw-armor doctor`, then `sdw-armor scan`.

Nothing on this page, and nothing Shadow-Armor does, pipes a downloaded script into a shell. A hardening tool whose first instruction is `curl | sh` has already lost the argument.

## Prerequisites

- **Control host**: Linux or macOS, amd64 or arm64. Shadow-Armor scans the local host, an SSH host or a Docker container from there; no agent on the target.
- **curl** and **sha256sum** (`shasum -a 256` on macOS): that is the whole list for the binary. No Go, no Ruby, no Python: the InSpec profile and the Chef cookbook are embedded in it.
- **CINC Auditor**, the engine: in no distribution repository, so no package manager pulls it and the Shadow-Armor packages cannot declare it as a dependency. `sdw-armor install-cinc` installs it from a SHA-256 verified package (below).
- **root or sudo** on the audited system: effective configuration needs it (`sshd -T`, `auditctl -l`, `/etc/shadow`). Scan with `--sudo`; without it those probes report errors, which count as failures.
- **SSH**: for a remote target, Shadow-Armor uses your `ssh` client, so your `~/.ssh/config`, keys, agent and `ProxyJump` apply.

## 1. Download the binary

Every release publishes one static binary per platform, `.deb` and `.rpm` packages, a CycloneDX SBOM, and a `SHA256SUMS` file signed with Sigstore.

The install page, [armor.shadow-security.fr](https://armor.shadow-security.fr), writes the command below for your system, architecture and version, with the checksum verification (and optionally the Sigstore signature) built in.

```sh
VERSION=v0.4.0     # https://github.com/Shadow-Security-official/Shadow-Armor/releases
ARCH=amd64         # or arm64
BASE=https://github.com/Shadow-Security-official/Shadow-Armor/releases/download/$VERSION
curl -fsSLO "$BASE/sdw-armor-linux-$ARCH"
curl -fsSLO "$BASE/SHA256SUMS"
```

or the package for your distribution:

```sh
curl -fsSLO "$BASE/sdw-armor_${VERSION#v}-1_$ARCH.deb"        # Debian, Ubuntu
curl -fsSLO "$BASE/sdw-armor-${VERSION#v}-1.x86_64.rpm"        # RHEL, Rocky, Alma, Fedora (aarch64 for arm64)
```

## 2. Verify it

**Integrity.** The file is the one the release published:

```sh
sha256sum --ignore-missing --check SHA256SUMS      # macOS: shasum -a 256 --ignore-missing -c SHA256SUMS
```

**Provenance.** A checksum does not say who built the file: someone who replaces both the binary and `SHA256SUMS` produces a consistent pair. The SLSA build provenance answers *who built it*: this exact file came out of this repository's release workflow, on that tag. It needs the [GitHub CLI](https://cli.github.com/) 2.49 or newer (`gh attestation`; Debian 13 ships 2.46: install it from GitHub's own package repository, or use the signed checksums below) and no access to the repository; a binary obtained from a mirror verifies just as well.

```sh
gh attestation verify "sdw-armor-linux-$ARCH" --repo Shadow-Security-official/Shadow-Armor
```

**Signed checksums** (optional, with [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)): `SHA256SUMS` is signed keylessly by the release workflow.

```sh
curl -fsSLO "$BASE/SHA256SUMS.sigstore.json"
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/Shadow-Security-official/Shadow-Armor/\.github/workflows/release\.yml@refs/(tags/v|heads/main)'
```

**SBOM.** `sdw-armor.cdx.json` (CycloneDX 1.6) lists what the binary contains: the Go standard library it was compiled with (no third-party Go module), and the embedded InSpec profile and Chef cookbook with a hash of their file trees. It is attested against the binaries and packages:

```sh
gh attestation verify "sdw-armor-linux-$ARCH" --repo Shadow-Security-official/Shadow-Armor \
  --predicate-type https://cyclonedx.org/bom
```

## 3. Install it

```sh
sudo install -m 0755 "sdw-armor-linux-$ARCH" /usr/local/bin/sdw-armor
# or: sudo dpkg -i sdw-armor_*.deb    /    sudo rpm -i sdw-armor-*.rpm   (installs /usr/bin/sdw-armor)
sdw-armor version
```

Later versions: `sdw-armor update` says whether a newer release exists, `sudo sdw-armor upgrade` installs it. The new file is checked against the release's `SHA256SUMS` (and its Sigstore signature when cosign is installed) before it replaces the old one; a package install is upgraded with `dpkg`/`rpm`. Details: [CLI.md](CLI.md#update-upgrade).

## 4. The scan engine: CINC Auditor

Shadow-Armor runs its controls with CINC Auditor (Chef InSpec 5 or newer works too). Where it must be installed depends on the mode:

| Mode | Command | CINC Auditor needed |
|---|---|---|
| local | `sdw-armor scan --sudo` | on this machine |
| remote over SSH | `sdw-armor scan ssh://web01 --sudo` | on this machine |
| container | `sdw-armor scan docker://app` | on this machine |
| on the target | `sdw-armor scan ssh://web01 --sudo --on-target` | on the target (about twice as fast) |

| any of the remote ones, with Docker | `sdw-armor scan ssh://web01 --sudo --engine docker` | nowhere: it runs from its container image |

`sdw-armor harden` also needs CINC Client on the target.

### No install at all: the Docker engine

With Docker on the machine running sdw-armor, `--engine docker` runs CINC Auditor from its official image (`docker.io/cincproject/auditor:7.2.1`, the version Shadow-Armor is tested with) in a throwaway container. It is the zero-install option for `ssh://` and `docker://` targets:

```sh
sdw-armor scan ssh://web01 --sudo --engine docker        # pulls the image the first time
sdw-armor scan docker://app --engine docker
sdw-armor scan ssh://web01 --sudo --engine docker --engine-image cincproject/auditor@sha256:<digest>   # pin it
```

- The image is pulled only when you ask for `--engine docker`. The default `--engine auto` uses the native engine, and falls back to the image only when it is **already present** locally.
- For `ssh://` targets, sdw-armor resolves the connection with your own client (`ssh -G`: aliases, user, port, keys, first `ProxyJump` hop) and hands the result to the engine; your keys are mounted read-only at their own path and your ssh-agent socket is shared. On Linux the container uses the host network.
- For `docker://` targets, the Docker API socket is mounted into the engine container, which gives it the same power over Docker as the `docker` command you run.
- The report records the image digest that ran (`engine.image`).
- A container cannot audit the machine it runs on: for `local` scans use the native engine.

### With sdw-armor (recommended)

```sh
sdw-armor install-cinc --sudo                       # CINC Auditor on this machine
sdw-armor install-cinc ssh://web01 --sudo --both    # CINC Auditor and CINC Client on a target
```

It asks before installing and shows what it will install. The steps are the ones you would type:

1. read the target's platform (`/etc/os-release`, `uname -m`);
2. ask the CINC omnitruck metadata endpoint which package fits it, and its published SHA-256;
3. download the package **on the machine running sdw-armor**, and refuse it unless the SHA-256 matches;
4. stream it to a private temporary directory on the target, check the SHA-256 again there;
5. install it with the system package tool (`dpkg -i` or `rpm -U`), and remove the temporary copy.

The target never needs Internet access. `--version 18` pins a major version. `--package cinc-auditor_7.2.1-1_amd64.deb` installs a package you bring yourself (air-gapped sites, internal mirrors, a vetted artifact); `SDW_ARMOR_OMNITRUCK=https://mirror.example` points it at a mirror of the omnitruck API.

The checksum proves the package is the one omnitruck published; it does not prove who built it. If your policy requires more, vet the package yourself and pass it with `--package`.

### By hand

`sdw-armor install-cinc --print` prints the exact commands for the detected platform, for example on Rocky Linux 9:

```sh
META=$(curl -fsS 'https://omnitruck.cinc.sh/stable/cinc-auditor/metadata?m=x86_64&p=el&pv=9')
URL=$(printf '%s\n' "$META" | awk '$1=="url"{print $2}')
SUM=$(printf '%s\n' "$META" | awk '$1=="sha256"{print $2}')
PKG=${URL##*/}
curl -fsSLO "$URL"
echo "$SUM  $PKG" | sha256sum --check   # integrity, before anything runs
sudo rpm -U "$PKG"                      # Debian/Ubuntu: sudo dpkg -i "$PKG"
cinc-auditor version
```

Omnitruck platform keys: `p=ubuntu&pv=22.04|24.04`, `p=debian&pv=12|13`, `p=el&pv=8|9|10` (RHEL, Rocky, AlmaLinux, CentOS, Oracle Linux), `p=amazon&pv=2|2023`, `p=sles&pv=15`; `m=x86_64` or `m=aarch64`.

On macOS, download CINC Auditor from [cinc.sh](https://cinc.sh/start/auditor/) and check it against the `.sha256` published next to it before opening the installer. The engine only needs to be on the Mac to audit `ssh://` and `docker://` targets.

### During a scan or a harden run

`--on-target` never installs anything by itself: when the engine is missing on the target, sdw-armor says so and stops. Pass `--bootstrap-cinc` to let that run install it with the same verified procedure (CINC Auditor for `--on-target`, CINC Client for `harden`), or `--cinc-package FILE` to use your own package.

## 5. Check everything

```sh
sdw-armor doctor                         # this machine: engine, privileges
sdw-armor doctor ssh://web01 --sudo      # and a target: reachability, sudo, engine/client, OS, init, container
```

`doctor` prints the fix of every gap it finds.

## Supported systems

The control host runs Linux or macOS (amd64, arm64). Audited targets:

| Family | Releases | Notes |
|---|---|---|
| Ubuntu | 22.04, 24.04 | validated on 24.04: local, `ssh://` (remote and on-target), `docker://`, `harden` (including `--reboot`) |
| Debian | 12, 13 | validated on 12: `docker://`, on-target, `harden` |
| RHEL family | RHEL, Rocky, AlmaLinux, Oracle Linux, CentOS Stream 8, 9, 10 | scan validated on Rocky 9 (`docker://`); `harden` recipes exist but have not been validated on this family yet |
| Fedora, Amazon Linux | current releases | probes and remediations handle dnf/rpm; not validated in CI |

One profile covers every system: controls adapt to the platform at run time (apt or dnf, AppArmor or SELinux, `grubby` or `grub.cfg`...) instead of shipping one profile per release. Inside a container, host-level controls (kernel, boot chain, firewall, audit subsystem) are reported *not applicable*.

## Common errors

- **`no CINC Auditor (cinc-auditor) or InSpec (inspec) found`**: the engine is not installed on this machine. This is the most common case after installing the package, and it is not a missing dependency of the package: the binary is static. Run `sdw-armor install-cinc --sudo`, scan with `--on-target`, or use `--engine docker` for remote targets.
- **`the Docker engine cannot audit this machine`**: `--engine docker` only audits `ssh://` and `docker://` targets; a local audit needs the native engine.
- **`cinc-auditor is not installed on the target`** (with `--on-target`): install it with `sdw-armor install-cinc ssh://host --sudo`, or add `--bootstrap-cinc`.
- **`sudo: a password is required`** / probes in error: the audit account needs non-interactive sudo (`NOPASSWD`), or export `SDW_SUDO_PASSWORD`. Without root, probes report errors that count as failures, never silent passes.
- **`sorry, you must have a tty to run sudo`** (`Defaults requiretty`, old RHEL defaults): sdw-armor never allocates a terminal for sudo, in any mode; exempt the audit account with `Defaults:audit !requiretty` in a sudoers drop-in.
- **`cannot reach ssh://...`**: sdw-armor uses your system `ssh` with `BatchMode=yes`; check `ssh -o BatchMode=yes host true` works (key or agent, `~/.ssh/config`, `ProxyJump`).
- **Many controls in error inside a minimal container**: some probes need tools that minimal images drop (`ss`, `lsblk`, `sshd`...); the report says which one, and those controls stay fail-closed.
- **`--reboot-baseline: no reboot happened between the two scans`**: the baseline and the scan share a boot ID. A container restart is not a reboot: containers share the host kernel.

## Build from source (contributors)

Not how the tool is meant to be installed. You need Go (version in `go.mod`); Node.js is optional (scoring parity test).

```sh
git clone https://github.com/Shadow-Security-official/Shadow-Armor.git && cd Shadow-Armor
make test          # vet + unit tests
make build         # dist/sdw-armor
make dist VERSION=v0.3.0-dev   # every platform, .deb/.rpm (nfpm), SBOM, SHA256SUMS
./dist/sdw-armor doctor
```

The repository holds the source of truth only; nothing needs regenerating before a build.
