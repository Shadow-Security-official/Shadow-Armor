# sdw-armor command line

```text
sdw-armor <command> [target] [flags]
```

Flags can appear before or after the target. `--no-color` is accepted by every command (also `NO_COLOR=1`). Run `sdw-armor <command> -h` for the authoritative list.

**Terminal output.** On a terminal, commands draw with the full width available: the banner in relief letters (a compact wordmark below 122 columns, one line below 70), live progress while scanning, converging or rebooting (a spinner, the current step, a progress line; the cursor is hidden and restored, Ctrl-C included), and result screens with boxes, gauges and bars. Colour depth follows the terminal: 24-bit when `COLORTERM=truecolor` (or a known truecolor terminal), 256 or 16 colours otherwise. Redirected to a file or a pipe, or with `--no-color`, the output is plain text without escape codes or animation, stable enough for logs; `scan --quiet` drops the progress messages.

## Targets

| Target | Meaning |
|---|---|
| *(none)*, `local` | this host |
| `ssh://[user@]host[:port]` | over SSH. The system `ssh` client is used for connectivity checks, `--on-target` and `harden`, so your `~/.ssh/config` (aliases, `ProxyJump`, `IdentityFile`, agents, `ControlMaster`) applies; in remote engine mode the engine's own SSH transport reads `~/.ssh/config` too. `-i key` adds an identity. |
| `docker://<container>` | a running container (`docker exec`, or the engine's Docker transport) |

## scan

Audit a target and grade it.

| Flag | Default | |
|---|---|---|
| `--sudo` | off | run privileged probes through `sudo -n` (`SDW_SUDO_PASSWORD` if sudo needs a password) |
| `--on-target` | off | run the engine on the target (uploads the profile to a private temp dir, removes it after) |
| `--bootstrap-cinc` | off | with `--on-target`, install cinc-auditor when it is missing: package resolved on omnitruck, downloaded here, SHA-256 verified, installed with dpkg/rpm |
| `--cinc-version` | latest | version for `--bootstrap-cinc` |
| `--cinc-package FILE` | | install CINC on the target from this `.deb`/`.rpm` when missing (air-gapped; repeatable) |
| `--reboot-baseline REPORT.json` | | a report of the same machine from before its last reboot: passes seen in both are **reboot-proven**, passes since lost are flagged |
| `--engine MODE` | auto | `auto` (native `cinc-auditor`/`inspec`, else the Docker image if already present), `native`, `docker` (CINC Auditor from its container image, pulled if needed; `ssh://` and `docker://` targets), or the path of a native engine (also `$SDW_ARMOR_ENGINE`) |
| `--engine-image IMAGE` | `docker.io/cincproject/auditor:7.2.1` | image of `--engine docker`; also `$SDW_ARMOR_ENGINE_IMAGE` (a digest reference pins it) |
| `--level 1\|2` | 1 | baseline, or baseline + hardened |
| `--pillar LIST` | all | pillar numbers or keys: `6,12` or `ssh,crypto-mfa` |
| `--standard KEY` | all | only controls mapped to `cis`, `anssi`, `nist`, `nist171`, `pci` or `stig` |
| `--lens KEY` | `--standard` | grade through one standard |
| `--controls IDS`, `--exclude IDS` | | explicit selection |
| `--input name=value` | | override an input (JSON values accepted: `--input sdw_allowed_listening_ports='[22,443]'`) |
| `--inputs FILE.json` | | input overrides from a JSON object |
| `--waivers FILE.yml` | | InSpec waiver file |
| `-o FORMAT:PATH` | | write a report; repeatable. Formats: `text`, `json`, `html`, `sarif`, `junit`, `markdown` (aliases `md`, `xml`, `txt`). `-o report.html` infers the format from the extension |
| `--format FORMAT\|none` | text | what goes to stdout |
| `--fail-under GRADE` | | exit 1 when the grade is worse |
| `--verbose` | off | list passes and non-applicable controls, stream engine messages |
| `--quiet` | off | no progress |
| `--timeout` | 45m | |

## harden

Everything `scan` accepts, plus:

| Flag | |
|---|---|
| `--from REPORT.json` | reuse a saved scan instead of auditing first |
| `--rules IDS` | only these controls |
| `--fix-pillar LIST` | only candidates of these pillars |
| `--all` | every candidate |
| `--yes` | no prompt (required when stdin is not a terminal) |
| `--dry-run` | Chef why-run: show, change nothing |
| `--plan-out FILE` | save the plan and stop |
| `--plan FILE` | apply exactly this plan |
| `--force` | also apply the rules a safety guard stopped (you have another way in) |
| `--no-verify` | skip the re-audit |
| `--bootstrap-cinc` | install cinc-client on the target when missing (verified package, see `install-cinc`) |
| `--reboot` | after applying and re-auditing, reboot the `ssh://` target (asks first unless `--yes`), wait for the new boot ID and re-scan: reboot-proven fixes, pending fixes confirmed, passes lost at the reboot |
| `--reboot-timeout` | how long to wait for the target to come back (default 15m) |
| `-o FORMAT:PATH` | write the post-harden report (base report with the re-audited controls merged; with `--reboot`, the post-reboot scan) |

## install-cinc

Install CINC Auditor (the scan engine) or CINC Client (what `harden` needs), explicitly, from a SHA-256 verified package. Never an installer script; the target needs no Internet access.

```sh
sdw-armor install-cinc --sudo                          # CINC Auditor on this machine
sdw-armor install-cinc ssh://web01 --sudo --both       # CINC Auditor and CINC Client on a target
sdw-armor install-cinc docker://app --client --version 18
sdw-armor install-cinc ssh://web01 --sudo --package cinc-auditor_7.2.1-1_amd64.deb
sdw-armor install-cinc --print                         # the same steps as shell commands; changes nothing
```

| Flag | |
|---|---|
| `--client`, `--both` | CINC Client instead of, or in addition to, CINC Auditor |
| `--version` | version or major (default: latest stable) |
| `--package FILE` | install this `.deb`/`.rpm` instead of downloading (repeatable) |
| `--print` | print the commands for the detected platform and stop |
| `--yes` | do not ask (required without a terminal) |
| `--sudo`, `-i` | as for `scan` |

`SDW_ARMOR_OMNITRUCK` points it at a mirror of the omnitruck API. Already-installed tools are left alone.

## explain, list

```sh
sdw-armor explain SA-06.01 [--json] [--fr]
sdw-armor list [--level 2] [--pillar ssh] [--standard pci] [--auto] [--json] [--fr]
sdw-armor list --pillars | --standards | --inputs | --markdown
```

## report, diff

```sh
sdw-armor report scan.json --lens pci -o html:pci.html --format none
sdw-armor diff before.json after.json [--json|--markdown] [--lens anssi] [--fail-on-regression]
```

`diff` reports **fixed**, **regressed**, **new failures**, **drifted** (same status, different qualifier: e.g. durable → runtime-only) and controls no longer audited. When the two reports are the same machine across a reboot (different boot ID), it says so, counts the passes that survived it and names regressions **lost at the reboot**.

## doctor, export, version

```sh
sdw-armor doctor [target] [--sudo]         # engine here, reachability, sudo, engine/client on the target, init, container
sdw-armor export profile ./shadow-armor     # the InSpec profile, runnable with plain cinc-auditor
sdw-armor export cookbook ./shadow_armor    # the Chef cookbook, for review
sdw-armor version
```

## update, upgrade

```sh
sdw-armor update                            # is a newer release published? installs nothing
sudo sdw-armor upgrade                      # download, verify and install the latest release
sudo sdw-armor upgrade --version v0.3.1     # a given release (going back included)
sudo sdw-armor upgrade --strict             # refuse unless cosign or gh verified who built it
```

`update` reads the latest release of the GitHub repository (exit `0` up to date, `1` a newer release exists, `3` GitHub unreachable). `upgrade` downloads the file for this platform and refuses it unless its SHA-256 matches the release's `SHA256SUMS`. When [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) is installed it also verifies the Sigstore signature of `SHA256SUMS` (identity: this project's release workflow); otherwise a logged-in GitHub CLI 2.49+ verifies the build provenance of the file; with neither, it says so, and `--strict` stops there. A downloaded binary must run and report the expected version before it replaces the running one, with an atomic rename in its directory. When the binary belongs to the `.deb` or `.rpm` package, the package of the release is installed with `dpkg -i` or `rpm -U` instead. It needs write access to the binary's directory (`sudo` for `/usr/local/bin` or a package).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | policy not met: `--fail-under`, `--fail-on-regression`, or `harden` left controls not durably compliant |
| 2 | usage error (unknown flag, control, input, malformed target...) |
| 3 | prerequisite missing: no engine, engine or CINC Client missing on the target, target unreachable, not root |
| 4 | engine or Chef run failure |

## Environment

| Variable | |
|---|---|
| `SDW_ARMOR_ENGINE` | engine path |
| `SDW_ARMOR_ENGINE_IMAGE` | image of the Docker engine |
| `SDW_ARMOR_OMNITRUCK` | base URL of an omnitruck mirror for `install-cinc` / `--bootstrap-cinc` (default `https://omnitruck.cinc.sh`) |
| `SDW_ARMOR_RELEASES` | releases API for `update` / `upgrade` (default `https://api.github.com/repos/Shadow-Security-official/Shadow-Armor`): a mirror answering the same `releases/latest` and `releases/tags/<tag>` requests |
| `GITHUB_TOKEN` | sent to the GitHub API by `update` / `upgrade` when set (higher rate limit) |
| `SDW_SUDO_PASSWORD` | sudo password when non-interactive sudo is not configured (never put it on the command line) |
| `NO_COLOR`, `FORCE_COLOR` | colour control |
| `COLORTERM` | `truecolor` enables 24-bit gradients; otherwise the depth is read from `TERM` |
