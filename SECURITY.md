# Security policy

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's **private vulnerability reporting** (Security → Report a vulnerability) on this repository. Include the version (`sdw-armor version`), the command line and a reproduction. We will acknowledge the report and coordinate the fix and its disclosure with you.

In scope: the `sdw-armor` binary, the embedded InSpec profile and Chef cookbook, the HTML report, the release pipeline. Out of scope: vulnerabilities of CINC/InSpec/Chef themselves (report them upstream), findings that require an already-root attacker on the scanning machine.

## What Shadow-Armor does on your systems

- **scan** runs read-only commands on the target (through `cinc-auditor`). It never refreshes package metadata, never installs, never changes configuration. With `--on-target` it uploads the profile to a private (`0700`) temporary directory and removes it afterwards. With `--engine docker` the engine runs in a throwaway container of the `cincproject/auditor` image (pulled only on that explicit request, digest recorded in the report); for `docker://` targets it gets the Docker API socket, for `ssh://` targets your key files read-only and your ssh-agent socket.
- **harden** changes the target only for the controls you selected, with CINC Client in local mode. It prefers drop-in files it owns, validates `sshd` and `sudoers` changes before writing them, backs up every edited file under `/var/lib/shadow-armor/backup`, and writes a journal of each run under `/var/lib/shadow-armor/journal`.
- **CINC installation** happens only when you ask for it (`sdw-armor install-cinc`, `--bootstrap-cinc`, `--cinc-package`), and never by piping a script into a shell: sdw-armor asks the omnitruck metadata endpoint (`https://omnitruck.cinc.sh`) for the package matching the target's platform and its published SHA-256, downloads the package on the machine running sdw-armor, refuses it unless the SHA-256 matches, streams it to a private temporary directory on the target, checks the SHA-256 again there, and installs it with `dpkg -i` or `rpm -U`. The target needs no Internet access. The checksum proves the package is the one omnitruck published, not who built it: if your policy requires more, bring your own vetted package with `--cinc-package`.
- **upgrade** replaces the running binary only with a release file whose SHA-256 matches the release's `SHA256SUMS`, and verifies the Sigstore signature of `SHA256SUMS` when cosign is installed (or the build provenance with a logged-in GitHub CLI); `--strict` refuses to install without that signature check. The new binary must run before it replaces the old one (atomic rename); package installs are upgraded with `dpkg`/`rpm`. `update` only reads the release list.
- No telemetry. Nothing leaves your machines except what you send yourself; sdw-armor contacts GitHub only when you run `update` or `upgrade`.

## Reports

Reports describe weaknesses: they are written with mode `0600`. The HTML report is self-contained (no external resource), uses a hash-based Content-Security-Policy, and inserts every value coming from the scanned host as text, never as HTML.

## Verifying a release

Each release publishes static binaries, a `SHA256SUMS` file signed keylessly with Sigstore by the release workflow (`SHA256SUMS.sigstore.json`), and SLSA build provenance attestations:

```sh
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/Shadow-Security-official/Shadow-Armor/\.github/workflows/release\.yml@refs/(tags/v|heads/main)'
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify sdw-armor-linux-amd64 --repo Shadow-Security-official/Shadow-Armor
```

The binary is built with `CGO_ENABLED=0 -trimpath` from the tagged commit and has no third-party Go dependency.
