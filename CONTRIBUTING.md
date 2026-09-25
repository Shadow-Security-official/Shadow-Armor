# Contributing to Shadow-Armor

Thanks for helping! Issues and pull requests are welcome, in English or French.

## Development setup

- Go (version in `go.mod`), and optionally Node.js (the scoring parity test runs `score.js` when `node` is available).
- CINC Auditor to run the profile (`https://cinc.sh/start/auditor/`), CINC Client to exercise `harden`.
- Docker to test against disposable targets.

```sh
make test        # go vet + unit tests (catalog/profile/cookbook consistency, verdicts, Go/JS scoring parity, reports)
make lint        # golangci-lint
make build       # static binary in ./dist
make dist VERSION=v0.3.0-dev   # all platforms, .deb/.rpm packages, SBOM, SHA256SUMS
make check       # cinc-auditor check profile
./dist/sdw-armor scan docker://my-test-container --level 2
```

## Ground rules

- **Mappings must be verifiable.** Only add a CIS, ANSSI, NIST, PCI DSS or STIG reference you have checked against the source document; say which version in the pull request. A wrong mapping is worse than a missing one.
- **Effective state first.** Ask the software for its resolved configuration (`sshd -T`, `/proc/sys`, `systemctl`, `auditctl`...) and report where a value comes from. Parse files only when there is no better source, and then resolve them the way the consumer does (includes, drop-ins, precedence).
- **Runtime and persistence.** When a setting has both, check both, with `runtime*` / `persistent*` property names, and list the kinds of state the control reads in its catalog `evidence` (a test compares it with the code).
- **Fail closed, skip honestly.** Errors count as failures; `only_if` skips must say why.
- **Safe remediations.** Validate before writing, prefer owned drop-in files, never lock the operator out (add a guard when needed), and keep a fix manual when it cannot be made safe unattended.
- **No new Go dependency** without a strong reason.
- Regenerate `docs/CONTROLS.md` (`go run ./cmd/sdw-armor list --markdown > docs/CONTROLS.md`) when the catalog changes; CI checks it.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how to add a control.

## Commits and pull requests

Small, focused pull requests with a clear description of what was tested (distributions, engine version). By contributing you agree that your contribution is licensed under the Apache License 2.0.
