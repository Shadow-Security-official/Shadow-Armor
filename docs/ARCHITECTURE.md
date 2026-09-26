# Architecture

```text
cmd/sdw-armor/          main
embed.go                embeds profile/ and cookbook/ into the binary
internal/catalog        catalog.json types, selection (level, pillar, standard)
internal/target         local / ssh (system client) / docker transports, tar upload
internal/engine         cinc-auditor / inspec discovery, exec (local, on-target or in the Docker image), live progress, InSpec JSON
internal/verdict        evidence kinds (live, boot, config, inventory, files, transient) → proof columns → qualified verdict
internal/score          the A-E formula (Go twin of internal/report/assets/score.js)
internal/scan           orchestration: select, stage, run, qualify; boot identity and reboot baselines
internal/cinc           verified CINC installation: omnitruck metadata, SHA-256, dpkg/rpm
internal/selfupdate     update / upgrade: GitHub releases, SHA256SUMS, cosign or gh verification
internal/report         text, JSON, HTML (self-contained), SARIF, JUnit, Markdown
internal/harden         candidates, plans, safety guards, cinc-client run
internal/diff           report comparison
internal/cli            commands and flags
profile/                the InSpec profile (controls, libraries, files/catalog.json)
cookbook/shadow_armor/  the Chef cookbook interpreting declarative remediations
testdata/               scoring vectors shared by the Go and JavaScript tests
tools/sbom/             CycloneDX SBOM generator for releases (standard library only)
packaging/              nfpm configuration of the .deb and .rpm packages
```

## Design rules

1. **One source of truth.** `profile/files/catalog.json` holds each control's title, severity, level, scope, rationale, probe description, standard mappings, input defaults and remediation. The InSpec controls read it (`sdw_catalog.apply(self, id)` sets title, impact and tags), the CLI reads the same file from the embedded profile, and the cookbook receives the resolved remediation actions. Tests fail when a catalog entry has no control, a control has no catalog entry, a remediation kind is not implemented by the cookbook, or a placeholder names an unknown input.
2. **Effective state, and what it proves.** Resources in `profile/libraries` ask the running software for its resolved configuration and report *where* a value comes from. They follow a naming contract: `runtime*` properties describe the live state, `persistent*` properties the state the next boot applies. Every catalog control lists the kinds of state it reads (`"evidence"`: `config`, `inventory`, `filesystem`, `transient`, then `runtime`, `persistent`), the type of its unprefixed assertions first; `TestEvidenceMatchesControlCode` parses the control code and fails when the list and the assertions disagree. The verdict package turns those kinds into the proof columns (now, on disk, after a reboot) and the qualified verdict ([SCORING.md](SCORING.md)).
3. **Fail closed.** A probe that cannot run raises an error that counts as a failure. Nothing is silently skipped except what is genuinely not applicable (and says why).
4. **Nothing behind your back.** No agent, no daemon. On-target runs stage in a private temp dir and remove it. CINC is only installed on explicit request (`install-cinc`, `--bootstrap-cinc`, `--cinc-package`), from a package whose SHA-256 is checked before anything runs, never by piping a script into a shell. Reboots only happen with `harden --reboot`, after a confirmation.
5. **Zero third-party Go dependencies.** Standard library only: a smaller supply chain for a security tool, and a static binary.

## Adding a control

1. Add the entry to `profile/files/catalog.json`: next free id in its pillar (`SA-PP.NN`), `title`, `severity`, `level`, `scope` (`host` when it audits the kernel, boot chain or host daemons), `evidence` (the kinds of state the assertions read, see design rule 2), `rationale`, `check` (what the probe reads, precisely), `map` (only references you have verified), `remediation` (`auto` + declarative `actions`, or `manual` guidance).
2. Implement it in the pillar's control file:

   ```ruby
   control 'SA-06.21' do
     sdw_catalog.apply(self, 'SA-06.21')
     only_if(sshd_missing) { sshd.installed? }
     describe sshd.option('ExposeAuthInfo') do
       its('value') { should cmp 'no' }
     end
   end
   ```

   Prefer an existing effective resource (`sdw_sshd`, `sdw_sysctl`, `sdw_unit`, `sdw_auditd`, `sdw_pam`, `sdw_sudoers`, `sdw_kv`, `sdw_mount`...). When the state has a live side and a boot-time source, check both and name the properties `runtime*` / `persistent*` (`SdwState.new(label, runtime:, persistent:)` wraps two computed values): a live-only check makes every PASS runtime-only. Wrap shell snippets in `sdw_sh(...)` so `--sudo` covers pipes and globs. Put text parsing in `profile/libraries/01_sdw_parse.rb` (pure functions, no InSpec) and cover it in `profile/test/parse_test.rb`, with a captured output under `profile/test/fixtures/` when the format is not obvious.
3. If the fix is automatic and needs a new action kind, implement it in `cookbook/shadow_armor/recipes/default.rb` (native resources, validated edits, owned drop-in files) and describe it in `internal/harden/plan.go`.
4. Regenerate the matrix: `go run ./cmd/sdw-armor list --markdown > docs/CONTROLS.md`.
5. `make test`, then scan and harden a disposable VM or container of each supported family.
