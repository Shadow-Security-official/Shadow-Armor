# shadow-armor InSpec profile

The audit profile embedded in `sdw-armor`. It runs standalone too:

```sh
sdw-armor export profile ./shadow-armor
cinc-auditor exec ./shadow-armor -t ssh://admin@web01 --sudo --reporter cli json:scan.json
cinc-auditor exec ./shadow-armor --input sdw_password_min_length=15 --controls /SA-06/
```

- `controls/`: 197 controls in 15 files, one per hardening pillar.
- `libraries/`: effective-state resources (`sdw_sshd`, `sdw_sysctl`, `sdw_unit`, `sdw_auditd`, `sdw_pam`, `sdw_sudoers`, `sdw_kv`, `sdw_mount`, `sdw_block`, `sdw_crypto`, `sdw_mfa`, `sdw_web`, `sdw_tls_endpoints`, `sdw_databases`, `sdw_hardware`...). Properties named `runtime*` read the live state, `persistent*` the state after reboot. Text parsing lives in `01_sdw_parse.rb` (pure Ruby, no InSpec), tested by `ruby profile/test/parse_test.rb` against captured outputs in `test/fixtures/`.
- `files/catalog.json`: the single source of truth for titles, severities, standard mappings (exposed as tags: `nist`, `nist_800_171`, `cis_controls_v8`, `cis_benchmark`, `anssi_bp028`, `pci_dss_v4`, `stig_srg`, `pillar`, `level`), input defaults and remediations. Titles and descriptions are applied from it when the profile loads, so `cinc-auditor check` warns that controls have "no title": that is expected.

The raw JSON output of `cinc-auditor exec` carries the `nist` tags Heimdall understands. Use `sdw-armor scan` for qualified verdicts, the A-E grade and the other report formats.
