# Qualified verdicts and the A-E grade

Shadow-Armor publishes exactly how a host is graded. The formula below is implemented twice, in Go for the CLI (`internal/score/score.go`) and in JavaScript for the HTML report (`internal/report/assets/score.js`); `TestParityWithJavaScript` runs both on the same vectors (`testdata/score-vectors.json`) so the grade in your terminal is the grade in your browser.

Most scanners answer a control with one bit, pass or fail. That bit hides the question that matters on a running system: **what does this PASS prove, and will it still be true after a reboot?** Shadow-Armor answers it for every control, then lets the answer weigh on the grade. The idea of qualifying a verdict comes from [Pavois](https://pavois.dev/en/handbook/qualified-verdict/).

## 1. Evidence: what each assertion reads

Every assertion of the profile reads one kind of state:

| Kind | How it is recognised | What it reads |
|---|---|---|
| `runtime` (live) | property `runtime*`, or a control declared live-only | the running system: live sysctl in `/proc/sys`, unit active, rule loaded with `auditctl -l`, mount options in `/proc/self/mounts`, running kernel, listening sockets |
| `persistent` (boot) | property `persistent*` | what the next boot applies: sysctl.d resolved like systemd-sysctl, unit enabled, `/etc/audit/rules.d` in augenrules order, fstab or `.mount` unit, boot loader command line, `modprobe --showconfig`, newest installed kernel |
| `config` (resolved config) | declared by the control | configuration as its consumer resolves it: `sshd -T`, PAM stacks with every include, sudoers with every `#includedir`, `login.defs`, `systemd-analyze cat-config`, `ssh -G` |
| `inventory` | declared | installed or absent software, hardware and OS facts, storage layout (dpkg/rpm, CPU NX, LUKS headers, release support) |
| `filesystem` (files) | declared | files on disk: modes, owners, content, account databases |
| `transient` | declared | live state a reboot can only clear (processes still mapping deleted libraries) |

Each control lists the kinds it reads in `catalog.json` (`"evidence"`, shown as the **Proves** column of [CONTROLS.md](CONTROLS.md) and by `sdw-armor explain`). A unit test parses every control's code and fails when the declaration and the assertions disagree, so the proof columns below cannot silently drift from what the check really does.

## 2. What a verdict proves: three columns

From the assertions that ran, every verdict gets three proof columns (`proof` in the JSON, the *What this verdict proves* box of the HTML report, `--verbose` in the terminal):

| Column | Filled by | Values |
|---|---|---|
| **running now** | runtime, config, inventory, filesystem, transient assertions | proven · failed · not measured |
| **on disk** | persistent, config, inventory, filesystem assertions | proven · failed · not measured |
| **after a reboot** | derived | **proven** (observed across a real reboot, see §4) · **expected** (the persisted state is compliant) · **would be undone** (the persisted state is not) · **lost** (passed before the last reboot, fails since) · not measured · n/a (transient state) |

A sysctl checked only in `/proc/sys` would prove *running now* and leave *after a reboot* unknown; Shadow-Armor checks the live value **and** the value the boot will apply, so the same control proves all three. The same folding is done for every state that has a clean persistent source:

- **sysctl**: live value and the systemd-sysctl resolution of every `sysctl.d` directory, with the file and line that set it;
- **services**: `is-active` and `is-enabled` (a service's live state is paired with its boot state);
- **kernel modules**: loaded now, and blocked by the resolved `modprobe.d` configuration;
- **mounts**: live options and the fstab entry or `.mount` unit;
- **kernel command line**: `/proc/cmdline` and the boot loader configuration (grubby/BLS, `grub.cfg`, `/etc/default/grub`);
- **audit rules**: loaded (`auditctl -l`) and in `rules.d`, including the final `-e 2`;
- **firewall**: default-deny in the live ruleset and the firewall enabled at boot;
- **MAC**: enforcing now and configured to enforce at boot;
- **kernel lockdown**: the live mode and the mode of the next boot (`lockdown=`, a kernel forced to lock down, or Secure Boot with a kernel that locks down under it);
- **swap encryption**: active swap areas and the swap `/etc/fstab` activates at boot (crypttab, zram);
- **kernel updates**: the running kernel and the newest installed one.

A handful of controls remain honestly live-only: the listening sockets (nothing on disk says which ports the next boot opens), what local TLS endpoints negotiate and present to a client, and the options and owner of running database processes. Their PASS is qualified *runtime-only* until a scan after a reboot proves it.

## 3. The qualified verdict

| Verdict | Rule |
|---|---|
| `waived` | an active waiver covers it (expired waivers are evaluated normally) |
| `error` | at least one assertion could not be evaluated (exception, missing privilege) |
| `n/a` (skip) | nothing applies to this target (`only_if`, container scope, feature absent) |
| `fail` · **pending** | only live values are wrong, the persisted state was checked and is compliant, and the live values exist: a reboot or reload will fix it |
| `fail` | any other failure (including a failing boot-only check) |
| `pass` · **runtime-only** | compliant now, but the persisted state contradicts it (*would be undone*) or nothing on disk proves it (*not measured*) |
| `pass` · **durable** | compliant now, and the persisted state keeps it after a reboot, or a real reboot proved it |

Example: `kernel.randomize_va_space` is 2 in `/proc/sys`, but no sysctl file sets it. The kernel default happens to be right today; nothing proves it will be tomorrow (a vendor file, an image rebuild, a tuning script). The control is **pass · runtime-only**: *now ✓ · on disk ✗ · after reboot ✗ would be undone*, and the evidence says `boot value: not persisted`.

Example: a kernel update is installed but the host has not rebooted. The newest installed kernel (boot) is fine, the running one (live) is not: **fail · pending (reboot)**.

## 4. Reboot-proven: the empirical proof

Reading the boot configuration proves what the next boot *should* do. A real reboot proves what it *does*. Every report records the boot identity of the target (`/proc/sys/kernel/random/boot_id`, the uptime, and a hash of `/etc/machine-id`: the raw machine ID is confidential and never stored), so two reports of the same machine taken across a reboot can be compared:

```sh
sdw-armor scan ssh://web01 --sudo -o json:before.json
# ... reboot web01 ...
sdw-armor scan ssh://web01 --sudo --reboot-baseline before.json
```

- a control that passed before the reboot and passes after it is **reboot-proven**: its *after a reboot* column becomes *proven*, and a runtime-only pass becomes durable (the empirical proof beats the inference, and the reason says so when the persisted state read on disk disagreed);
- a control that passed before and fails after it is **lost at the reboot**: a fix that was never persisted;
- the baseline must come from the same machine (same machine-ID hash), from an earlier boot (different boot ID) and be older than the scan; anything else is refused.

`sdw-armor harden --reboot` does it end to end on an `ssh://` target: apply, re-audit, reboot, wait for the new boot ID, wait for the boot to settle, re-scan everything against the pre-reboot state. `sdw-armor diff` recognises two reports taken across a reboot and names regressions *lost at the reboot*.

## 5. The score

```text
weight(severity)   critical 10 · high 5 · medium 3 · low 1 · info 0
evaluated          controls whose status is pass, fail or error
score              100 × Σ weight(pass) / Σ weight(evaluated), rounded to 1 decimal
```

- **Errors count as failures** (fail-closed): a scan without enough privilege cannot look better than one with it.
- **Not-applicable and waived controls are left out**, but waived controls are always listed with their justification and expiry.
- Runtime-only passes count as passes in the points: the score stays failure-driven. They weigh on the letter instead (next section).

## 6. The grade

```text
raw grade   A ≥ 90 · B ≥ 80 · C ≥ 65 · D ≥ 50 · E below
caps        any critical control failing or in error      → at most D
            an A that rests on runtime-only passes        → B
grade       the worse of the raw grade and every cap
            nothing evaluated                             → N/A
```

**Critical cap.** A single critical failure (an extra UID 0 account, an empty password, a world-readable `/etc/shadow`, a writable sudoers file, SSH accepting empty passwords) is an open door whatever the rest of the configuration.

**Runtime cap.** An A must mean *and it will still be true after the next reboot*. The A **rests on** runtime-only passes when it would not stay an A if every one of them failed after a reboot (their weight moved from passes to failures, and the critical cap applied if one of them is critical). Then the grade is capped at B and the report says *runtime-qualified*. An A that holds even in that worst case is kept: this makes the rule monotonic, so **failing a control can never earn a better grade than passing it** (a flat "any runtime-only pass caps at B" would reward turning a live-only pass into a failure). The points are never touched: a qualified pass adds no failure.

In the JSON report the summary shows it:

```json
{
  "score": 100,
  "grade": "B",
  "raw_grade": "A",
  "runtime_qualified": true,
  "qualified_passes": 7,
  "counts": { "pass": 150, "runtime_only": 7, "reboot_proven": 0, "...": 0 }
}
```

The points are 100 (no control failed), an A on arithmetic alone, but the A rests on 7 passes whose persistence is not proven, so the letter is B until persistence is proven: fix the persisted configuration (`sdw-armor harden` does both at once), or prove it with a scan after a reboot.

## 7. Pillars and standard lenses

- Each pillar is graded with the same formula on its own controls.
- A **lens** re-grades a scan through one standard: only the controls mapped to that standard count (`--lens cis|anssi|nist|nist171|pci|stig`, or the lens buttons of the HTML report). `--standard` additionally restricts *which controls run*.

## 8. Levels

- **Level 1** (default): baseline controls, reasonable on every server.
- **Level 2**: adds hardened controls that can have operational impact (FIPS mode, USB storage, IPv6 router advertisements, kexec, compilers, audit immutability...).
