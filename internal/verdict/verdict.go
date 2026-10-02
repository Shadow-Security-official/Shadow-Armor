// Package verdict turns raw engine results into a qualified verdict: what a
// PASS proves, not only whether the check passed.
//
// Every assertion of the profile has an evidence type:
//   - runtime:    live state of the running system (property named runtime*,
//     or a live-only check such as listening sockets);
//   - persistent: the configuration that recreates the state at the next boot
//     (property named persistent*: sysctl.d, modprobe.d, enabled units,
//     fstab, audit rules.d, boot loader command line);
//   - config:     resolved configuration as its consumer reads it (sshd -T,
//     PAM and sudoers with their includes, login.defs, systemd cat-config);
//   - inventory:  installed or absent software, hardware and OS facts,
//     storage layout;
//   - filesystem: files on disk, their modes, owners and content;
//   - transient:  live state that a reboot can only clear (processes still
//     mapping deleted libraries).
//
// Unprefixed assertions take the type the catalog declares for the control.
// The assertions then prove three things (the proof columns):
//
//	now      runtime, config, inventory, filesystem, transient assertions
//	on disk  persistent, config, inventory, filesystem assertions
//	reboot   expected when the on-disk state is compliant, failed when it is
//	         not, not_measured when nothing on disk was checked, n/a for
//	         transient state, proven once a scan after a real reboot saw it
//	         (see scan.ApplyRebootBaseline)
//
// and the control gets one of:
//
//	pass/durable       compliant now, and the persisted state keeps it after a reboot
//	pass/runtime-only  compliant now, but the persisted state contradicts it or
//	                   nothing on disk proves it (caps an A that rests on it)
//	fail/pending       only live values are wrong and the persisted state is
//	                   compliant: a reboot or reload is pending
//	fail               any other failure
//	error              an assertion could not be evaluated (counts as a failure)
//	skip               not applicable on this target
//	waived             accepted risk recorded in a waiver file
package verdict

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/engine"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
)

// Evidence types.
const (
	KindRuntime    = "runtime"
	KindPersistent = "persistent"
	KindConfig     = "config"
	KindInventory  = "inventory"
	KindFilesystem = "filesystem"
	KindTransient  = "transient"
	// KindEffective marks an unprefixed assertion before the control's
	// declared evidence type is applied.
	KindEffective = "effective"
)

var kindRe = regexp.MustCompile(`(?:^|\s)(runtime|persistent)[a-z_]*\s+is expected`)

// Kind classifies one assertion from its InSpec code description:
// runtime, persistent, or effective (type declared by the control).
func Kind(codeDesc string) string {
	m := kindRe.FindStringSubmatch(codeDesc)
	if m == nil {
		return KindEffective
	}
	return m[1]
}

func counts(kind string) (now, disk bool) {
	switch kind {
	case KindRuntime, KindTransient:
		return true, false
	case KindPersistent:
		return false, true
	}
	return true, true // config, inventory, filesystem: durable state read as it is used
}

var (
	emptyFailRe = regexp.MustCompile("^expected `(.*)\\.empty\\?` to be truthy, got false$")
	emptyOkRe   = regexp.MustCompile("^expected `\\[\\]\\.empty\\?` to be falsey, got true$")
	spaceRe     = regexp.MustCompile(`\s+`)
	comparedRe  = regexp.MustCompile(`\(compared using [^)]*\)`)
	diffRe      = regexp.MustCompile(`\s*Diff:.*$`)

	eqRe      = regexp.MustCompile(`^expected: (.*?) got: (.*)$`)
	cmpRe     = regexp.MustCompile(`^expected it (not )?to be (>=|<=|==|!=|>|<) (.*?) got: (.*)$`)
	inListRe  = regexp.MustCompile("^expected `(.*)` (not )?to be in the list: `\\[(.*)\\]`$")
	betweenRe = regexp.MustCompile(`^expected (.*) to be between (\S+) and (\S+)(?: \(inclusive\))?$`)
	maskRe    = regexp.MustCompile(`^expected "?([0-7]+)"? to mask at least ([0-7]+)$`)
	includeRe = regexp.MustCompile(`^expected \[(.*)\] to include (.*)$`)
	existRe   = regexp.MustCompile(`^expected (?:File|Directory|Path) (.*) to exist$`)
	quotedRe  = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
)

// CleanMessage turns an RSpec failure message into one line that says what
// was found and what was expected, in that order.
func CleanMessage(m string) string {
	m = comparedRe.ReplaceAllString(m, "")
	m = diffRe.ReplaceAllString(strings.ReplaceAll(m, "\n", " "), "")
	m = strings.TrimSpace(spaceRe.ReplaceAllString(m, " "))
	if strings.HasSuffix(m, "got:") {
		m += " (unset)"
	}
	m = strings.Replace(m, "got: expected", "got: (unset) expected", 1)
	if sm := emptyFailRe.FindStringSubmatch(m); sm != nil {
		return "found: " + strings.Trim(sm[1], "[]")
	}
	if emptyOkRe.MatchString(m) {
		return "found: none"
	}
	if sm := cmpRe.FindStringSubmatch(m); sm != nil {
		want := sm[2] + " " + unquote(sm[3])
		switch {
		case sm[1] != "" && sm[2] == "==":
			want = "anything but " + unquote(sm[3])
		case sm[1] != "":
			want = "not " + want
		case sm[2] == "==":
			want = unquote(sm[3])
		}
		return found(sm[4]) + " · expected " + want
	}
	if sm := eqRe.FindStringSubmatch(m); sm != nil {
		switch {
		case sm[1] == "[]":
			return "found: " + strings.Trim(sm[2], "[]")
		case sm[1] == "not nil" && sm[2] == "nil":
			return "found none"
		}
		return found(sm[2]) + " · expected " + unquote(sm[1])
	}
	if sm := inListRe.FindStringSubmatch(m); sm != nil {
		opts := listItems(sm[3], true)
		if sm[2] != "" {
			return found(sm[1]) + " · expected anything but " + strings.Join(opts, ", ")
		}
		if len(opts) == 1 {
			return found(sm[1]) + " · expected " + opts[0]
		}
		return found(sm[1]) + " · expected one of " + strings.Join(opts, ", ")
	}
	if sm := betweenRe.FindStringSubmatch(m); sm != nil {
		return found(sm[1]) + " · expected between " + sm[2] + " and " + sm[3]
	}
	if sm := maskRe.FindStringSubmatch(m); sm != nil {
		return "found umask " + sm[1] + " · expected " + sm[2] + " or stricter"
	}
	if sm := includeRe.FindStringSubmatch(m); sm != nil {
		have := listItems(sm[1], false)
		var missing []string
		for _, w := range listItems(strings.Replace(sm[2], ", and ", ", ", 1), false) {
			if !contains(have, w) {
				missing = append(missing, w)
			}
		}
		if len(missing) == 0 {
			return m
		}
		f := strings.Join(have, ", ")
		if f == "" {
			f = "none"
		}
		return "missing " + strings.Join(missing, ", ") + " · found " + f
	}
	if sm := existRe.FindStringSubmatch(m); sm != nil {
		return sm[1] + " does not exist"
	}
	return m
}

func found(v string) string { return "found " + unquote(v) }

// unquote drops RSpec's inspect quotes around a single value.
func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '`' && v[len(v)-1] == '`') {
		v = v[1 : len(v)-1]
	}
	if v == "" {
		return "(empty)"
	}
	return v
}

// listItems splits an inspected list ("a", "b" or a, b) into plain values;
// fold drops case duplicates (auditd accepts EMAIL and email).
func listItems(s string, fold bool) []string {
	var raw []string
	if q := quotedRe.FindAllStringSubmatch(s, -1); q != nil {
		for _, x := range q {
			raw = append(raw, x[1])
		}
	} else {
		for _, x := range strings.Split(s, ",") {
			if x = strings.TrimSpace(x); x != "" {
				raw = append(raw, x)
			}
		}
	}
	var out []string
	for _, x := range raw {
		if x == "" {
			x = "(empty)"
		}
		dup := false
		for _, y := range out {
			if y == x || fold && strings.EqualFold(y, x) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, x)
		}
	}
	return out
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func isSkipException(exc string) bool {
	return strings.HasSuffix(exc, "ResourceSkipped")
}

// Evidence converts engine results into report evidence; unprefixed
// assertions get the control's declared evidence type (config by default).
func Evidence(results []engine.InspecResult, declared string) []model.Evidence {
	if declared == "" {
		declared = KindConfig
	}
	out := make([]model.Evidence, 0, len(results))
	for _, r := range results {
		kind := Kind(r.CodeDesc)
		if kind == KindEffective {
			kind = declared
		}
		ev := model.Evidence{Kind: kind, Status: r.Status, Desc: strings.TrimSpace(r.CodeDesc)}
		switch {
		case r.Exception != "" && isSkipException(r.Exception):
			ev.Status = "skipped"
			ev.Message = CleanMessage(r.Message)
		case r.Exception != "" || strings.HasPrefix(r.CodeDesc, "Control Source Code Error"):
			ev.Status = "error"
			ev.Message = CleanMessage(r.Message)
		case r.Status == "skipped":
			ev.Message = CleanMessage(r.SkipMessage)
		case r.Status == "failed":
			ev.Message = CleanMessage(r.Message)
		}
		out = append(out, ev)
	}
	return out
}

// Result is the qualified verdict of one control.
type Result struct {
	Status    model.Status
	Qualifier model.Qualifier
	Reason    string
	Evidence  []model.Evidence
	Proof     *model.Proof
}

// Reasons of a runtime-only pass.
const (
	ReasonContradicted = "compliant now, but the persisted configuration would undo it at the next reboot"
	ReasonUnproven     = "compliant now, but nothing on disk proves it survives a reboot (live state only): re-scan after a reboot with --reboot-baseline to prove it"
	ReasonPending      = "the persisted configuration is compliant: a reboot or reload is pending"
)

// Classify computes the qualified verdict of one control. declared is the
// evidence type of its unprefixed assertions (catalog "evidence").
func Classify(ic engine.InspecControl, declared string) Result {
	ev := Evidence(ic.Results, declared)
	if w := waiver(ic.WaiverData); w != "" {
		return Result{Status: model.Waived, Reason: w, Evidence: ev}
	}
	var (
		skipped, errs, run                   int
		nowPass, nowFail, diskPass, diskFail int
		rtFail, otherFail, pCount, rtAbsent  int
		transientOnly                        = true
		firstErr, firstSkip                  string
	)
	for _, e := range ev {
		switch e.Status {
		case "skipped":
			skipped++
			if firstSkip == "" {
				firstSkip = e.Message
			}
			continue
		case "error":
			errs++
			if firstErr == "" {
				firstErr = e.Message
			}
			continue
		}
		run++
		if e.Kind != KindTransient {
			transientOnly = false
		}
		if e.Kind == KindPersistent {
			pCount++
		}
		now, disk := counts(e.Kind)
		failed := e.Status == "failed"
		if now {
			if failed {
				nowFail++
			} else {
				nowPass++
			}
		}
		if disk {
			if failed {
				diskFail++
			} else {
				diskPass++
			}
		}
		if failed {
			if e.Kind == KindRuntime {
				rtFail++
				if strings.HasPrefix(e.Message, "found (unset)") {
					// The live value does not exist (feature missing from this
					// kernel/host): a reboot will not fix it.
					rtAbsent++
				}
			} else if e.Kind != KindPersistent {
				otherFail++
			}
		}
	}
	switch {
	case errs > 0:
		return Result{Status: model.Error, Reason: firstErr, Evidence: ev}
	case run == 0:
		if firstSkip == "" {
			firstSkip = "no assertion applies to this target"
		}
		return Result{Status: model.Skip, Reason: strings.TrimPrefix(firstSkip, "Skipped control due to only_if condition: "), Evidence: ev}
	}
	col := func(pass, fail int) string {
		switch {
		case fail > 0:
			return model.ProofFailed
		case pass > 0:
			return model.ProofProven
		}
		return model.ProofNotMeasured
	}
	p := &model.Proof{Now: col(nowPass, nowFail), OnDisk: col(diskPass, diskFail)}
	switch {
	case p.OnDisk == model.ProofFailed:
		p.Reboot = model.ProofFailed
	case p.OnDisk == model.ProofProven:
		p.Reboot = model.ProofExpected
	case transientOnly:
		p.Reboot = model.ProofNA
	default:
		p.Reboot = model.ProofNotMeasured
	}
	r := Result{Evidence: ev, Proof: p}
	switch {
	case nowFail > 0:
		r.Status = model.Fail
		if otherFail == 0 && rtFail == nowFail && rtAbsent == 0 && pCount > 0 && p.OnDisk == model.ProofProven {
			r.Qualifier, r.Reason = model.Pending, ReasonPending
		}
	case p.Now == model.ProofNotMeasured && p.OnDisk == model.ProofFailed:
		// Only boot-time state was checked, and it is wrong.
		r.Status = model.Fail
	case p.Reboot == model.ProofFailed:
		r.Status, r.Qualifier, r.Reason = model.Pass, model.RuntimeOnly, ReasonContradicted
	case p.Reboot == model.ProofNotMeasured:
		r.Status, r.Qualifier, r.Reason = model.Pass, model.RuntimeOnly, ReasonUnproven
	default:
		r.Status, r.Qualifier = model.Pass, model.Durable
	}
	return r
}

// waiver returns a description when the control is covered by an active
// waiver (InSpec evaluates expiry: expired waivers run normally).
func waiver(w map[string]any) string {
	if len(w) == 0 {
		return ""
	}
	msg, _ := w["message"].(string)
	if strings.Contains(strings.ToLower(msg), "expired") {
		return ""
	}
	skipped, _ := w["skipped_due_to_waiver"].(bool)
	run, _ := w["run"].(bool)
	if !skipped && !run {
		return ""
	}
	j, _ := w["justification"].(string)
	if j == "" {
		j = "waived"
	}
	if exp, ok := w["expiration_date"]; ok && exp != nil {
		return fmt.Sprintf("%s (until %v)", j, exp)
	}
	return j
}

// WaiverOf extracts justification and expiry for the report.
func WaiverOf(w map[string]any) *model.Waiver {
	if waiver(w) == "" {
		return nil
	}
	j, _ := w["justification"].(string)
	var exp string
	if e, ok := w["expiration_date"]; ok && e != nil {
		exp = fmt.Sprint(e)
	}
	return &model.Waiver{Justification: j, Expires: exp}
}
