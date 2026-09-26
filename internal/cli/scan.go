package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/catalog"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/cinc"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/engine"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/report"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/scan"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/score"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/target"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/ui"
)

type scanFlags struct {
	sudo        bool
	identity    string
	onTarget    bool
	bootstrap   bool
	cincVersion string
	cincPkgs    multi
	engine      string
	engineImage string
	level       int
	pillars     multi
	standard    string
	lens        string
	controls    multi
	exclude     multi
	inputs      multi
	inputsFile  string
	waivers     string
	verbose     bool
	noColor     bool
	quiet       bool
	timeout     time.Duration
	forHarden   bool
}

func (sf *scanFlags) register(f *flags) {
	sf.pillars.split, sf.controls.split, sf.exclude.split = true, true, true
	f.BoolVar(&sf.sudo, "sudo", false, "run privileged probes through sudo (non-interactive; set SDW_SUDO_PASSWORD if sudo needs a password)")
	f.StringVar(&sf.identity, "i", "", "SSH private key file (default: your ssh-agent and ~/.ssh/config)")
	f.BoolVar(&sf.onTarget, "on-target", false, "run the engine on the target itself (fast); it must be installed there")
	f.BoolVar(&sf.bootstrap, "bootstrap-cinc", false, "install CINC on the target when missing (cinc-auditor for --on-target, cinc-client for harden): package resolved on omnitruck.cinc.sh, downloaded here, SHA-256 verified, installed with dpkg/rpm; no installer script")
	f.StringVar(&sf.cincVersion, "cinc-version", "", "CINC version to install with --bootstrap-cinc (default: latest stable)")
	f.Var(&sf.cincPkgs, "cinc-package", "install CINC on the target from this local .deb/.rpm when missing (air-gapped; repeatable: cinc-auditor and cinc packages)")
	f.StringVar(&sf.engine, "engine", "auto", "engine: auto (native cinc-auditor/inspec, else the Docker image when already present), native, docker (runs the CINC Auditor image, pulled if needed; ssh:// and docker:// targets), or a path")
	f.StringVar(&sf.engineImage, "engine-image", "", "image of --engine docker (default "+engine.DefaultImage+"; or $SDW_ARMOR_ENGINE_IMAGE)")
	f.IntVar(&sf.level, "level", 1, "1 = baseline controls, 2 = baseline + hardened")
	f.Var(&sf.pillars, "pillar", "only these pillars (numbers or keys, comma separated, e.g. 6,12 or ssh,crypto-mfa)")
	f.StringVar(&sf.standard, "standard", "all", "only controls mapped to a standard: "+strings.Join(catalog.StandardKeys, ", "))
	f.StringVar(&sf.lens, "lens", "", "grade through one standard (default: the --standard value)")
	f.Var(&sf.controls, "controls", "only these control IDs (comma separated)")
	f.Var(&sf.exclude, "exclude", "skip these control IDs (comma separated)")
	f.Var(&sf.inputs, "input", "override an input, name=value (repeatable; value parsed as JSON when possible)")
	f.StringVar(&sf.inputsFile, "inputs", "", "JSON file of input overrides")
	f.StringVar(&sf.waivers, "waivers", "", "InSpec waiver file (YAML: control id -> justification, expiration_date, run)")
	f.BoolVar(&sf.verbose, "verbose", false, "list passes and non-applicable controls, stream engine messages")
	f.BoolVar(&sf.noColor, "no-color", false, "disable colours")
	f.BoolVar(&sf.quiet, "quiet", false, "no progress messages")
	f.DurationVar(&sf.timeout, "timeout", 45*time.Minute, "abort the audit after this long")
}

func (a *app) parsePillars(vals []string) ([]int, error) {
	var out []int
	for _, v := range vals {
		if n, err := strconv.Atoi(v); err == nil {
			if _, ok := a.cat.Pillar(n); !ok {
				return nil, usagef("unknown pillar %d (1-%d)", n, len(a.cat.Pillars))
			}
			out = append(out, n)
			continue
		}
		found := false
		for _, p := range a.cat.Pillars {
			if strings.EqualFold(p.Key, v) {
				out = append(out, p.ID)
				found = true
			}
		}
		if !found {
			return nil, usagef("unknown pillar %q (use 1-%d or a key from `sdw-armor list --pillars`)", v, len(a.cat.Pillars))
		}
	}
	return out, nil
}

func (a *app) parseInputs(sf *scanFlags) (map[string]any, error) {
	known := a.cat.InputDefaults()
	out := map[string]any{}
	if sf.inputsFile != "" {
		raw, err := os.ReadFile(sf.inputsFile)
		if err != nil {
			return nil, usagef("--inputs: %v", err)
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, usagef("--inputs %s: not a JSON object: %v", sf.inputsFile, err)
		}
	}
	for _, kv := range sf.inputs.vals {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, usagef("--input %q: expected name=value", kv)
		}
		var val any
		if err := json.Unmarshal([]byte(v), &val); err != nil {
			val = v
		}
		out[strings.TrimSpace(k)] = val
	}
	for k := range out {
		if _, ok := known[k]; !ok {
			return nil, usagef("unknown input %q (see `sdw-armor list --inputs`)", k)
		}
	}
	return out, nil
}

func (a *app) scanOptions(sf *scanFlags, targetArg string) (scan.Options, error) {
	t, err := target.Parse(targetArg)
	if err != nil {
		return scan.Options{}, usageError{err.Error()}
	}
	t.Sudo = sf.sudo
	t.Identity = sf.identity
	t.SudoPassword = os.Getenv("SDW_SUDO_PASSWORD")
	if sf.level != 1 && sf.level != 2 {
		return scan.Options{}, usagef("--level must be 1 or 2")
	}
	if !catalog.ValidStandard(sf.standard) {
		return scan.Options{}, usagef("unknown --standard %q (use %s or all)", sf.standard, strings.Join(catalog.StandardKeys, ", "))
	}
	lens := sf.lens
	if lens == "" {
		lens = sf.standard
	}
	if !catalog.ValidStandard(lens) {
		return scan.Options{}, usagef("unknown --lens %q", lens)
	}
	pillars, err := a.parsePillars(sf.pillars.vals)
	if err != nil {
		return scan.Options{}, err
	}
	for _, id := range sf.controls.vals {
		if _, ok := a.cat.Control(id); !ok {
			return scan.Options{}, usagef("unknown control %q", id)
		}
	}
	inputs, err := a.parseInputs(sf)
	if err != nil {
		return scan.Options{}, err
	}
	if sf.engine == "docker" && sf.onTarget {
		return scan.Options{}, usagef("--engine docker runs the engine here, in a container; --on-target runs it on the target: pick one")
	}
	if sf.engine == "docker" && t.Kind == target.Local {
		return scan.Options{}, usagef("%v; audit this machine with the native engine (sdw-armor install-cinc --sudo), or scan it from another machine over ssh://", scan.ErrDockerLocal)
	}
	if (sf.bootstrap || len(sf.cincPkgs.vals) > 0) && !sf.onTarget && !sf.forHarden {
		return scan.Options{}, usagef("--bootstrap-cinc and --cinc-package only make sense with --on-target")
	}
	for _, pkg := range sf.cincPkgs.vals {
		if cinc.ProjectOf(pkg) == "" || cinc.PkgType(pkg) == "" {
			return scan.Options{}, usagef("--cinc-package %s: expected a cinc-auditor or cinc .deb/.rpm package file", pkg)
		}
		if _, err := os.Stat(pkg); err != nil {
			return scan.Options{}, usagef("--cinc-package: %v", err)
		}
	}
	if sf.waivers != "" {
		if _, err := os.Stat(sf.waivers); err != nil {
			return scan.Options{}, usagef("--waivers: %v", err)
		}
	}
	o := scan.Options{
		Target: t, Engine: sf.engine, EngineImage: sf.engineImage, OnTarget: sf.onTarget, BootstrapCINC: sf.bootstrap, CINCVersion: sf.cincVersion, CINCPackages: sf.cincPkgs.vals,
		Filter: catalog.Filter{Level: sf.level, Pillars: pillars, Standard: sf.standard, IDs: sf.controls.vals, Exclude: sf.exclude.vals},
		Inputs: inputs, WaiverFile: sf.waivers, Lens: lens,
	}
	if sf.verbose {
		o.EngineLog = a.stderr
	}
	return o, nil
}

// runScan executes a scan with progress feedback and maps errors to exit codes.
func (a *app) runScan(ctx context.Context, sf *scanFlags, o scan.Options) (*model.Report, error) {
	if o.Target.Kind == target.Local && !o.Target.Sudo && os.Geteuid() != 0 && !sf.quiet {
		fmt.Fprintf(a.stderr, "note: running as uid %d without --sudo: probes that need root (/etc/shadow, sshd -T, auditctl) will report errors, which count as failures.\n", os.Geteuid())
	}
	live := a.scanProgress(sf.quiet, sf.verbose, &o)
	rep, err := scan.Run(ctx, a.cat, o)
	live.finish(rep, err)
	if err != nil {
		switch {
		case errors.Is(err, scan.ErrNoEngine):
			hint := ""
			if o.Target.Kind != target.Local {
				hint = "\nor run it from its Docker image, nothing to install: --engine docker"
			}
			return nil, exitError{ExitPrereq, fmt.Errorf("%v\n\nsdw-armor needs CINC Auditor (the free build of InSpec) to run its controls; it is in no\ndistribution repository, so no package manager pulls it for you. Install it on this machine:\n  sdw-armor install-cinc --sudo     (SHA-256 verified package, asks before installing)\n  sdw-armor install-cinc --print    (the same steps as shell commands)\nor run the engine on the target with --on-target (and --bootstrap-cinc to install it there)%s", err, hint)}
		case errors.Is(err, scan.ErrDockerLocal):
			return nil, exitError{ExitUsage, err}
		case errors.Is(err, engine.ErrDockerUnavailable):
			return nil, exitError{ExitPrereq, err}
		case errors.Is(err, scan.ErrEngineMissingOnTarget):
			return nil, exitError{ExitPrereq, err}
		case strings.Contains(err.Error(), "cannot reach"):
			return nil, exitError{ExitPrereq, err}
		case strings.HasPrefix(err.Error(), "--reboot-baseline"):
			return nil, exitError{ExitUsage, err}
		case errors.Is(err, context.DeadlineExceeded):
			return nil, exitError{ExitEngineError, fmt.Errorf("audit timed out after %s", sf.timeout)}
		}
		return nil, exitError{ExitEngineError, err}
	}
	return rep, nil
}

func signalContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	if timeout <= 0 {
		return ctx, cancel
	}
	tctx, tcancel := context.WithTimeout(ctx, timeout)
	return tctx, func() { tcancel(); cancel() }
}

// output handles -o format[:path] and --format.
type outputSpec struct {
	format string
	path   string
}

func parseOutputs(vals []string, def string) ([]outputSpec, error) {
	var out []outputSpec
	for _, v := range vals {
		f, p, _ := strings.Cut(v, ":")
		if strings.Contains(v, ":") {
			f = extFormat(f)
		}
		if !validFormat(f) {
			// Allow -o report.html (format from the extension).
			if ext := strings.TrimPrefix(filepath.Ext(v), "."); validFormat(extFormat(ext)) && !strings.Contains(v, ":") {
				f, p = extFormat(ext), v
			} else {
				return nil, usagef("-o %q: format must be one of %s", v, strings.Join(report.Formats, ", "))
			}
		}
		out = append(out, outputSpec{f, p})
	}
	if def != "" {
		if !validFormat(def) {
			return nil, usagef("--format %q: must be one of %s", def, strings.Join(report.Formats, ", "))
		}
		out = append([]outputSpec{{def, ""}}, out...)
	}
	return out, nil
}

func extFormat(ext string) string {
	switch ext {
	case "md":
		return "markdown"
	case "xml":
		return "junit"
	case "txt":
		return "text"
	case "htm":
		return "html"
	}
	return ext
}

func validFormat(f string) bool {
	for _, x := range report.Formats {
		if x == f {
			return true
		}
	}
	return false
}

func (a *app) render(w io.Writer, format string, r *model.Report, verbose, color bool) error {
	switch format {
	case "text":
		o := report.TextOptions{Profile: ui.NoColor, Width: 100, Verbose: verbose, Sudo: a.sudoHint}
		if t := ui.Detect(w, color); t.TTY || color {
			o.Profile, o.Width = t.Profile, t.Width
		}
		report.Text(w, r, o)
		return nil
	case "json":
		return report.JSON(w, r)
	case "html":
		return report.HTML(w, r)
	case "sarif":
		return report.SARIF(w, r)
	case "junit":
		return report.JUnit(w, r)
	case "markdown":
		return report.Markdown(w, r)
	}
	return fmt.Errorf("unknown format %q", format)
}

func (a *app) writeOutputs(specs []outputSpec, r *model.Report, verbose, noColor bool) error {
	// Files first: a closed stdout pipe (| head) must not lose them.
	for _, s := range specs {
		if s.path == "" || s.path == "-" {
			continue
		}
		var buf bytes.Buffer
		if err := a.render(&buf, s.format, r, verbose, false); err != nil {
			return err
		}
		// Reports describe weaknesses of a host: keep them private.
		if err := os.WriteFile(s.path, buf.Bytes(), 0o600); err != nil {
			return err
		}
		if t := ui.Detect(a.stderr, a.color); t.TTY {
			fmt.Fprintln(a.stderr, "  "+t.Profile.Paint(ui.Green, "✓")+" "+t.Profile.Paint(ui.Steel, s.format+" report written to ")+t.Profile.Paint(ui.Ink, s.path))
		} else {
			fmt.Fprintf(a.stderr, "wrote %s report to %s\n", s.format, s.path)
		}
	}
	for _, s := range specs {
		if s.path != "" && s.path != "-" {
			continue
		}
		if err := a.render(a.stdout, s.format, r, verbose, a.color && !noColor); err != nil {
			return err
		}
	}
	return nil
}

func (a *app) scan(args []string) error {
	f := newFlags("scan", "Audit a target: effective configuration, qualified verdicts, A-E grade.", "[target] [flags]")
	var sf scanFlags
	sf.register(f)
	var outputs multi
	var format, failUnder, rebootBase string
	f.Var(&outputs, "o", "write a report: format:path (repeatable), e.g. -o html:report.html -o json:scan.json; formats: "+strings.Join(report.Formats, ", "))
	f.StringVar(&rebootBase, "reboot-baseline", "", "JSON report of this host from before its last reboot: passes seen in both are reboot-proven (lifts the runtime-only cap), passes since lost are flagged")
	f.StringVar(&format, "format", "", "format printed on stdout (default text; 'none' when only -o files are wanted)")
	f.StringVar(&failUnder, "fail-under", "", "exit 1 when the grade is worse than this (A-E), for CI")
	pos, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return usagef("one target at a time (got %s)", strings.Join(pos, " "))
	}
	targetArg := ""
	if len(pos) == 1 {
		targetArg = pos[0]
	}
	if failUnder != "" && score.Rank(strings.ToUpper(failUnder)) >= len(score.Grades) {
		return usagef("--fail-under must be one of A, B, C, D, E")
	}
	stdoutFmt := format
	if stdoutFmt == "" {
		stdoutFmt = "text"
	}
	if stdoutFmt == "none" {
		stdoutFmt = ""
	}
	specs, err := parseOutputs(outputs.vals, stdoutFmt)
	if err != nil {
		return err
	}
	o, err := a.scanOptions(&sf, targetArg)
	if err != nil {
		return err
	}
	a.sudoHint = sf.sudo
	if rebootBase != "" {
		if o.RebootBaseline, err = loadReport(rebootBase); err != nil {
			return exitError{ExitUsage, err}
		}
		if o.RebootBaseline.Target.URI != o.Target.String() && !sf.quiet {
			fmt.Fprintf(a.stderr, "note: the baseline was taken through %s, this scan through %s (the machine identity is what is compared)\n", o.RebootBaseline.Target.URI, o.Target)
		}
	}
	ctx, cancel := signalContext(sf.timeout)
	defer cancel()
	a.banner(sf.quiet)
	rep, err := a.runScan(ctx, &sf, o)
	if err != nil {
		return err
	}
	if err := a.writeOutputs(specs, rep, sf.verbose, sf.noColor); err != nil {
		return err
	}
	if o.RebootBaseline != nil && !sf.quiet {
		a.rebootSummary(rep)
	}
	if failUnder != "" {
		want := strings.ToUpper(failUnder)
		if score.Rank(rep.Summary.Grade) > score.Rank(want) {
			return exitError{ExitPolicy, fmt.Errorf("grade %s is worse than --fail-under %s", rep.Summary.Grade, want)}
		}
	}
	return nil
}

// rebootSummary prints what a reboot baseline proved.
func (a *app) rebootSummary(r *model.Report) {
	t := ui.Detect(a.stderr, a.color)
	p := t.Profile
	var proven, lost []string
	for _, c := range r.Controls {
		if c.Proof == nil {
			continue
		}
		switch c.Proof.Reboot {
		case model.ProofProven:
			proven = append(proven, c.ID)
		case model.ProofLost:
			lost = append(lost, c.ID)
		}
	}
	line := "  " + p.Paint(ui.Cyan, "↻ ") + p.Paint(ui.Ink, fmt.Sprintf("reboot proof: %d pass(es) survived a real reboot", len(proven)))
	if len(lost) > 0 {
		line += p.Paint(ui.Muted, " · ") + p.Paint(ui.Red, fmt.Sprintf("%d lost at the reboot: %s", len(lost), strings.Join(lost, ", ")))
	}
	fmt.Fprintln(a.stderr, line)
}
