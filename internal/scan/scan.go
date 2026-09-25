// Package scan orchestrates one audit: select controls, stage the embedded
// profile, run the engine (locally or on the target), and qualify the results.
package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	shadowarmor "github.com/Shadow-Security-official/Shadow-Armor"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/catalog"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/cinc"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/engine"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/score"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/target"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/verdict"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/version"
)

type Options struct {
	Target *target.Target
	// Engine: "auto" (default: the native engine, else the Docker image when
	// it is already present), "native", "docker", or the path of a native
	// engine binary.
	Engine        string
	EngineImage   string // Docker engine image (default engine.DefaultImage)
	OnTarget      bool
	BootstrapCINC bool
	CINCVersion   string
	CINCPackages  []string // operator-provided packages (air-gapped bootstrap)
	Filter        catalog.Filter
	Inputs        map[string]any // overrides of catalog defaults
	WaiverFile    string
	Lens          string
	// RebootBaseline: a report of the same host from an earlier boot; passes
	// seen in both are reboot-proven (see ApplyRebootBaseline).
	RebootBaseline *model.Report
	// Engine stderr is copied here when set (verbose mode).
	EngineLog io.Writer
	// Progress receives short status lines.
	Progress func(string)
	// OnEvent receives live engine progress (controls done, results).
	OnEvent func(engine.Event)
}

// ErrEngineMissingOnTarget is returned in --on-target mode when the target has
// no engine and --bootstrap-cinc was not given.
var ErrEngineMissingOnTarget = errors.New("cinc-auditor is not installed on the target")

// ErrNoEngine is returned when no local engine is available.
var ErrNoEngine = errors.New("no local engine")

// ErrDockerLocal: the Docker engine cannot audit the machine it runs on.
var ErrDockerLocal = errors.New("the Docker engine cannot audit this machine: a container only sees its own filesystem")

func (o *Options) progress(format string, a ...any) {
	if o.Progress != nil {
		o.Progress(fmt.Sprintf(format, a...))
	}
}

// Run performs the audit and returns the qualified report.
func Run(ctx context.Context, cat *catalog.Catalog, o Options) (*model.Report, error) {
	selected := cat.Select(o.Filter)
	if len(selected) == 0 {
		return nil, errors.New("no control matches the selection (check --level, --pillar, --standard, --controls)")
	}
	ids := make([]string, len(selected))
	for i, c := range selected {
		ids[i] = c.ID
	}
	inputs := cat.InputDefaults()
	for k, v := range o.Inputs {
		inputs[k] = v
	}
	inputsYAML, err := engine.InputsYAML(inputs)
	if err != nil {
		return nil, err
	}
	var waivers []byte
	if o.WaiverFile != "" {
		if waivers, err = os.ReadFile(o.WaiverFile); err != nil {
			return nil, fmt.Errorf("waiver file: %w", err)
		}
	}

	t := o.Target
	// Boot identity (best effort: without a local ssh/docker client the
	// engine can still reach the target with its own transport).
	host, herr := HostOf(ctx, t)
	if herr != nil && o.RebootBaseline != nil {
		return nil, fmt.Errorf("--reboot-baseline: cannot read the boot identity of %s: %w", t, herr)
	}
	if o.RebootBaseline != nil {
		if ok, why := model.Rebooted(o.RebootBaseline.Target.Host, host); !ok {
			return nil, fmt.Errorf("--reboot-baseline: %s", why)
		}
	}
	start := time.Now()
	var raw []byte
	var eng model.Engine
	if o.OnTarget && t.Kind != target.Local {
		raw, eng, err = runOnTarget(ctx, o, ids, inputsYAML, waivers)
	} else {
		raw, eng, err = runLocal(ctx, o, ids, inputsYAML, waivers)
	}
	if err != nil {
		return nil, err
	}
	ir, err := engine.ParseReport(raw)
	if err != nil {
		return nil, fmt.Errorf("parse engine report: %w", err)
	}
	eng.Duration = time.Since(start).Round(100 * time.Millisecond).Seconds()
	rep := Build(cat, ir, selected, o.Filter, inputs, o.Lens)
	rep.Engine = eng
	rep.Target.URI = t.String()
	rep.Target.Kind = string(t.Kind)
	rep.Target.Host = host
	if o.RebootBaseline != nil {
		if _, err := ApplyRebootBaseline(rep, o.RebootBaseline); err != nil {
			return nil, fmt.Errorf("--reboot-baseline: %w", err)
		}
	}
	return rep, nil
}

// localEngine picks the engine that runs on this machine.
type localEngine struct {
	native *engine.Engine
	docker *engine.Docker
}

func pickEngine(ctx context.Context, o Options) (localEngine, error) {
	mode := o.Engine
	if mode == "" {
		mode = "auto"
	}
	image := engine.ImageRef(o.EngineImage)
	useDocker := func(pull bool) (localEngine, error) {
		if o.Target.Kind == target.Local {
			return localEngine{}, ErrDockerLocal
		}
		if pull {
			o.progress("preparing the engine image %s", image)
		}
		d, err := engine.PrepareDocker(ctx, image, pull, o.EngineLog)
		if err != nil {
			return localEngine{}, err
		}
		return localEngine{docker: d}, nil
	}
	switch mode {
	case "docker":
		return useDocker(true)
	case "auto", "native":
		e, err := engine.Find(ctx, "")
		if err == nil {
			return localEngine{native: e}, nil
		}
		if mode == "auto" && o.Target.Kind != target.Local {
			if engine.DockerReady(ctx) == nil {
				if _, present := engine.ImageDigest(ctx, image); present {
					o.progress("no native engine here: using the CINC Auditor image already present (%s)", image)
					return useDocker(false)
				}
			}
		}
		return localEngine{}, fmt.Errorf("%w: %v", ErrNoEngine, err)
	default:
		e, err := engine.Find(ctx, mode)
		if err != nil {
			return localEngine{}, fmt.Errorf("%w: %v", ErrNoEngine, err)
		}
		return localEngine{native: e}, nil
	}
}

func runLocal(ctx context.Context, o Options, ids []string, inputsYAML, waivers []byte) ([]byte, model.Engine, error) {
	le, err := pickEngine(ctx, o)
	if err != nil {
		return nil, model.Engine{}, err
	}
	// Fail fast with a readable message when the target is unreachable
	// (only when the matching client exists here; the engine has its own).
	if client := map[target.Kind]string{target.SSH: "ssh", target.Docker: "docker"}[o.Target.Kind]; client != "" {
		if _, lerr := exec.LookPath(client); lerr == nil {
			o.progress("connecting to %s", o.Target)
			user, perr := o.Target.Probe(ctx)
			if perr != nil {
				return nil, model.Engine{}, perr
			}
			if user == "root" {
				o.Target.Sudo = false // already root: sudo is not needed, and may not be installed
			}
		}
	}
	if o.Target.Kind == target.Local && os.Geteuid() == 0 {
		o.Target.Sudo = false
	}
	dir, err := os.MkdirTemp("", "sdw-armor-")
	if err != nil {
		return nil, model.Engine{}, err
	}
	defer os.RemoveAll(dir)
	if err := target.ExtractTo(shadowarmor.Profile, "profile", filepath.Join(dir, "profile")); err != nil {
		return nil, model.Engine{}, fmt.Errorf("stage profile: %w", err)
	}
	opts := engine.ExecOptions{
		ProfileDir: filepath.Join(dir, "profile"),
		TargetURI:  o.Target.String(),
		Controls:   ids,
		InputFile:  filepath.Join(dir, "inputs.yml"),
		ReportPath: filepath.Join(dir, "report.json"),
		Sudo:       o.Target.Sudo,
		Identity:   o.Target.Identity,
		Progress:   o.OnEvent,
	}
	if err := os.WriteFile(opts.InputFile, inputsYAML, 0o600); err != nil {
		return nil, model.Engine{}, err
	}
	if waivers != nil {
		opts.WaiverFile = filepath.Join(dir, "waivers.yml")
		if err := os.WriteFile(opts.WaiverFile, waivers, 0o600); err != nil {
			return nil, model.Engine{}, err
		}
	}
	if o.Target.SudoPassword != "" && o.Target.Kind != target.Docker {
		opts.ConfigFile = filepath.Join(dir, "config.json")
		cfg := fmt.Sprintf(`{"version":"1.1","cli_options":{"sudo_password":%q}}`, o.Target.SudoPassword)
		if err := os.WriteFile(opts.ConfigFile, []byte(cfg), 0o600); err != nil {
			return nil, model.Engine{}, err
		}
	}
	if le.docker != nil {
		d := le.docker
		run := engine.DockerRun{WorkDir: dir, DockerTarget: o.Target.Kind == target.Docker}
		if o.Target.Kind == target.SSH {
			ssh, keys := sshSettings(ctx, o.Target)
			opts.SSH = ssh
			run.ReadOnly = keys
		}
		o.progress("cinc-auditor %s (docker %s) auditing %s (%d controls)", d.Version, d.Image, o.Target, len(ids))
		raw, err := d.Exec(ctx, run, opts, o.EngineLog)
		if err != nil {
			return nil, model.Engine{}, err
		}
		return raw, model.Engine{Name: "cinc-auditor", Version: d.Version, Mode: "docker", Image: d.Ref()}, nil
	}
	e := le.native
	mode := "local"
	if o.Target.Kind != target.Local {
		mode = "remote"
	}
	o.progress("%s %s auditing %s (%d controls, %s mode)", e.Name, e.Version, o.Target, len(ids), mode)
	raw, err := e.Exec(ctx, opts, o.EngineLog)
	if err != nil {
		return nil, model.Engine{}, err
	}
	return raw, model.Engine{Name: e.Name, Version: e.Version, Mode: mode}, nil
}

// sshSettings resolves how the system ssh client reaches the target, for an
// engine that cannot read ~/.ssh/config itself (the Docker engine), and the
// key files it must be able to read.
func sshSettings(ctx context.Context, t *target.Target) (*engine.SSHSettings, []string) {
	s := &engine.SSHSettings{Host: t.Host, User: t.User, Port: t.Port}
	if c, err := t.ResolveSSH(ctx); err == nil {
		if c.HostName != "" {
			s.Host = c.HostName
		}
		if c.User != "" {
			s.User = c.User
		}
		if c.Port != 0 {
			s.Port = c.Port
		}
		s.KeyFiles = c.IdentityFile
		s.ProxyCommand = c.ProxyCommand
		if c.ProxyJump != "" {
			// First hop only: user@host:port.
			hop := strings.Split(c.ProxyJump, ",")[0]
			if u, err := url.Parse("ssh://" + hop); err == nil {
				s.BastionHost = u.Hostname()
				if u.User != nil {
					s.BastionUser = u.User.Username()
				}
				if p, err := strconv.Atoi(u.Port()); err == nil {
					s.BastionPort = p
				}
			}
		}
	}
	if t.Identity != "" {
		if abs, err := filepath.Abs(t.Identity); err == nil {
			s.KeyFiles = append([]string{abs}, s.KeyFiles...)
		}
	}
	return s, s.KeyFiles
}

func runOnTarget(ctx context.Context, o Options, ids []string, inputsYAML, waivers []byte) ([]byte, model.Engine, error) {
	t := o.Target
	o.progress("connecting to %s", t)
	if _, err := t.Probe(ctx); err != nil {
		return nil, model.Engine{}, err
	}
	path, ok := t.Has(ctx, "cinc-auditor")
	if !ok {
		path, ok = t.Has(ctx, "inspec")
	}
	if !ok {
		copts := cinc.Options{Version: o.CINCVersion, Packages: o.CINCPackages, Log: o.EngineLog, Progress: o.Progress}
		if !o.BootstrapCINC && copts.PackageFor(cinc.Auditor) == "" {
			return nil, model.Engine{}, fmt.Errorf("%w (%s): install it (sdw-armor install-cinc %s --sudo), or re-run with --bootstrap-cinc to let this scan install a SHA-256 verified package", ErrEngineMissingOnTarget, t, t)
		}
		if err := Bootstrap(ctx, t, cinc.Auditor, copts); err != nil {
			return nil, model.Engine{}, err
		}
		if path, ok = t.Has(ctx, "cinc-auditor"); !ok {
			return nil, model.Engine{}, fmt.Errorf("cinc-auditor still not found on %s after bootstrap", t)
		}
	}
	ver, _ := t.Output(ctx, target.Quote(path)+" version 2>/dev/null | head -1", false)
	name := "cinc-auditor"
	if strings.Contains(filepath.Base(path), "inspec") {
		name = "inspec"
	}
	files := map[string][]byte{"inputs.yml": inputsYAML}
	opts := engine.ExecOptions{Controls: ids, InputFile: "inputs.yml", Progress: o.OnEvent}
	if waivers != nil {
		files["waivers.yml"] = waivers
		opts.WaiverFile = "waivers.yml"
	}
	o.progress("%s %s auditing %s on the target (%d controls)", name, strings.TrimSpace(ver), t, len(ids))
	upload := func(dir string) error { return t.Upload(ctx, shadowarmor.Profile, "profile", dir) }
	raw, err := engine.OnTarget(ctx, t, path, upload, opts, files, o.EngineLog)
	if err != nil {
		return nil, model.Engine{}, err
	}
	return raw, model.Engine{Name: name, Version: versionOnly(ver), Mode: "on-target"}, nil
}

var semverRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

func versionOnly(s string) string {
	if v := semverRe.FindString(s); v != "" {
		return v
	}
	return strings.TrimSpace(s)
}

// Bootstrap installs a CINC project (cinc.Auditor or cinc.Client) on the
// target: a SHA-256 verified package installed with dpkg/rpm, never an
// installer script. Only ever called on explicit request.
func Bootstrap(ctx context.Context, t *target.Target, project string, o cinc.Options) error {
	m, err := cinc.Install(ctx, t, project, o)
	if err != nil {
		return err
	}
	if o.Progress != nil {
		o.Progress(strings.Join(strings.Fields(fmt.Sprintf("%s %s installed on %s", cinc.Label(project), m.Version, t)), " "))
	}
	return nil
}

var sourceRe = regexp.MustCompile(`controls/[^:]+\.rb`)

// Build merges engine results with the catalog into a qualified report.
func Build(cat *catalog.Catalog, ir *engine.InspecReport, selected []catalog.Control, f catalog.Filter, inputs map[string]any, lens string) *model.Report {
	byID := map[string]engine.InspecControl{}
	profVer := ""
	for _, p := range ir.Profiles {
		if profVer == "" {
			profVer = p.Version
		}
		for _, c := range p.Controls {
			byID[c.ID] = c
		}
	}
	rep := &model.Report{
		Schema:      model.Schema,
		Tool:        model.Tool{Name: "Shadow-Armor", Version: version.Version, Commit: version.Commit},
		GeneratedAt: time.Now().UTC().Truncate(time.Second),
		Target:      model.Target{Platform: model.Platform{Name: ir.Platform.Name, Release: ir.Platform.Release}},
		Profile:     profVer,
		Selection:   model.Selection{Level: levelOr2(f.Level), Pillars: f.Pillars, Standard: stdOrAll(f.Standard), Count: len(selected)},
		Inputs:      inputs,
		Weights:     cat.SeverityWeights,
	}
	for _, p := range cat.Pillars {
		rep.Pillars = append(rep.Pillars, model.PillarMeta{ID: p.ID, Key: p.Key, Title: p.Title, TitleFR: p.TitleFR})
	}
	for _, k := range catalog.StandardKeys {
		rep.Standards = append(rep.Standards, model.StandardMeta{Key: k, Name: cat.StandardLabel(k)})
	}
	for _, c := range selected {
		cr := model.ControlResult{
			ID: c.ID, Title: c.Title, Pillar: c.Pillar, Severity: c.Severity, Level: c.Level, Scope: c.Scope,
			Rationale: c.Rationale, Check: c.Check, Map: c.Map, Remediation: c.Remediation,
		}
		ic, ok := byID[c.ID]
		if !ok {
			cr.Status = model.Error
			cr.Reason = "the engine returned no result for this control"
		} else {
			v := verdict.Classify(ic, c.DeclaredType())
			cr.Status, cr.Qualifier, cr.Reason, cr.Evidence, cr.Proof = v.Status, v.Qualifier, v.Reason, v.Evidence, v.Proof
			cr.Waiver = verdict.WaiverOf(ic.WaiverData)
			if m := sourceRe.FindString(ic.SourceLocation.Ref); m != "" {
				cr.Source = fmt.Sprintf("profile/%s:%d", m, ic.SourceLocation.Line)
			}
			if strings.Contains(cr.Reason, "not applicable inside a container") {
				rep.Target.Container = containerKind(cr.Reason)
			}
		}
		rep.Controls = append(rep.Controls, cr)
	}
	sort.SliceStable(rep.Controls, func(i, j int) bool { return rep.Controls[i].ID < rep.Controls[j].ID })
	rep.Summary = score.Compute(rep.Controls, rep.Weights, lens)
	return rep
}

var containerRe = regexp.MustCompile(`inside a container \(([^)]+)\)`)

func containerKind(reason string) string {
	if m := containerRe.FindStringSubmatch(reason); m != nil {
		return m[1]
	}
	return "container"
}

func levelOr2(l int) int {
	if l == 0 {
		return 2
	}
	return l
}

func stdOrAll(s string) string {
	if s == "" {
		return "all"
	}
	return s
}

// ProfileFS exposes the embedded profile (for export).
func ProfileFS() fs.FS { return shadowarmor.Profile }
