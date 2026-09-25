package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/catalog"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/harden"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/score"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/target"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/ui"
)

func (a *app) harden(args []string) error {
	f := newFlags("harden", `Harden as code: plan the fixes of failing controls, opt in per rule, converge with a native Chef run.

Flow: audit (or --from a saved report) -> candidates with an automatic fix ->
you accept or refuse each rule (or --rules / --all with --yes) -> lockout
guards -> cinc-client --local-mode converges the plan -> the fixed controls
are audited again and the new grade is shown.`, "[target] [flags]")
	sf := scanFlags{forHarden: true}
	sf.register(f)
	var rules, pillarSel multi
	rules.split, pillarSel.split = true, true
	var from, planOut, planIn string
	var all, yes, dryRun, noVerify, force, reboot bool
	var rebootTimeout time.Duration
	var outputs multi
	f.StringVar(&from, "from", "", "use a saved JSON report instead of auditing first")
	f.Var(&rules, "rules", "only these control IDs (comma separated)")
	f.Var(&pillarSel, "fix-pillar", "only candidates of these pillars")
	f.BoolVar(&all, "all", false, "select every candidate (still asks for confirmation unless --yes)")
	f.BoolVar(&yes, "yes", false, "do not prompt: apply the selection given by --rules/--all/--plan")
	f.BoolVar(&dryRun, "dry-run", false, "Chef why-run: show what would change, change nothing")
	f.StringVar(&planOut, "plan-out", "", "write the plan to this file and stop (review it, then apply it with --plan)")
	f.StringVar(&planIn, "plan", "", "apply exactly this plan file")
	f.BoolVar(&noVerify, "no-verify", false, "do not re-audit the fixed controls after applying")
	f.BoolVar(&force, "force", false, "also apply the rules a safety guard stopped (you have another way in)")
	f.BoolVar(&reboot, "reboot", false, "after applying and re-auditing, reboot the target (ssh:// only, asks first unless --yes), wait for the new boot and re-scan: passes that survive are reboot-proven, pending fixes are confirmed, anything lost is flagged")
	f.DurationVar(&rebootTimeout, "reboot-timeout", 15*time.Minute, "how long to wait for the target to come back with --reboot")
	f.Var(&outputs, "o", "write the post-harden report: format:path (repeatable)")
	pos, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return usagef("one target at a time")
	}
	targetArg := ""
	if len(pos) == 1 {
		targetArg = pos[0]
	}
	specs, err := parseOutputs(outputs.vals, "")
	if err != nil {
		return err
	}
	ctx, cancel := signalContext(sf.timeout)
	defer cancel()
	l := a.look()
	a.sudoHint = sf.sudo
	a.banner(sf.quiet)
	in := bufio.NewReader(os.Stdin)
	interactive := isTerminal(os.Stdin) && !yes

	var plan *harden.Plan
	var base *model.Report

	if planIn != "" {
		if plan, err = harden.Load(planIn); err != nil {
			return exitError{ExitUsage, err}
		}
		if targetArg == "" {
			targetArg = plan.Target
		} else if targetArg != plan.Target {
			return usagef("the plan was made for %s, not %s", plan.Target, targetArg)
		}
	}
	o, err := a.scanOptions(&sf, targetArg)
	if err != nil {
		return err
	}
	t := o.Target
	if reboot {
		switch {
		case dryRun || noVerify || planOut != "":
			return usagef("--reboot proves applied fixes: it cannot be combined with --dry-run, --no-verify or --plan-out")
		case t.Kind == target.Local:
			return usagef("--reboot cannot reboot the machine sdw-armor runs on: save a report (-o json:before.json), reboot, then run `sdw-armor scan --reboot-baseline before.json`")
		case t.Kind == target.Docker:
			return usagef("--reboot needs a host: a container has no boot of its own (it shares the host kernel)")
		}
	}

	if plan == nil {
		switch {
		case from != "":
			if base, err = loadReport(from); err != nil {
				return exitError{ExitUsage, err}
			}
			if targetArg != "" && base.Target.URI != t.String() {
				return usagef("the report %s is for %s, not %s", from, base.Target.URI, t)
			}
			if targetArg == "" {
				if o, err = a.scanOptions(&sf, base.Target.URI); err != nil {
					return err
				}
				t = o.Target
			}
		default:
			if !sf.quiet {
				fmt.Fprintln(a.stderr, "  "+l.muted(fmt.Sprintf("auditing %s first (--from reuses a saved report)", t)))
			}
			if base, err = a.runScan(ctx, &sf, o); err != nil {
				return err
			}
		}
		cands := harden.Candidates(base)
		if len(pillarSel.vals) > 0 {
			ids, err := a.parsePillars(pillarSel.vals)
			if err != nil {
				return err
			}
			keep := map[int]bool{}
			for _, id := range ids {
				keep[id] = true
			}
			cands = filterControls(cands, func(c model.ControlResult) bool { return keep[c.Pillar] })
		}
		if len(rules.vals) > 0 {
			want := map[string]bool{}
			for _, r := range rules.vals {
				ctl, ok := a.cat.Control(r)
				if !ok {
					return usagef("unknown control %q", r)
				}
				if !ctl.Remediation.Auto {
					return usagef("%s has no automatic remediation (see `sdw-armor explain %s`)", ctl.ID, ctl.ID)
				}
				want[ctl.ID] = true
			}
			cands = filterControls(cands, func(c model.ControlResult) bool { return want[c.ID] })
			for id := range want {
				if !containsID(cands, id) {
					fmt.Fprintln(a.stderr, "  "+l.ok(l.steel(id+" is already compliant (or waived, or not applicable): nothing to do")))
				}
			}
		}
		manual := harden.ManualOnly(base)
		if len(cands) == 0 {
			fmt.Fprintln(a.stdout, "\n  "+l.ok(l.bold(ui.Green, "Nothing to harden automatically.")))
			a.printManual(manual)
			return nil
		}
		a.hardenIntro(t.String(), base, cands, manual)
		var chosen []model.ControlResult
		switch {
		case len(rules.vals) > 0 || all:
			chosen = cands
			if interactive && !yes && planOut == "" {
				a.showCandidates(cands)
				if !confirm(in, a.stdout, fmt.Sprintf("Apply these %d fixes?", len(cands))) {
					return exitError{ExitOK, errors.New("aborted")}
				}
			}
		case interactive:
			chosen, err = a.pickInteractively(in, cands)
			if err != nil {
				return err
			}
		default:
			a.showCandidates(cands)
			return usagef("no terminal to ask per rule: choose with --rules <ids> or --all, and --yes to apply (or --plan-out to save the plan)")
		}
		if len(chosen) == 0 {
			fmt.Fprintln(a.stdout, "\n  "+l.muted("no rule selected, nothing changed."))
			return nil
		}
		inputs, _ := a.parseInputs(&sf)
		if plan, err = harden.New(a.cat, base, chosen, inputs); err != nil {
			return err
		}
	}

	a.showPlan(plan)
	if planOut != "" {
		if err := plan.Save(planOut); err != nil {
			return err
		}
		sudoHint := ""
		if t.Kind == "ssh" {
			sudoHint = " --sudo"
		}
		fmt.Fprintln(a.stdout, "\n  "+l.ok(l.ink("plan written to "+planOut))+l.muted(": review it, then apply it with"))
		fmt.Fprintln(a.stdout, "    "+l.paint(ui.Violet, "❯ ")+l.cyan(fmt.Sprintf("sdw-armor harden %s --plan %s%s", plan.Target, planOut, sudoHint)))
		return nil
	}

	// Safety guards.
	if _, err := t.Probe(ctx); err != nil {
		return exitError{ExitPrereq, err}
	}
	user, _ := t.Output(ctx, "id -un", false)
	if user != "root" && !t.Sudo && t.Kind != "docker" {
		return exitError{ExitPrereq, fmt.Errorf("hardening needs root on %s (connected as %s): pass --sudo", t, user)}
	}
	// A failed guard leaves its rule out of this run; --force keeps it.
	if stopped := a.showGuards(harden.Guards(ctx, t, plan), force); len(stopped) > 0 && !force {
		plan.Drop(stopped)
		if len(plan.Items) == 0 {
			return exitError{ExitPolicy, errors.New("nothing left to apply: a safety guard stopped every chosen rule. Do what it says, or pass --force if you have another way in (console, out-of-band)")}
		}
	}
	if interactive && planIn != "" && !confirm(in, a.stdout, "Apply this plan?") {
		return exitError{ExitOK, errors.New("aborted")}
	}

	var progress func(string)
	if !sf.quiet {
		progress = func(s string) { fmt.Fprintln(a.stderr, "   "+l.paint(ui.Cyan, "›")+" "+l.steel(s)) }
	}
	fmt.Fprintln(a.stdout)
	title := "CONVERGE"
	if dryRun {
		title = "WHY-RUN"
	}
	fmt.Fprintln(a.stdout, l.section(title, "cinc-client --local-mode on "+t.String()))
	chefOut := a.stdout
	var view *chefView
	if !sf.verbose {
		view = a.newChefView(dryRun)
		chefOut = view
	}
	aopts := harden.Options{WhyRun: dryRun, BootstrapCINC: sf.bootstrap, CINCVersion: sf.cincVersion, CINCPackages: sf.cincPkgs.vals, Out: chefOut, Progress: progress}
	if view != nil {
		aopts.OnConverge = view.begin
	}
	err = harden.Apply(ctx, t, plan, aopts)
	if view != nil {
		view.end(err != nil && !errors.Is(err, harden.ErrClientMissing))
	}
	if err != nil {
		if errors.Is(err, harden.ErrClientMissing) {
			return exitError{ExitPrereq, err}
		}
		return exitError{ExitEngineError, err}
	}
	if dryRun {
		fmt.Fprintln(a.stdout, "\n  "+l.paint(ui.Amber, "~")+" "+l.ink("why-run complete: nothing was changed.")+l.muted(" Apply with the same command without --dry-run."))
		return nil
	}
	if noVerify {
		fmt.Fprintln(a.stdout, "\n  "+l.ok(l.ink("applied."))+l.muted(" Re-audit with: sdw-armor scan "+t.String()))
		return nil
	}

	// Closed loop: audit the fixed controls again.
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, l.section("RE-AUDIT", fmt.Sprintf("the %d fixed control(s)", len(plan.Items))))
	vo := o
	vo.Filter = catalog.Filter{IDs: plan.Controls(), Level: 2}
	after, err := a.runScan(ctx, &sf, vo)
	if err != nil {
		return err
	}
	merged := mergeReports(base, after)
	still := a.showOutcome(plan, after, base, merged)
	if reboot {
		return a.rebootAndProve(ctx, &sf, o, plan, base, merged, specs, interactive && !yes, in, rebootTimeout)
	}
	if len(specs) > 0 && merged != nil {
		if err := a.writeOutputs(specs, merged, false, true); err != nil {
			return err
		}
	}
	if still > 0 {
		return exitError{ExitPolicy, fmt.Errorf("%d control(s) still not compliant", still)}
	}
	return nil
}

func filterControls(in []model.ControlResult, keep func(model.ControlResult) bool) []model.ControlResult {
	var out []model.ControlResult
	for _, c := range in {
		if keep(c) {
			out = append(out, c)
		}
	}
	return out
}

func containsID(cs []model.ControlResult, id string) bool {
	for _, c := range cs {
		if c.ID == id {
			return true
		}
	}
	return false
}

func confirm(in *bufio.Reader, w io.Writer, q string) bool {
	fmt.Fprintf(w, "\n  ? %s [y/N] › ", q)
	line, _ := in.ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes" || line == "o" || line == "oui"
}

func mergeReports(base, after *model.Report) *model.Report {
	if base == nil {
		return after
	}
	m := *base
	idx := map[string]model.ControlResult{}
	for _, c := range after.Controls {
		idx[c.ID] = c
	}
	m.Controls = make([]model.ControlResult, len(base.Controls))
	for i, c := range base.Controls {
		if n, ok := idx[c.ID]; ok {
			m.Controls[i] = n
		} else {
			m.Controls[i] = c
		}
	}
	m.GeneratedAt = after.GeneratedAt
	if after.Target.Host != nil {
		m.Target.Host = after.Target.Host
	}
	m.Summary = score.Compute(m.Controls, m.Weights, base.Summary.Lens)
	return &m
}
