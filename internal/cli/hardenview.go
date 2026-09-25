package cli

import (
	"bufio"
	"fmt"
	"sort"
	"strings"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/harden"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/report"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/score"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/ui"
)

// hardenIntro frames what harden can do on this target.
func (a *app) hardenIntro(t string, base *model.Report, cands, manual []model.ControlResult) {
	l := a.look()
	proj, _ := score.Projected(base.Controls, base.Weights, base.Summary.Lens)
	lines := []string{
		"",
		"  " + l.muted("now        ") + l.gradeScore(base.Summary) + l.muted("  ·  ") + l.ink(fmt.Sprintf("%d automatic fix(es)", len(cands))) + l.muted(fmt.Sprintf(" · %d need a human", len(manual))),
		"  " + l.muted("harden path") + " " + l.gradeScore(base.Summary) + " " + l.gradient("━━━━━━►", ui.GradeColor(base.Summary.Grade), ui.GradeColor(proj.Grade)) + " " + l.gradeScore(proj) + l.muted("  every automatic fix and pending reboot, projected"),
		"",
	}
	fmt.Fprintln(a.stdout)
	for _, s := range l.box(l.gradient("HARDEN", ui.Brand...)+l.muted(" · ")+l.bold(ui.Ink, t), "", lines, ui.Faint) {
		fmt.Fprintln(a.stdout, s)
	}
}

// candidateRow is one candidate fix, one line.
func (a *app) candidateRow(c model.ControlResult) string {
	l := a.look()
	state := string(c.Status)
	if c.Qualifier != "" && c.Qualifier != model.Durable {
		state += "/" + string(c.Qualifier)
	}
	left := fmt.Sprintf("   %s %s  %s", ui.Pad(l.sev(c.Severity), 8), l.bold(ui.SeverityColor(c.Severity), c.ID), l.ink(c.Title))
	return ui.Pad(ui.Trunc(left, l.w-20), l.w-20) + " " + l.muted(state)
}

func (a *app) showCandidates(cands []model.ControlResult) {
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, a.look().section("CANDIDATE FIXES", fmt.Sprintf("%d", len(cands))))
	for _, c := range cands {
		fmt.Fprintln(a.stdout, a.candidateRow(c))
	}
}

// pickInteractively shows one card per rule and asks.
func (a *app) pickInteractively(in *bufio.Reader, cands []model.ControlResult) ([]model.ControlResult, error) {
	l := a.look()
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, "  "+l.muted("Opt in rule by rule: ")+l.cyan("y")+l.muted(" apply · ")+l.cyan("n")+l.muted(" skip · ")+l.cyan("a")+l.muted(" this and all remaining · ")+l.cyan("q")+l.muted(" stop asking · ")+l.cyan("?")+l.muted(" details"))
	var chosen []model.ControlResult
	for i := 0; i < len(cands); i++ {
		c := cands[i]
		ctl, _ := a.cat.Control(c.ID)
		sc := ui.SeverityColor(c.Severity)
		now := string(c.Status)
		if c.Qualifier != "" {
			now += "/" + string(c.Qualifier)
		}
		e := firstFailing(c)
		rows := [][2]string{{"now", l.paint(ui.Red, now) + l.muted(" · ") + l.paint(ui.Amber, e.Message)}, {"checked", l.steel(ui.Trunc(report.EvidenceDesc(e), l.w-24))}, {"fix", l.ink(ctl.Remediation.Summary)}}
		if e.Message == "" {
			rows[0][1] = l.paint(ui.Red, now)
		}
		if ctl.Remediation.Risk != "" {
			rows = append(rows, [2]string{"risk", l.paint(ui.Amber, ctl.Remediation.Risk)})
		}
		if ctl.Remediation.Reboot {
			rows = append(rows, [2]string{"reboot", l.steel("takes full effect after a reboot")})
		}
		var body []string
		for _, r := range l.kv(rows) {
			body = append(body, wrapStyled(r, l.w-6)...)
		}
		title := l.muted(fmt.Sprintf("%d/%d", i+1, len(cands))) + "  " + l.bold(sc, c.ID) + " " + l.sev(c.Severity) + "  " + l.ink(c.Title)
		fmt.Fprintln(a.stdout)
		for _, s := range l.box(title, l.muted("[y] apply  [n] skip  [a] all remaining  [q] stop  [?] details"), body, ui.Mix(sc, ui.Faint, 0.55)) {
			fmt.Fprintln(a.stdout, s)
		}
		for {
			fmt.Fprint(a.stdout, "  "+l.paint(ui.Violet, "❯")+" apply "+l.bold(sc, c.ID)+"? ")
			line, err := in.ReadString('\n')
			if err != nil && line == "" {
				return chosen, nil
			}
			switch strings.ToLower(strings.TrimSpace(line)) {
			case "y", "yes", "o", "oui":
				chosen = append(chosen, c)
				fmt.Fprintln(a.stdout, "    "+l.ok(l.steel("added to the plan")))
			case "n", "no", "non", "":
				fmt.Fprintln(a.stdout, "    "+l.muted("· skipped"))
			case "a", "all":
				fmt.Fprintln(a.stdout, "    "+l.ok(l.steel(fmt.Sprintf("added, with the %d remaining", len(cands)-i-1))))
				return append(chosen, cands[i:]...), nil
			case "q", "quit":
				return chosen, nil
			case "?", "d", "details":
				for _, e := range c.Evidence {
					if e.Status == "failed" || e.Status == "error" {
						fmt.Fprintln(a.stdout, "    "+l.faint("•")+" "+l.steel(report.EvidenceLine(e)))
					}
				}
				for _, act := range ctl.Remediation.Actions {
					fmt.Fprintln(a.stdout, "    "+l.cyan("→")+" "+l.steel(harden.Describe(act)))
				}
				continue
			default:
				continue
			}
			break
		}
	}
	return chosen, nil
}

func firstFailing(c model.ControlResult) model.Evidence {
	for _, e := range c.Evidence {
		if e.Status == "failed" || e.Status == "error" {
			return e
		}
	}
	if len(c.Evidence) > 0 {
		return c.Evidence[0]
	}
	return model.Evidence{Desc: c.Reason}
}

// wrapStyled wraps a styled "label  value" row; continuation lines are
// indented under the value.
func wrapStyled(s string, w int) []string {
	if ui.Width(s) <= w {
		return []string{s}
	}
	return []string{ui.Trunc(s, w)}
}

// showPlan draws the plan as a tree of controls and their actions.
func (a *app) showPlan(plan *harden.Plan) {
	l := a.look()
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, l.section("PLAN", fmt.Sprintf("%s · %d control(s) · run %s", plan.Target, len(plan.Items), plan.RunID)))
	for i, it := range plan.Items {
		last := i == len(plan.Items)-1
		fmt.Fprintln(a.stdout, "   "+l.paint(ui.Violet, "◆")+" "+l.bold(ui.Ink, it.Control)+"  "+l.ink(it.Title))
		stem := l.faint("│")
		if last {
			stem = " "
		}
		n := len(it.Actions)
		if it.Risk != "" {
			n++
		}
		k := 0
		for _, act := range it.Actions {
			k++
			br := "├─"
			if k == n {
				br = "╰─"
			}
			fmt.Fprintln(a.stdout, "   "+stem+" "+l.faint(br)+" "+l.steel(ui.Trunc(harden.Describe(act), l.w-12)))
		}
		if it.Risk != "" {
			// The risk is read in full: it says what stops working.
			for j, r := range ui.Wrap(it.Risk, l.w-14) {
				lead := l.faint("╰─") + " " + l.paint(ui.Amber, "! ")
				if j > 0 {
					lead = "     "
				}
				fmt.Fprintln(a.stdout, "   "+stem+" "+lead+l.paint(ui.Amber, r))
			}
		}
	}
	for _, id := range plan.NotAutomated {
		fmt.Fprintln(a.stdout, "   "+l.warn(l.steel(fmt.Sprintf("%s: no automatic fix on %s %s (sdw-armor explain %s)", id, plan.Platform.Name, plan.Platform.Release, id))))
	}
	if plan.NeedsReboot() {
		fmt.Fprintln(a.stdout, "   "+l.paint(ui.Sky, "◐ ")+l.steel("some settings only take effect after a reboot: they read 'pending' until then (or use --reboot)"))
	}
}

// showGuards prints the safety guards and returns the controls they stop.
func (a *app) showGuards(gs []harden.GuardResult, force bool) []string {
	if len(gs) == 0 {
		return nil
	}
	l := a.look()
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, l.section("SAFETY GUARDS", "never lock you out, never cut what runs"))
	var stopped []string
	seen := map[string]bool{}
	for _, g := range gs {
		mark := l.paint(ui.Green, "✓")
		if !g.OK {
			mark = l.paint(ui.Red, "✗")
			if !seen[g.Control] {
				seen[g.Control] = true
				stopped = append(stopped, g.Control)
			}
		}
		lines := ui.Wrap(g.Detail, max(30, l.w-38))
		for i, d := range lines {
			if i == 0 {
				fmt.Fprintln(a.stdout, "   "+mark+" "+ui.Pad(l.muted(g.Control), 9)+" "+ui.Pad(l.ink(g.Name), 21)+" "+l.steel(d))
				continue
			}
			fmt.Fprintln(a.stdout, strings.Repeat(" ", 37)+l.steel(d))
		}
	}
	if len(stopped) > 0 {
		verb := "left out of this run"
		if force {
			verb = "applied anyway (--force)"
		}
		fmt.Fprintln(a.stdout, "   "+l.paint(ui.Amber, "!")+" "+l.ink(strings.Join(stopped, ", ")+" "+verb))
	}
	return stopped
}

func (a *app) printManual(manual []model.ControlResult) {
	if len(manual) == 0 {
		return
	}
	l := a.look()
	sort.SliceStable(manual, func(i, j int) bool { return manual[i].ID < manual[j].ID })
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, l.section("NEEDS A HUMAN", fmt.Sprintf("%d · sdw-armor explain <id> gives the steps", len(manual))))
	for _, c := range manual {
		fmt.Fprintln(a.stdout, a.candidateRow(c))
	}
}

// showOutcome compares the fixed controls before and after, and the grade.
func (a *app) showOutcome(plan *harden.Plan, after, base, merged *model.Report) int {
	l := a.look()
	res := map[string]model.ControlResult{}
	for _, c := range after.Controls {
		res[c.ID] = c
	}
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, l.section("RESULT", "the fixed controls, audited again"))
	still := 0
	for _, it := range plan.Items {
		c := res[it.Control]
		now := string(c.Status)
		if c.Qualifier != "" {
			now += " · " + string(c.Qualifier)
		}
		mark := l.paint(ui.Green, "✓")
		nowS := l.paint(ui.Green, now)
		switch {
		case c.Status == model.Pass && c.Qualifier == model.Durable:
		case c.Status == model.Fail && c.Qualifier == model.Pending:
			mark = l.paint(ui.Sky, "◐")
			nowS = l.paint(ui.Sky, "pending "+strings.TrimPrefix(pendingOf(c), "pending "))
			still++
		default:
			mark = l.paint(ui.Red, "✗")
			nowS = l.paint(ui.Red, now)
			still++
		}
		left := fmt.Sprintf("   %s %s  %s", mark, l.bold(ui.Ink, it.Control), l.ink(it.Title))
		right := l.muted(it.Before) + " " + l.faint("━━►") + " " + nowS
		room := l.w - ui.Width(right) - 2
		fmt.Fprintln(a.stdout, ui.Pad(ui.Trunc(left, room), room)+" "+right)
	}
	if base != nil && merged != nil {
		fmt.Fprintln(a.stdout)
		for _, s := range l.transition(base.Summary, merged.Summary, "before", "after harden") {
			fmt.Fprintln(a.stdout, s)
		}
	}
	fmt.Fprintln(a.stdout)
	if still > 0 {
		fmt.Fprintln(a.stdout, "   "+l.paint(ui.Amber, "!")+" "+l.steel(fmt.Sprintf("%d control(s) not durably compliant yet: 'pending' ones after a reboot (or --reboot), the others with sdw-armor explain <id>", still)))
	}
	fmt.Fprintln(a.stdout, "   "+l.muted(fmt.Sprintf("journal /var/lib/shadow-armor/journal/%s.json · backups /var/lib/shadow-armor/backup", plan.RunID)))
	fmt.Fprintln(a.stdout)
	return still
}

func pendingOf(c model.ControlResult) string {
	if c.Remediation.Reboot {
		return "reboot"
	}
	return "reboot or reload"
}
