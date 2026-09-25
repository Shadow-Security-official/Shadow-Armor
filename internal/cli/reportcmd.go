package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/catalog"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/diff"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/score"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/ui"
)

func loadReport(path string) (*model.Report, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r model.Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("%s: not a Shadow-Armor JSON report: %v", path, err)
	}
	if r.Schema != model.Schema {
		return nil, fmt.Errorf("%s: unsupported report schema %q (expected %s)", path, r.Schema, model.Schema)
	}
	return &r, nil
}

func (a *app) report(args []string) error {
	f := newFlags("report", "Re-render a saved JSON report in another format or through another standard lens.", "<report.json> [flags]")
	var outputs multi
	var format, lens, failUnder string
	var verbose, noColor bool
	f.Var(&outputs, "o", "write format:path (repeatable)")
	f.StringVar(&format, "format", "text", "format printed on stdout ('none' for files only)")
	f.StringVar(&lens, "lens", "", "re-grade through one standard: "+strings.Join(catalog.StandardKeys, ", ")+" or all")
	f.StringVar(&failUnder, "fail-under", "", "exit 1 when the grade is worse than this")
	f.BoolVar(&verbose, "verbose", false, "list passes and non-applicable controls")
	f.BoolVar(&noColor, "no-color", false, "disable colours")
	pos, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("give one JSON report")
	}
	r, err := loadReport(pos[0])
	if err != nil {
		return exitError{ExitUsage, err}
	}
	if lens != "" {
		if !catalog.ValidStandard(lens) {
			return usagef("unknown --lens %q", lens)
		}
		r.Summary = score.Compute(r.Controls, r.Weights, lens)
	}
	if format == "none" {
		format = ""
	}
	specs, err := parseOutputs(outputs.vals, format)
	if err != nil {
		return err
	}
	if err := a.writeOutputs(specs, r, verbose, noColor); err != nil {
		return err
	}
	if failUnder != "" && score.Rank(r.Summary.Grade) > score.Rank(strings.ToUpper(failUnder)) {
		return exitError{ExitPolicy, fmt.Errorf("grade %s is worse than --fail-under %s", r.Summary.Grade, strings.ToUpper(failUnder))}
	}
	return nil
}

func (a *app) diff(args []string) error {
	f := newFlags("diff", "Compare two reports of the same host: fixed, regressed, drifted (durable <-> runtime-only), new failures.", "<before.json> <after.json> [flags]")
	var asJSON, failOnRegression, md, noColor bool
	var lens string
	f.BoolVar(&noColor, "no-color", false, "disable colours")
	f.BoolVar(&asJSON, "json", false, "JSON output")
	f.BoolVar(&md, "markdown", false, "Markdown output")
	f.BoolVar(&failOnRegression, "fail-on-regression", false, "exit 1 when a control regressed or a new failure appeared (CI drift gate)")
	f.StringVar(&lens, "lens", "", "compare through one standard lens")
	pos, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return usagef("give two JSON reports: before and after")
	}
	before, err := loadReport(pos[0])
	if err != nil {
		return exitError{ExitUsage, err}
	}
	after, err := loadReport(pos[1])
	if err != nil {
		return exitError{ExitUsage, err}
	}
	if lens != "" {
		if !catalog.ValidStandard(lens) {
			return usagef("unknown --lens %q", lens)
		}
		before.Summary = score.Compute(before.Controls, before.Weights, lens)
		after.Summary = score.Compute(after.Controls, after.Weights, lens)
	}
	if noColor {
		a.color = false
	}
	d := diff.Compare(before, after)
	switch {
	case asJSON:
		enc := json.NewEncoder(a.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(d); err != nil {
			return err
		}
	case md:
		a.diffMarkdown(d)
	default:
		a.diffText(d)
	}
	if failOnRegression && (len(d.Regressed) > 0 || len(d.New) > 0) {
		return exitError{ExitPolicy, fmt.Errorf("%d regression(s), %d new failure(s)", len(d.Regressed), len(d.New))}
	}
	return nil
}

func gradeScore(s model.Summary) string {
	if s.Score == nil {
		return s.Grade
	}
	return fmt.Sprintf("%s (%.1f)", s.Grade, *s.Score)
}

func (a *app) diffText(d diff.Result) {
	l := a.look()
	w := a.stdout
	fmt.Fprintln(w)
	title := l.gradient("SHADOW-ARMOR DIFF", ui.Brand...) + l.muted(" · ") + l.bold(ui.Ink, d.BeforeTarget)
	if d.BeforeTarget != d.AfterTarget {
		title += l.muted(" → ") + l.bold(ui.Ink, d.AfterTarget)
	}
	var body []string
	body = append(body, "")
	body = append(body, l.transition(d.Before, d.After, "before", "after")...)
	body = append(body, "")
	stat := func(c ui.RGB, n int, label string) string {
		if n == 0 {
			return l.muted(fmt.Sprintf("%d %s", n, label))
		}
		return l.bold(c, fmt.Sprint(n)) + " " + l.steel(label)
	}
	body = append(body, "   "+stat(ui.Green, len(d.Fixed), "fixed")+l.muted(" · ")+stat(ui.Red, len(d.Regressed), "regressed")+l.muted(" · ")+
		stat(ui.Red, len(d.New), "new failures")+l.muted(" · ")+stat(ui.Amber, len(d.Drifted), "drifted")+l.muted(" · ")+stat(ui.Steel, d.StillFailing, "still failing"))
	if d.Rebooted {
		body = append(body, "   "+l.paint(ui.Cyan, "↻ ")+l.steel(fmt.Sprintf("the host rebooted between the two scans: %d pass(es) survived it", d.SurvivedReboot)))
	}
	if d.BeforeTarget != d.AfterTarget {
		body = append(body, "   "+l.warn(l.paint(ui.Amber, "the two reports come from different targets")))
	}
	body = append(body, "")
	for _, s := range l.box(title, "", body, ui.Faint) {
		fmt.Fprintln(w, s)
	}
	group := func(title string, c ui.RGB, mark string, cs []diff.Change) {
		if len(cs) == 0 {
			return
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, l.section(title, fmt.Sprint(len(cs))))
		for _, ch := range cs {
			from, to := orAbsent(ch.Before), orAbsent(ch.After)
			left := fmt.Sprintf("   %s %s %s  %s", l.paint(c, mark), ui.Pad(l.sev(ch.Severity), 8), l.bold(ui.Ink, ch.ID), l.ink(ch.Title))
			right := l.muted(from) + " " + l.faint("━━►") + " " + l.paint(c, to)
			room := l.w - ui.Width(right) - 2
			fmt.Fprintln(w, ui.Pad(ui.Trunc(left, room), room)+" "+right)
		}
	}
	regressed := "REGRESSED"
	if d.Rebooted {
		regressed = "LOST AT THE REBOOT"
	}
	group(regressed, ui.Red, "✗", d.Regressed)
	group("NEW FAILURES", ui.Red, "+", d.New)
	group("FIXED", ui.Green, "✓", d.Fixed)
	group("DRIFTED", ui.Amber, "~", d.Drifted)
	group("NO LONGER AUDITED", ui.Steel, "-", d.Removed)
	fmt.Fprintln(w)
}

func (a *app) diffMarkdown(d diff.Result) {
	w := a.stdout
	fmt.Fprintf(w, "## Shadow-Armor drift: %s → %s\n\n", gradeScore(d.Before), gradeScore(d.After))
	if d.Rebooted {
		fmt.Fprintf(w, "The host rebooted between the two scans: %d pass(es) survived it, regressions were lost at the reboot.\n\n", d.SurvivedReboot)
	}
	fmt.Fprintf(w, "| fixed | regressed | new failures | drifted | still failing |\n|---|---|---|---|---|\n| %d | %d | %d | %d | %d |\n\n",
		len(d.Fixed), len(d.Regressed), len(d.New), len(d.Drifted), d.StillFailing)
	for _, g := range []struct {
		t  string
		cs []diff.Change
	}{{"Regressed", d.Regressed}, {"New failures", d.New}, {"Fixed", d.Fixed}, {"Drifted", d.Drifted}} {
		if len(g.cs) == 0 {
			continue
		}
		fmt.Fprintf(w, "### %s\n\n", g.t)
		for _, c := range g.cs {
			fmt.Fprintf(w, "- `%s` %s (%s): %s → %s\n", c.ID, c.Title, c.Severity, orAbsent(c.Before), orAbsent(c.After))
		}
		fmt.Fprintln(w)
	}
}

func orAbsent(s string) string {
	if s == "" {
		return "absent"
	}
	return s
}
