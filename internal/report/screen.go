package report

import (
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/score"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/ui"
)

// TextOptions shape the terminal report.
type TextOptions struct {
	Profile  ui.Profile // colours (ui.NoColor for files and pipes)
	Width    int        // terminal width (default 100)
	Verbose  bool       // list every failure, the passes and the non-applicable controls
	HideNext bool       // no "next steps" footer
	// MaxFailures listed before "… N more" (default 12; Verbose lists all).
	MaxFailures int
	// Sudo adds --sudo to the suggested commands.
	Sudo bool
}

// Text writes the terminal report: a grade card, findings and proof
// panels, the pillars, the path to a better grade, the failures and what to
// do next.
func Text(w io.Writer, r *model.Report, o TextOptions) {
	s := newScreen(r, o)
	s.header()
	s.panels()
	s.pillars()
	s.projection()
	s.failures()
	s.runtimeOnly()
	s.errorsAndWaivers()
	if o.Verbose {
		s.passes()
	}
	if !o.HideNext {
		s.next()
	}
	for _, l := range s.out {
		fmt.Fprintln(w, strings.TrimRight(l, " "))
	}
}

type screen struct {
	r     *model.Report
	o     TextOptions
	p     ui.Profile
	w     int // content width
	out   []string
	fails []model.ControlResult
	errs  []model.ControlResult
	rto   []model.ControlResult
	pass  []model.ControlResult
	skip  []model.ControlResult
	waive []model.ControlResult
}

func newScreen(r *model.Report, o TextOptions) *screen {
	w := o.Width
	if w <= 0 {
		w = 100
	}
	w = min(w-2, 118)
	if w < 60 {
		w = 60
	}
	s := &screen{r: r, o: o, p: o.Profile, w: w}
	for _, c := range r.Controls {
		if !score.InLens(c, r.Summary.Lens) {
			continue
		}
		switch c.Status {
		case model.Fail:
			s.fails = append(s.fails, c)
		case model.Error:
			s.errs = append(s.errs, c)
		case model.Pass:
			if c.Qualifier == model.RuntimeOnly {
				s.rto = append(s.rto, c)
			} else {
				s.pass = append(s.pass, c)
			}
		case model.Skip:
			s.skip = append(s.skip, c)
		case model.Waived:
			s.waive = append(s.waive, c)
		}
	}
	bySeverity(s.fails)
	bySeverity(s.errs)
	bySeverity(s.rto)
	return s
}

func (s *screen) add(lines ...string) { s.out = append(s.out, lines...) }

func (s *screen) muted(t string) string { return s.p.Paint(ui.Muted, t) }
func (s *screen) steel(t string) string { return s.p.Paint(ui.Steel, t) }
func (s *screen) bold(c ui.RGB, t string) string {
	return s.p.Bold(&c, t)
}

// section starts a titled block.
func (s *screen) section(title, note string) {
	s.add("")
	l := " " + s.p.Rule(title, s.w-1, ui.Ink)
	if note != "" {
		// Keep the note on the rule when it fits.
		head := " " + s.p.Paint(ui.Faint, "── ") + s.bold(ui.Ink, title) + " " + s.muted(note) + " "
		if ui.Width(head) < s.w-4 {
			l = head + s.p.Paint(ui.Faint, strings.Repeat("─", s.w-ui.Width(head)))
		}
	}
	s.add(l)
}

// ── header: the grade card ─────────────────────────────────────────────────

func (s *screen) header() {
	r := s.r
	sum := r.Summary
	gc := ui.GradeColor(sum.Grade)
	var letter []string
	if len(sum.Grade) == 1 {
		letter = s.p.Relief(ui.Letters(ui.Big, sum.Grade, 0), []ui.RGB{ui.Lighten(gc, 0.35), gc, ui.Darken(gc, 0.15)})
	} else {
		letter = s.p.Relief(ui.Letters(ui.Big, "N/A", 0), []ui.RGB{ui.Steel, ui.Muted})
	}
	lw := ui.Width(ui.Letters(ui.Big, "A", 0)[0])
	if len(sum.Grade) != 1 {
		lw = ui.Width(ui.Letters(ui.Big, "N/A", 0)[0])
	}
	inner := s.w - 4
	gauge := min(46, inner-lw-6)

	title := s.bold(gc, "GRADE "+sum.Grade) + s.p.Paint(gc, " · "+ui.GradeWord(sum.Grade))
	var qual []string
	if sum.RuntimeQualified {
		qual = append(qual, s.p.Paint(ui.Amber, "runtime-qualified"))
	}
	if sum.RawGrade != sum.Grade && sum.RawGrade != "" {
		qual = append(qual, s.muted("raw grade "+sum.RawGrade))
	}
	for _, c := range sum.Caps {
		if c.Grade == "D" {
			qual = append(qual, s.p.Paint(ui.Pink, "critical failure"))
		}
	}
	scoreTxt := "no evaluated control"
	frac := 0.0
	if sum.Score != nil {
		frac = *sum.Score / 100
		scoreTxt = s.bold(ui.White, fmt.Sprintf("%.1f", *sum.Score)) + s.muted(" / 100")
	}
	cnt := sum.Counts
	evaluated := cnt.Pass + cnt.Fail + cnt.Error
	right := []string{
		title,
		strings.Join(qual, s.muted(" · ")),
		scoreTxt,
		s.gauge(frac, gauge),
		s.gaugeLabels(gauge, sum.Grade),
		fmt.Sprintf("%s %s", s.bold(ui.Ink, fmt.Sprintf("%d/%d", cnt.Pass, evaluated)), s.muted("evaluated controls pass")),
	}
	if right[1] == "" {
		right[1] = s.muted(lensLabel(r))
	}
	body := []string{""}
	body = append(body, ui.Columns(prefixAll(letter, " "), right, lw+1, 4)...)
	body = append(body, "")

	plat := strings.TrimSpace(r.Target.Platform.Name + " " + r.Target.Platform.Release)
	if r.Target.Container != "" {
		plat += " (container)"
	}
	eng := strings.TrimSpace(r.Engine.Name + " " + r.Engine.Version)
	mode := r.Engine.Mode
	if mode == "docker" {
		mode = "docker engine"
	}
	title2 := s.p.Gradient("SHADOW-ARMOR", ui.Brand) + s.muted(" · ") + s.bold(ui.Ink, r.Target.URI)
	foot := s.muted(fmt.Sprintf("%s · %s · %s · %.1fs · level %d · %s", plat, eng, mode, r.Engine.Duration, r.Selection.Level, stdName(r, r.Selection.Standard)))
	s.add("")
	for _, l := range s.p.Box(title2, foot, body, s.w, ui.Faint) {
		s.add(" " + l)
	}
}

func lensLabel(r *model.Report) string {
	if r.Summary.Lens == "" || r.Summary.Lens == "all" {
		return "all standards"
	}
	return "lens " + stdName(r, r.Summary.Lens)
}

func prefixAll(lines []string, p string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = p + l
	}
	return out
}

// gauge is the score bar: heat-coloured fill in a thin frame.
func (s *screen) gauge(frac float64, w int) string {
	return s.p.Paint(ui.Faint, "▕") + s.p.Bar(frac, w, ui.AlongFn(ui.Heat), ui.Hex("#1E293B")) + s.p.Paint(ui.Faint, "▏")
}

// gaugeLabels puts each grade letter under its band of the gauge.
func (s *screen) gaugeLabels(w int, current string) string {
	cells := make([]string, w+2)
	for i := range cells {
		cells[i] = " "
	}
	bands := []struct {
		g      string
		lo, hi float64
	}{{"E", 0, 50}, {"D", 50, 65}, {"C", 65, 80}, {"B", 80, 90}, {"A", 90, 100}}
	for _, b := range bands {
		pos := 1 + int(math.Round((b.lo+b.hi)/2/100*float64(w)))
		if pos >= len(cells) {
			pos = len(cells) - 1
		}
		c := ui.Mix(ui.GradeColor(b.g), ui.Faint, 0.45)
		if b.g == current {
			cells[pos] = s.bold(ui.GradeColor(b.g), b.g)
		} else {
			cells[pos] = s.p.Paint(c, b.g)
		}
	}
	// Threshold ticks between bands.
	for _, t := range []float64{50, 65, 80, 90} {
		pos := 1 + int(math.Round(t/100*float64(w)))
		if pos < len(cells) && cells[pos] == " " {
			cells[pos] = s.p.Paint(ui.Faint, "╵")
		}
	}
	return strings.Join(cells, "")
}

// ── findings and proof panels ──────────────────────────────────────────────

func (s *screen) panels() {
	half := (s.w - 4) / 2
	left := s.findingsPanel(half)
	right := s.proofPanel(half)
	s.add("")
	if s.w >= 96 {
		for _, l := range ui.Columns(left, right, half, 3) {
			s.add(" " + l)
		}
		return
	}
	for _, l := range append(append(left, ""), right...) {
		s.add(" " + l)
	}
}

func (s *screen) findingsPanel(w int) []string {
	bySev := map[string]int{}
	auto := 0
	for _, c := range append(append([]model.ControlResult{}, s.fails...), s.errs...) {
		bySev[c.Severity]++
		if c.Remediation.Auto {
			auto++
		}
	}
	total := len(s.fails) + len(s.errs)
	out := []string{s.bold(ui.Ink, "FINDINGS") + s.muted(fmt.Sprintf("  %d failing", total))}
	maxN := 1
	for _, n := range bySev {
		maxN = max(maxN, n)
	}
	barW := max(6, w-24)
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		n := bySev[sev]
		c := ui.SeverityColor(sev)
		dot := s.p.Paint(c, "●")
		if n == 0 {
			dot = s.p.Paint(ui.Faint, "○")
		}
		label := ui.Pad(s.p.Paint(ui.Mix(c, ui.Ink, 0.25), sev), 9)
		num := ui.PadLeft(s.bold(ui.Ink, fmt.Sprint(n)), 4)
		if n == 0 {
			num = ui.PadLeft(s.muted("0"), 4)
		}
		bar := ""
		if n > 0 {
			bar = s.p.Paint(c, strings.Repeat("■", max(1, int(math.Round(float64(n)/float64(maxN)*float64(barW))))))
		}
		out = append(out, fmt.Sprintf(" %s %s%s  %s", dot, label, num, bar))
	}
	if total > 0 {
		out = append(out, s.p.Paint(ui.Cyan, " ↯ ")+s.steel(fmt.Sprintf("%d of %d fixable by sdw-armor harden", auto, total)))
	} else {
		out = append(out, s.p.Paint(ui.Green, " ✓ ")+s.steel("nothing failing"))
	}
	return out
}

func (s *screen) proofPanel(w int) []string {
	cnt := s.r.Summary.Counts
	durable := cnt.Pass - cnt.RuntimeOnly - cnt.RebootProven
	out := []string{s.bold(ui.Ink, "WHAT THE PASSES PROVE") + s.muted(fmt.Sprintf("  %d passing", cnt.Pass))}
	barW := max(10, w-2)
	out = append(out, " "+s.p.Segments(
		[]float64{float64(cnt.RebootProven), float64(durable), float64(cnt.RuntimeOnly)},
		[]ui.RGB{ui.Green, ui.Teal, ui.Amber}, []string{"█", "█", "▒"}, barW))
	item := func(c ui.RGB, glyph string, n int, label, hint string) string {
		l := " " + s.p.Paint(c, glyph) + " " + ui.PadLeft(s.bold(ui.Ink, fmt.Sprint(n)), 3) + " " + s.steel(label)
		if hint != "" {
			l += s.muted("  " + hint)
		}
		return l
	}
	out = append(out,
		item(ui.Green, "█", cnt.RebootProven, "reboot-proven", "survived a real reboot"),
		item(ui.Teal, "█", durable, "durable", "persisted state keeps them"),
		item(ui.Amber, "▒", cnt.RuntimeOnly, "runtime-only", "persistence not proven"),
		item(ui.Sky, "◐", cnt.Pending, "pending", "fixed on disk, reboot/reload due"),
	)
	return out
}

// ── pillars ────────────────────────────────────────────────────────────────

func (s *screen) pillars() {
	sum := s.r.Summary
	if len(sum.Pillars) == 0 {
		return
	}
	note := ""
	if total := len(s.r.Pillars); len(sum.Pillars) < total {
		note = fmt.Sprintf("%d of %d in this selection", len(sum.Pillars), total)
	}
	s.section("PILLARS", note)
	titles := map[int]string{}
	for _, pm := range s.r.Pillars {
		titles[pm.ID] = pm.Title
	}
	titleW := min(40, s.w-36)
	barW := max(8, min(24, s.w-titleW-26))
	for _, ps := range sum.Pillars {
		gc := ui.GradeColor(ps.Grade)
		sc := "  n/a"
		frac := 0.0
		if ps.Score != nil {
			sc = fmt.Sprintf("%5.1f", *ps.Score)
			frac = *ps.Score / 100
		}
		ev := ps.Counts.Pass + ps.Counts.Fail + ps.Counts.Error
		grade := s.bold(gc, ui.Pad(ps.Grade, 3))
		s.add(fmt.Sprintf("  %s %s %s %s %s  %s",
			s.muted(fmt.Sprintf("%02d", ps.ID)),
			ui.Pad(ui.Trunc(s.p.Paint(ui.Ink, titles[ps.ID]), titleW), titleW),
			grade,
			s.p.Bar(frac, barW, ui.Fixed(gc), ui.Hex("#1E293B")),
			s.steel(sc),
			s.muted(fmt.Sprintf("%d/%d", ps.Counts.Pass, ev))))
	}
}

// ── the path to a better grade ─────────────────────────────────────────────

func (s *screen) projection() {
	sum := s.r.Summary
	proj, n := score.Projected(s.r.Controls, s.r.Weights, sum.Lens)
	if n == 0 || proj.Score == nil || sum.Score == nil {
		return
	}
	from := s.bold(ui.GradeColor(sum.Grade), sum.Grade) + " " + s.steel(fmt.Sprintf("%.1f", *sum.Score))
	to := s.bold(ui.GradeColor(proj.Grade), proj.Grade) + " " + s.steel(fmt.Sprintf("%.1f", *proj.Score))
	arrow := s.p.Gradient("──────►", []ui.RGB{ui.GradeColor(sum.Grade), ui.GradeColor(proj.Grade)})
	s.add("")
	s.add(fmt.Sprintf("  %s %s  %s  %s   %s", s.p.Paint(ui.Cyan, "↯"), s.bold(ui.Ink, "HARDEN PATH"), from, arrow, to) +
		s.muted("   projected once the "+plural(n, "automatic fix", "automatic fixes")+" and pending reboots are done"))
}

// ── failures ───────────────────────────────────────────────────────────────

func (s *screen) failures() {
	if len(s.fails) == 0 {
		return
	}
	limit := s.o.MaxFailures
	if limit <= 0 {
		limit = 12
	}
	if s.o.Verbose {
		limit = len(s.fails)
	}
	s.section("FAILURES", "most severe first")
	sev := ""
	for i, c := range s.fails {
		if i == limit {
			break
		}
		if c.Severity != sev {
			sev = c.Severity
			sc := ui.SeverityColor(sev)
			s.add("  " + s.p.Paint(sc, "▍") + s.bold(sc, strings.ToUpper(sev)))
		}
		s.control(c)
	}
	if n := len(s.fails) - limit; n > 0 {
		s.add(s.muted(fmt.Sprintf("  … %d more failing control(s): add --verbose, or open the HTML report (-o html:report.html)", n)))
	}
}

// control renders one failing or qualified control with its evidence.
func (s *screen) control(c model.ControlResult) {
	sc := ui.SeverityColor(c.Severity)
	mark, tag := s.p.Paint(ui.Red, "✗"), ""
	switch {
	case c.Qualifier == model.Pending:
		mark = s.p.Paint(ui.Sky, "◐")
		tag = s.p.Paint(ui.Sky, "pending "+pendingWhat(c))
	case c.Proof != nil && c.Proof.Reboot == model.ProofLost:
		tag = s.p.Paint(ui.Red, "lost at the reboot")
	case c.Status == model.Pass:
		mark = s.p.Paint(ui.Amber, "◑")
	case c.Status == model.Error:
		mark = s.p.Paint(ui.Purple, "!")
	}
	fix := s.muted("manual")
	if c.Remediation.Auto {
		fix = s.p.Paint(ui.Cyan, "↯ auto")
	}
	right := fix
	if tag != "" {
		right = tag + s.muted(" · ") + fix
	}
	left := fmt.Sprintf("   %s %s  %s", mark, s.bold(sc, c.ID), s.p.Paint(ui.Ink, c.Title))
	room := s.w - ui.Width(right) - 2
	s.add(ui.Pad(ui.Trunc(left, room), room) + " " + right)
	items, more := failingItems(c, 2)
	if c.Status == model.Error {
		items, more = []model.Evidence{{Desc: c.Reason}}, 0
	}
	for i, e := range items {
		branch, cont := "├─", "│ "
		if i == len(items)-1 && more == 0 {
			branch, cont = "╰─", "  "
		}
		s.add("      " + s.p.Paint(ui.Faint, branch) + " " + s.steel(ui.Trunc(EvidenceDesc(e), s.w-10)))
		// The outcome gets its own line(s): it is never cut.
		if e.Message == "" {
			continue
		}
		for j, l := range ui.Wrap(e.Message, s.w-13) {
			if j == 0 {
				l = s.outcome(l)
			} else {
				l = s.steel(l)
			}
			s.add("      " + s.p.Paint(ui.Faint, cont) + "   " + l)
		}
	}
	if more > 0 {
		s.add("      " + s.p.Paint(ui.Faint, "╰─") + " " + s.muted(fmt.Sprintf("… and %d more", more)))
	}
}

// outcome colours "found X · expected Y": what is wrong, then what is right.
func (s *screen) outcome(l string) string {
	got, want, ok := strings.Cut(l, " · expected ")
	if !ok {
		return s.p.Paint(ui.Amber, l)
	}
	return s.p.Paint(ui.Amber, got) + s.muted(" · ") + s.p.Paint(ui.Green, "expected "+want)
}

// ── runtime-only passes ────────────────────────────────────────────────────

func (s *screen) runtimeOnly() {
	if len(s.rto) == 0 {
		return
	}
	sum := s.r.Summary
	note := "compliant now; persistence contradicted or not proven"
	switch {
	case sum.RuntimeQualified:
		note += " · the A rests on them: capped at B"
	case sum.Grade == "A":
		note += " · the A holds without them"
	}
	s.section("RUNTIME-ONLY PASSES", note)
	for _, c := range s.rto {
		s.control(c)
		s.add("      " + s.p.Paint(ui.Faint, "   ") + s.proofLine(c.Proof))
	}
}

// proofLine renders the three proof columns with colours.
func (s *screen) proofLine(pr *model.Proof) string {
	if pr == nil {
		return s.muted("proof not recorded")
	}
	col := func(label, v string) string {
		switch v {
		case model.ProofProven, model.ProofExpected:
			return s.muted(label+" ") + s.p.Paint(ui.Green, "✓")
		case model.ProofFailed, model.ProofLost:
			return s.muted(label+" ") + s.p.Paint(ui.Red, "✗")
		case model.ProofNA:
			return s.muted(label + " n/a")
		}
		return s.muted(label+" ") + s.p.Paint(ui.Amber, "?")
	}
	reboot := map[string]string{
		model.ProofProven: "proven", model.ProofExpected: "expected", model.ProofFailed: "would be undone",
		model.ProofLost: "lost", model.ProofNotMeasured: "not measured", model.ProofNA: "",
	}[pr.Reboot]
	return col("now", pr.Now) + s.muted(" · ") + col("on disk", pr.OnDisk) + s.muted(" · ") + col("after reboot", pr.Reboot) + " " + s.muted(reboot)
}

// ── errors, waivers, passes ────────────────────────────────────────────────

func (s *screen) errorsAndWaivers() {
	if len(s.errs) > 0 {
		s.section("COULD NOT BE EVALUATED", "counted as failures (fail-closed)")
		for _, c := range s.errs {
			s.control(c)
		}
	}
	if len(s.waive) > 0 {
		s.section("WAIVED", "accepted risks, left out of the score")
		for _, c := range s.waive {
			s.add(fmt.Sprintf("   %s %s  %s", s.p.Paint(ui.Blue, "≈"), s.bold(ui.Blue, c.ID), s.p.Paint(ui.Ink, c.Title)))
			s.add("      " + s.p.Paint(ui.Faint, "╰─") + " " + s.steel(ui.Trunc(c.Reason, s.w-10)))
		}
	}
}

func (s *screen) passes() {
	if len(s.pass) > 0 {
		s.section("PASSES", "")
		for _, c := range s.pass {
			mark := s.p.Paint(ui.Teal, "✓")
			if c.Proof != nil && c.Proof.Reboot == model.ProofProven {
				mark = s.p.Paint(ui.Green, "✓")
			}
			left := fmt.Sprintf("   %s %s  %s", mark, s.p.Paint(ui.Steel, c.ID), c.Title)
			s.add(ui.Pad(ui.Trunc(left, s.w-44), s.w-44) + " " + s.proofLine(c.Proof))
		}
	}
	if len(s.skip) > 0 {
		s.section("NOT APPLICABLE", "")
		for _, c := range s.skip {
			s.add(fmt.Sprintf("   %s %s  %s %s", s.muted("↺"), s.muted(c.ID), c.Title, s.muted("· "+ui.Trunc(c.Reason, 60))))
		}
	}
}

// ── next steps ─────────────────────────────────────────────────────────────

func (s *screen) next() {
	t := s.r.Target.URI
	sudo := ""
	if s.o.Sudo {
		sudo = " --sudo"
	}
	auto := 0
	for _, c := range append(append(append([]model.ControlResult{}, s.fails...), s.errs...), s.rto...) {
		if c.Remediation.Auto {
			auto++
		}
	}
	var cmds [][2]string
	if auto > 0 {
		cmds = append(cmds, [2]string{"sdw-armor harden " + t + sudo, "plan the " + plural(auto, "automatic fix", "automatic fixes") + ", opt in rule by rule"})
	}
	first := ""
	if len(s.fails) > 0 {
		first = s.fails[0].ID
	} else if len(s.rto) > 0 {
		first = s.rto[0].ID
	}
	if first != "" {
		cmds = append(cmds, [2]string{"sdw-armor explain " + first, "why it matters, how it is checked, how to fix it"})
	}
	cmds = append(cmds, [2]string{"sdw-armor scan " + t + sudo + " -o html:report.html", "the interactive report: filters, lenses, evidence"})
	if !s.o.Verbose {
		cmds = append(cmds, [2]string{"… --verbose", "every failure, the passes and what they prove"})
	}
	s.section("NEXT", "")
	cw := 0
	for _, c := range cmds {
		cw = max(cw, ui.Width(c[0]))
	}
	cw = min(cw, s.w-30)
	for _, c := range cmds {
		s.add("  " + s.p.Paint(ui.Violet, "❯ ") + ui.Pad(s.p.Paint(ui.Cyan, ui.Trunc(c[0], cw)), cw) + "  " + s.muted(c[1]))
	}
	s.add("")
}

// plural writes "1 fix" or "3 fixes".
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
