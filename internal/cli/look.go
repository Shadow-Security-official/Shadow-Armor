package cli

import (
	"fmt"
	"strings"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/ui"
)

// look is the visual toolkit of one output (colours, width).
type look struct {
	p ui.Profile
	w int
}

// look for stdout.
func (a *app) look() look {
	t := ui.Detect(a.stdout, a.color)
	w := t.Width
	if w <= 0 {
		w = 100
	}
	return look{p: t.Profile, w: max(60, min(w-2, 118))}
}

func (l look) muted(s string) string                 { return l.p.Paint(ui.Muted, s) }
func (l look) faint(s string) string                 { return l.p.Paint(ui.Faint, s) }
func (l look) steel(s string) string                 { return l.p.Paint(ui.Steel, s) }
func (l look) ink(s string) string                   { return l.p.Paint(ui.Ink, s) }
func (l look) paint(c ui.RGB, s string) string       { return l.p.Paint(c, s) }
func (l look) bold(c ui.RGB, s string) string        { return l.p.Bold(&c, s) }
func (l look) cyan(s string) string                  { return l.p.Paint(ui.Cyan, s) }
func (l look) ok(s string) string                    { return l.p.Paint(ui.Green, "✓") + " " + s }
func (l look) bad(s string) string                   { return l.p.Paint(ui.Red, "✗") + " " + s }
func (l look) warn(s string) string                  { return l.p.Paint(ui.Amber, "!") + " " + s }
func (l look) grade(g string) string                 { return l.bold(ui.GradeColor(g), g) }
func (l look) gradient(s string, c ...ui.RGB) string { return l.p.Gradient(s, c) }

// sev is a coloured severity label.
func (l look) sev(s string) string {
	return l.bold(ui.SeverityColor(s), strings.ToUpper(s))
}

// section prints a titled rule.
func (l look) section(title, note string) string {
	head := " " + l.faint("── ") + l.bold(ui.Ink, title)
	if note != "" {
		head += " " + l.muted(note)
	}
	head += " "
	return head + l.faint(strings.Repeat("─", max(0, l.w-ui.Width(head))))
}

// gradeScore renders "B 85.7" in colour.
func (l look) gradeScore(s model.Summary) string {
	if s.Score == nil {
		return l.grade(s.Grade)
	}
	return l.grade(s.Grade) + " " + l.steel(fmt.Sprintf("%.1f", *s.Score))
}

// bigGrade is a grade letter in relief.
func (l look) bigGrade(g string) []string {
	if len(g) != 1 {
		g = "N/A"
	}
	c := ui.GradeColor(g)
	return l.p.Relief(ui.Letters(ui.Big, g, 0), []ui.RGB{ui.Lighten(c, 0.35), c, ui.Darken(c, 0.15)})
}

// transition draws "before ━━━► after" with big letters and scores.
func (l look) transition(before, after model.Summary, labels ...string) []string {
	a, b := l.bigGrade(before.Grade), l.bigGrade(after.Grade)
	arrow := []string{"", "", l.gradient(" ━━━━━━━► ", ui.GradeColor(before.Grade), ui.GradeColor(after.Grade)), "", "", ""}
	aw := ui.Width(ui.Strip(a[0]))
	rows := ui.Columns(ui.Columns(a, arrow, aw, 2), b, aw+2+10, 2)
	score := func(s model.Summary) string {
		if s.Score == nil {
			return l.muted("n/a")
		}
		return l.bold(ui.GradeColor(s.Grade), fmt.Sprintf("%.1f", *s.Score)) + l.muted(" / 100")
	}
	left, right := "before", "after"
	if len(labels) == 2 {
		left, right = labels[0], labels[1]
	}
	rows = append(rows, ui.Pad(score(before), aw+12)+"  "+score(after))
	rows = append(rows, ui.Pad(l.muted(left), aw+12)+"  "+l.muted(right))
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = "   " + r
	}
	return out
}

// kv renders "label  value" rows with aligned labels.
func (l look) kv(rows [][2]string) []string {
	w := 0
	for _, r := range rows {
		w = max(w, ui.Width(r[0]))
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, ui.Pad(l.muted(r[0]), w)+"  "+r[1])
	}
	return out
}

// box frames lines at the look's width.
func (l look) box(title, footer string, lines []string, border ui.RGB) []string {
	out := l.p.Box(title, footer, lines, l.w, border)
	for i := range out {
		out[i] = " " + out[i]
	}
	return out
}
