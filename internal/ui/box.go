package ui

import "strings"

// Box draws lines inside a rounded frame of total width w. The title sits in
// the top border, the footer in the bottom one. border colours the frame.
func (p Profile) Box(title, footer string, lines []string, w int, border RGB) []string {
	if w < 20 {
		w = 20
	}
	inner := w - 4
	bc := func(s string) string { return p.Paint(border, s) }
	top := "╭─"
	if title != "" {
		t := " " + Trunc(title, inner-2) + " "
		top += t + bc(strings.Repeat("─", max(0, w-3-Width(t))))
	} else {
		top += bc(strings.Repeat("─", w-3))
	}
	top = bc("╭─") + strings.TrimPrefix(top, "╭─") + bc("╮")
	out := []string{top}
	for _, l := range lines {
		out = append(out, bc("│")+" "+Pad(Trunc(l, inner), inner)+" "+bc("│"))
	}
	bottom := ""
	if footer != "" {
		f := " " + Trunc(footer, inner-2) + " "
		bottom = bc("╰"+strings.Repeat("─", max(0, w-3-Width(f)))) + f + bc("─╯")
	} else {
		bottom = bc("╰" + strings.Repeat("─", w-2) + "╯")
	}
	return append(out, bottom)
}

// Rule is a horizontal separator with a label: "── LABEL ─────────".
func (p Profile) Rule(label string, w int, c RGB) string {
	if label == "" {
		return p.Paint(Faint, strings.Repeat("─", w))
	}
	l := p.Bold(&c, label)
	return p.Paint(Faint, "── ") + l + " " + p.Paint(Faint, strings.Repeat("─", max(0, w-4-Width(label))))
}

// Columns lays two blocks side by side with a gap (the left one padded).
func Columns(left, right []string, leftWidth, gap int) []string {
	n := max(len(left), len(right))
	out := make([]string, n)
	for i := 0; i < n; i++ {
		l, r := "", ""
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		out[i] = Pad(l, leftWidth) + strings.Repeat(" ", gap) + r
	}
	return out
}
