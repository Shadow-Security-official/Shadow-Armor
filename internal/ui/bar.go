package ui

import (
	"math"
	"strings"
)

var partial = []rune{' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'}

// Bar is a smooth horizontal bar of w cells filled to frac (0..1), with
// eighth-of-a-cell precision. fill picks the colour of each cell from its
// position (0..1) along the bar.
func (p Profile) Bar(frac float64, w int, fill func(t float64) RGB, track RGB) string {
	frac = math.Max(0, math.Min(1, frac))
	eighths := int(math.Round(frac * float64(w) * 8))
	var b strings.Builder
	for i := 0; i < w; i++ {
		t := (float64(i) + 0.5) / float64(w)
		n := eighths - i*8
		switch {
		case n >= 8:
			b.WriteString(p.Paint(fill(t), "█"))
		case n > 0:
			b.WriteString(p.Paint(fill(t), string(partial[n])))
		default:
			if p == NoColor {
				b.WriteRune('·')
			} else {
				b.WriteString(p.Paint(track, "━"))
			}
		}
	}
	return b.String()
}

// Line is a thin progress line (━ done, ╺ head, ━ track dimmed).
func (p Profile) Line(frac float64, w int, fill func(t float64) RGB, track RGB) string {
	frac = math.Max(0, math.Min(1, frac))
	done := int(frac * float64(w))
	var b strings.Builder
	for i := 0; i < w; i++ {
		t := float64(i) / float64(max(1, w-1))
		switch {
		case i < done:
			b.WriteString(p.Paint(fill(t), "━"))
		case i == done && frac < 1:
			b.WriteString(p.Paint(fill(t), "╸"))
		default:
			if p == NoColor {
				b.WriteRune('─')
			} else {
				b.WriteString(p.Paint(track, "━"))
			}
		}
	}
	return b.String()
}

// Segments is a stacked bar: each part a share of w cells in its colour.
func (p Profile) Segments(parts []float64, colors []RGB, glyphs []string, w int) string {
	total := 0.0
	for _, x := range parts {
		total += x
	}
	if total == 0 {
		return p.Paint(Faint, strings.Repeat("━", w))
	}
	var b strings.Builder
	used := 0
	acc := 0.0
	for i, x := range parts {
		acc += x
		end := int(math.Round(acc / total * float64(w)))
		if n := end - used; n > 0 {
			g := "█"
			if i < len(glyphs) && glyphs[i] != "" {
				g = glyphs[i]
			}
			b.WriteString(p.Paint(colors[i], strings.Repeat(g, n)))
			used = end
		}
	}
	return b.String()
}

// Fixed is a fill function of one colour.
func Fixed(c RGB) func(float64) RGB { return func(float64) RGB { return c } }

// Along is a fill function following a gradient.
func AlongFn(stops []RGB) func(float64) RGB { return func(t float64) RGB { return Along(stops, t) } }
