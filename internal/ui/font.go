package ui

import "strings"

// Big is a 6-row block font in the "ANSI Shadow" style: full blocks for the
// face of each letter, box-drawing strokes for its shadow.
var Big = map[rune][]string{
	'A': {
		" █████╗ ",
		"██╔══██╗",
		"███████║",
		"██╔══██║",
		"██║  ██║",
		"╚═╝  ╚═╝",
	},
	'B': {
		"██████╗ ",
		"██╔══██╗",
		"██████╔╝",
		"██╔══██╗",
		"██████╔╝",
		"╚═════╝ ",
	},
	'C': {
		" ██████╗",
		"██╔════╝",
		"██║     ",
		"██║     ",
		"╚██████╗",
		" ╚═════╝",
	},
	'D': {
		"██████╗ ",
		"██╔══██╗",
		"██║  ██║",
		"██║  ██║",
		"██████╔╝",
		"╚═════╝ ",
	},
	'E': {
		"███████╗",
		"██╔════╝",
		"█████╗  ",
		"██╔══╝  ",
		"███████╗",
		"╚══════╝",
	},
	'H': {
		"██╗  ██╗",
		"██║  ██║",
		"███████║",
		"██╔══██║",
		"██║  ██║",
		"╚═╝  ╚═╝",
	},
	'M': {
		"███╗   ███╗",
		"████╗ ████║",
		"██╔████╔██║",
		"██║╚██╔╝██║",
		"██║ ╚═╝ ██║",
		"╚═╝     ╚═╝",
	},
	'N': {
		"███╗   ██╗",
		"████╗  ██║",
		"██╔██╗ ██║",
		"██║╚██╗██║",
		"██║ ╚████║",
		"╚═╝  ╚═══╝",
	},
	'O': {
		" ██████╗ ",
		"██╔═══██╗",
		"██║   ██║",
		"██║   ██║",
		"╚██████╔╝",
		" ╚═════╝ ",
	},
	'R': {
		"██████╗ ",
		"██╔══██╗",
		"██████╔╝",
		"██╔══██╗",
		"██║  ██║",
		"╚═╝  ╚═╝",
	},
	'S': {
		"███████╗",
		"██╔════╝",
		"███████╗",
		"╚════██║",
		"███████║",
		"╚══════╝",
	},
	'W': {
		"██╗    ██╗",
		"██║    ██║",
		"██║ █╗ ██║",
		"██║███╗██║",
		"╚███╔███╔╝",
		" ╚══╝╚══╝ ",
	},
	'/': {
		"    ██╗",
		"   ██╔╝",
		"  ██╔╝ ",
		" ██╔╝  ",
		"██╔╝   ",
		"╚═╝    ",
	},
	'-': {
		"      ",
		"      ",
		"█████╗",
		"╚════╝",
		"      ",
		"      ",
	},
	' ': {"  ", "  ", "  ", "  ", "  ", "  "},
}

// Small is a 2-row half-block font for the compact wordmark.
var Small = map[rune][]string{
	'S': {"█▀", "▄█"},
	'H': {"█ █", "█▀█"},
	'A': {"▄▀█", "█▀█"},
	'D': {"█▀▄", "█▄▀"},
	'O': {"█▀█", "█▄█"},
	'W': {"█ █ █", "▀▄▀▄▀"},
	'R': {"█▀█", "█▀▄"},
	'M': {"█▀▄▀█", "█ ▀ █"},
	'-': {"▄▄", "  "},
	' ': {" ", " "},
}

// Letters renders text with a font, one space between glyphs.
func Letters(font map[rune][]string, text string, gap int) []string {
	rows := 0
	for _, g := range font {
		rows = len(g)
		break
	}
	out := make([]string, rows)
	for i, r := range strings.ToUpper(text) {
		g, ok := font[r]
		if !ok {
			continue
		}
		w := 0
		for _, l := range g {
			if n := Width(l); n > w {
				w = n
			}
		}
		for row := range out {
			if i > 0 {
				out[row] += strings.Repeat(" ", gap)
			}
			out[row] += Pad(g[row], w)
		}
	}
	return out
}

// shadowRunes are the strokes drawn as the letters' shadow.
const shadowRunes = "╗║╔═╝╚"

// Relief colours big letters: the face with a gradient across the whole
// block (left to right, slightly shifted per row), the shadow strokes in a
// darker shade of the same hue.
func (p Profile) Relief(lines []string, stops []RGB) []string {
	if p == NoColor {
		return lines
	}
	w := 0
	for _, l := range lines {
		if n := Width(l); n > w {
			w = n
		}
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		var b strings.Builder
		col := 0
		last := ""
		for _, r := range l {
			if r == ' ' {
				b.WriteRune(r)
				col++
				continue
			}
			t := 0.0
			if w > 1 {
				t = (float64(col) + float64(i)*0.9) / (float64(w) + float64(len(lines))*0.9)
			}
			c := Along(stops, t)
			if strings.ContainsRune(shadowRunes, r) {
				c = Mix(Darken(c, 0.45), Faint, 0.35)
			}
			if code := p.Fg(c); code != last {
				b.WriteString(code)
				last = code
			}
			b.WriteRune(r)
			col++
		}
		b.WriteString(reset)
		out[i] = b.String()
	}
	return out
}
