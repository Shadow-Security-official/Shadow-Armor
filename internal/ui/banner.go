package ui

import "strings"

// Shield is the Shadow-Armor emblem: a shield with an S cut out of it.
var Shield = []string{
	"█████████████",
	"███  ▄▄▄▄▄███",
	"████▄▄▄▄ ▀███",
	"▀██▄▄▄▄▄▄▄██▀",
	"  ▀███████▀  ",
	"     ▀█▀     ",
}

// Tagline is the one-line description under the logo.
const Tagline = "effective linux compliance & hardening"

// Banner draws the logo for a terminal width: the emblem and the name in big
// relief letters when there is room, a compact wordmark otherwise, one line
// on very narrow terminals. info lines go under (or next to) the name.
func (p Profile) Banner(width int, info ...string) []string {
	shield := make([]string, len(Shield))
	for i, l := range Shield {
		shield[i] = p.Paint(Along(Brand, float64(i)/float64(len(Shield)-1)), l)
	}
	sub := func(s string) string { return p.Paint(Steel, s) }
	switch {
	case width >= 122:
		word := p.Relief(Letters(Big, "SHADOW-ARMOR", 0), Brand)
		out := Columns(shield, word, Width(Shield[0]), 3)
		lead := strings.Repeat(" ", Width(Shield[0])+3)
		line := p.Gradient(Tagline, []RGB{Steel, Ink})
		for _, s := range info {
			line += sub("  ·  ") + sub(s)
		}
		return append(prefix(out, "  "), "  "+lead+line)
	case width >= 70:
		word := p.Relief(Letters(Small, "SHADOW-ARMOR", 1), Brand)
		right := []string{"", word[0], word[1], p.Gradient(Tagline, []RGB{Steel, Ink})}
		if len(info) > 0 {
			right = append(right, sub(strings.Join(info, "  ·  ")))
		}
		return prefix(Columns(shield, right, Width(Shield[0]), 3), "  ")
	}
	line := p.Paint(Violet, "◆ ") + p.Gradient("SHADOW-ARMOR", Brand)
	if len(info) > 0 {
		line += " " + sub(info[0])
	}
	return []string{" " + line}
}

func prefix(lines []string, p string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = p + l
	}
	return out
}
