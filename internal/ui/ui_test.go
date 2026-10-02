package ui

import (
	"strings"
	"testing"
)

func TestWidthIgnoresEscapes(t *testing.T) {
	s := TrueColor.Paint(Red, "héllo") + " " + TrueColor.Bold(&Green, "✓")
	if Width(s) != 7 {
		t.Fatalf("width %d", Width(s))
	}
	if got := Trunc(s, 4); Width(got) != 4 || !strings.HasSuffix(Strip(got), "…") {
		t.Fatalf("trunc %q", Strip(got))
	}
	if Width(Pad("ab", 5)) != 5 || Width(PadLeft("ab", 5)) != 5 || Width(Center("ab", 6)) != 6 {
		t.Fatal("padding")
	}
}

func TestNoColorWritesNoEscapes(t *testing.T) {
	p := NoColor
	for _, s := range []string{
		p.Paint(Red, "x"), p.Bold(&Red, "x"), p.Gradient("abc", Brand),
		strings.Join(p.Relief(Letters(Big, "AB", 0), Brand), ""),
		p.Bar(0.5, 10, Fixed(Red), Faint), p.Line(0.5, 10, Fixed(Red), Faint),
		strings.Join(p.Box("t", "f", []string{"a"}, 30, Faint), ""),
		strings.Join(p.Banner(140, "v1"), ""), p.Shimmer("abc", 3, Steel, White),
	} {
		if strings.Contains(s, "\x1b[") {
			t.Fatalf("escape sequence in no-colour output: %q", s)
		}
	}
}

func TestFontsAreRectangular(t *testing.T) {
	for name, font := range map[string]map[rune][]string{"big": Big, "small": Small} {
		rows := -1
		for r, g := range font {
			if rows == -1 {
				rows = len(g)
			}
			if len(g) != rows {
				t.Fatalf("%s %q: %d rows, want %d", name, r, len(g), rows)
			}
		}
	}
	for _, text := range []string{"SHADOW-ARMOR", "ABCDE", "N/A"} {
		lines := Letters(Big, text, 0)
		for _, l := range lines {
			if Width(l) != Width(lines[0]) {
				t.Fatalf("%s: ragged lines", text)
			}
		}
	}
}

func TestBoxAndBarsHaveExactWidths(t *testing.T) {
	for _, p := range []Profile{NoColor, TrueColor} {
		for _, l := range p.Box("title", "footer", []string{"short", strings.Repeat("x", 200)}, 50, Faint) {
			if Width(l) != 50 {
				t.Fatalf("box line %d wide: %q", Width(l), Strip(l))
			}
		}
		for _, f := range []float64{0, 0.33, 0.5, 1} {
			if Width(p.Bar(f, 20, Fixed(Red), Faint)) != 20 || Width(p.Line(f, 20, Fixed(Red), Faint)) != 20 {
				t.Fatalf("bar width at %v", f)
			}
		}
		if Width(p.Segments([]float64{3, 1, 1}, []RGB{Red, Green, Amber}, nil, 30)) != 30 {
			t.Fatal("segments width")
		}
	}
}

func TestBannerFitsItsWidth(t *testing.T) {
	for _, w := range []int{40, 64, 80, 100, 121, 122, 160} {
		for _, l := range TrueColor.Banner(w, "v0.2.0", "162 controls · 12 pillars") {
			if Width(l) > w {
				t.Fatalf("banner at %d columns has a %d-cell line: %q", w, Width(l), Strip(l))
			}
		}
	}
}

func TestColorDepths(t *testing.T) {
	if got := Ansi256.Fg(Hex("#ff0000")); got != "\x1b[38;5;196m" {
		t.Fatalf("256: %q", got)
	}
	if got := TrueColor.Fg(Hex("#0a0b0c")); got != "\x1b[38;2;10;11;12m" {
		t.Fatalf("truecolor: %q", got)
	}
	if got := Basic.Fg(Hex("#ef4444")); got != "\x1b[91m" {
		t.Fatalf("16: %q", got)
	}
}
