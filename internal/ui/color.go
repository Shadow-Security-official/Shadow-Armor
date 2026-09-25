package ui

import (
	"fmt"
	"math"
	"strings"
)

// RGB is a 24-bit colour.
type RGB struct{ R, G, B uint8 }

// Hex parses "#rrggbb".
func Hex(s string) RGB {
	var c RGB
	_, _ = fmt.Sscanf(strings.TrimPrefix(s, "#"), "%02x%02x%02x", &c.R, &c.G, &c.B)
	return c
}

// Mix interpolates between a and b (t in [0,1]).
func Mix(a, b RGB, t float64) RGB {
	t = math.Max(0, math.Min(1, t))
	l := func(x, y uint8) uint8 { return uint8(math.Round(float64(x) + (float64(y)-float64(x))*t)) }
	return RGB{l(a.R, b.R), l(a.G, b.G), l(a.B, b.B)}
}

// Lighten moves c towards white.
func Lighten(c RGB, t float64) RGB { return Mix(c, RGB{255, 255, 255}, t) }

// Darken moves c towards black.
func Darken(c RGB, t float64) RGB { return Mix(c, RGB{}, t) }

// Along returns the colour at position t in [0,1] of a gradient.
func Along(stops []RGB, t float64) RGB {
	if len(stops) == 0 {
		return RGB{200, 200, 200}
	}
	if len(stops) == 1 || t <= 0 {
		return stops[0]
	}
	if t >= 1 {
		return stops[len(stops)-1]
	}
	seg := t * float64(len(stops)-1)
	i := int(seg)
	return Mix(stops[i], stops[i+1], seg-float64(i))
}

const (
	reset = "\x1b[0m"
	esc   = "\x1b["
)

// Fg is the escape sequence that sets the foreground to c.
func (p Profile) Fg(c RGB) string {
	switch p {
	case TrueColor:
		return fmt.Sprintf("\x1b[38;2;%d;%d;%dm", c.R, c.G, c.B)
	case Ansi256:
		return fmt.Sprintf("\x1b[38;5;%dm", to256(c))
	case Basic:
		return fmt.Sprintf("\x1b[%dm", to16(c))
	}
	return ""
}

// Bg is the escape sequence that sets the background to c.
func (p Profile) Bg(c RGB) string {
	switch p {
	case TrueColor:
		return fmt.Sprintf("\x1b[48;2;%d;%d;%dm", c.R, c.G, c.B)
	case Ansi256:
		return fmt.Sprintf("\x1b[48;5;%dm", to256(c))
	case Basic:
		return fmt.Sprintf("\x1b[%dm", to16(c)+10)
	}
	return ""
}

// Attr returns an SGR attribute (1 bold, 2 dim, 3 italic, 4 underline) or "".
func (p Profile) Attr(n int) string {
	if p == NoColor {
		return ""
	}
	return fmt.Sprintf("%s%dm", esc, n)
}

// Reset clears all attributes.
func (p Profile) Reset() string {
	if p == NoColor {
		return ""
	}
	return reset
}

// Paint wraps s in a foreground colour.
func (p Profile) Paint(c RGB, s string) string {
	if p == NoColor || s == "" {
		return s
	}
	return p.Fg(c) + s + reset
}

// Bold wraps s in bold, optionally coloured.
func (p Profile) Bold(c *RGB, s string) string {
	if p == NoColor || s == "" {
		return s
	}
	col := ""
	if c != nil {
		col = p.Fg(*c)
	}
	return esc + "1m" + col + s + reset
}

// Gradient colours each rune of s along the stops (spaces stay plain).
func (p Profile) Gradient(s string, stops []RGB) string {
	if p == NoColor {
		return s
	}
	rs := []rune(s)
	n := 0
	for _, r := range rs {
		if r != ' ' {
			n++
		}
	}
	var b strings.Builder
	i := 0
	for _, r := range rs {
		if r == ' ' {
			b.WriteRune(r)
			continue
		}
		t := 0.0
		if n > 1 {
			t = float64(i) / float64(n-1)
		}
		b.WriteString(p.Fg(Along(stops, t)))
		b.WriteRune(r)
		i++
	}
	b.WriteString(reset)
	return b.String()
}

func to256(c RGB) int {
	// Greys get the 24-step ramp, colours the 6x6x6 cube.
	if c.R == c.G && c.G == c.B {
		if c.R < 8 {
			return 16
		}
		if c.R > 248 {
			return 231
		}
		return 232 + int(math.Round(float64(c.R-8)/247*24))
	}
	q := func(v uint8) int { return int(math.Round(float64(v) / 255 * 5)) }
	return 16 + 36*q(c.R) + 6*q(c.G) + q(c.B)
}

func to16(c RGB) int {
	r, g, b := float64(c.R)/255, float64(c.G)/255, float64(c.B)/255
	mx := math.Max(r, math.Max(g, b))
	if mx < 0.2 {
		return 90 // dark grey
	}
	bright := mx > 0.7
	code := 0
	if r > mx*0.6 {
		code |= 1
	}
	if g > mx*0.6 {
		code |= 2
	}
	if b > mx*0.6 {
		code |= 4
	}
	if code == 7 && !bright {
		return 37
	}
	if bright {
		return 90 + code
	}
	return 30 + code
}
