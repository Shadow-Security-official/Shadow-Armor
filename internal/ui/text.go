package ui

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

// Strip removes ANSI escape sequences.
func Strip(s string) string { return ansiRe.ReplaceAllString(s, "") }

// Width is the number of terminal cells s occupies (escape sequences
// excluded; every rune Shadow-Armor prints is one cell wide).
func Width(s string) int { return utf8.RuneCountInString(Strip(s)) }

// Pad right-pads s with spaces to width w (visible cells).
func Pad(s string, w int) string {
	if n := Width(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

// PadLeft left-pads s to width w.
func PadLeft(s string, w int) string {
	if n := Width(s); n < w {
		return strings.Repeat(" ", w-n) + s
	}
	return s
}

// Center pads s on both sides to width w.
func Center(s string, w int) string {
	n := Width(s)
	if n >= w {
		return s
	}
	left := (w - n) / 2
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", w-n-left)
}

// Trunc cuts s to w visible cells, keeping escape sequences and ending with
// "…" when something was cut.
func Trunc(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if Width(s) <= w {
		return s
	}
	var b strings.Builder
	cells := 0
	for i := 0; i < len(s); {
		if loc := ansiRe.FindStringIndex(s[i:]); loc != nil && loc[0] == 0 {
			b.WriteString(s[i : i+loc[1]])
			i += loc[1]
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if cells == w-1 {
			b.WriteRune('…')
			if strings.Contains(s, "\x1b[") {
				b.WriteString(reset)
			}
			return b.String()
		}
		b.WriteRune(r)
		cells++
		i += size
	}
	return b.String()
}

// Wrap breaks plain text into lines of at most w cells.
func Wrap(s string, w int) []string {
	if w < 10 {
		w = 10
	}
	var lines []string
	for _, para := range strings.Split(s, "\n") {
		line := ""
		for _, word := range strings.Fields(para) {
			switch {
			case line == "":
				line = word
			case Width(line)+1+Width(word) <= w:
				line += " " + word
			default:
				lines = append(lines, line)
				line = word
			}
			for Width(line) > w {
				r := []rune(line)
				lines = append(lines, string(r[:w]))
				line = string(r[w:])
			}
		}
		lines = append(lines, line)
	}
	return lines
}
