// Package ui draws Shadow-Armor's terminal interface: colour profiles and
// gradients, big block lettering, boxes, bars and live (animated) regions.
// Standard library only. Everything degrades: no colour when NO_COLOR is set
// or the output is not a terminal, no animation off a terminal, plain
// layouts at any width.
package ui

import (
	"io"
	"os"
	"strconv"
	"strings"
)

// Profile is how many colours the terminal renders.
type Profile int

const (
	NoColor Profile = iota
	Basic           // 16 colours
	Ansi256
	TrueColor
)

// Term describes an output: is it a terminal, how wide, which colours.
type Term struct {
	W       io.Writer
	TTY     bool
	Width   int
	Profile Profile
}

// IsTerminal reports whether w is a character device.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

// Detect inspects w and the environment. color=false forces no colour.
func Detect(w io.Writer, color bool) Term {
	t := Term{W: w, TTY: IsTerminal(w), Width: 100}
	if f, ok := w.(*os.File); ok && t.TTY {
		if n := termWidth(f); n > 0 {
			t.Width = n
		}
	}
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n > 20 && !t.TTY {
		t.Width = n
	}
	if color {
		t.Profile = ColorProfile()
	}
	return t
}

// ColorProfile reads the colour depth from the environment.
func ColorProfile() Profile {
	ct := strings.ToLower(os.Getenv("COLORTERM"))
	term := strings.ToLower(os.Getenv("TERM"))
	switch {
	case term == "dumb":
		return NoColor
	case ct == "truecolor" || ct == "24bit" || os.Getenv("WT_SESSION") != "" ||
		strings.Contains(term, "truecolor") || strings.Contains(term, "direct") ||
		os.Getenv("TERM_PROGRAM") == "iTerm.app" || os.Getenv("TERM_PROGRAM") == "WezTerm" || os.Getenv("TERM_PROGRAM") == "vscode":
		return TrueColor
	case strings.Contains(term, "256"):
		return Ansi256
	case os.Getenv("GITHUB_ACTIONS") == "true" || os.Getenv("CI") != "":
		return Ansi256
	}
	return Basic
}

// Refresh re-reads the width of a terminal (it may have been resized).
func (t *Term) Refresh() {
	if f, ok := t.W.(*os.File); ok && t.TTY {
		if n := termWidth(f); n > 0 {
			t.Width = n
		}
	}
}
