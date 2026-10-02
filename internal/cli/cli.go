// Package cli implements the sdw-armor command line.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	shadowarmor "github.com/Shadow-Security-official/Shadow-Armor"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/catalog"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/ui"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/version"
)

// Exit codes (documented in docs/CLI.md).
const (
	ExitOK          = 0
	ExitPolicy      = 1 // --fail-under / --fail-on-regression not met, or harden left failures
	ExitUsage       = 2
	ExitPrereq      = 3 // engine missing, target unreachable
	ExitEngineError = 4
)

type app struct {
	stdout, stderr io.Writer
	color          bool
	cat            *catalog.Catalog
	sudoHint       bool // suggest --sudo in the commands a report prints
}

// usageError is reported with exit code 2.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

// exitError carries a specific exit code.
type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}

// Main runs the CLI and returns the process exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	cat, err := catalog.Load(shadowarmor.Profile)
	if err != nil {
		fmt.Fprintln(stderr, "sdw-armor: embedded catalog is broken:", err)
		return ExitEngineError
	}
	a := &app{stdout: stdout, stderr: stderr, cat: cat, color: colorEnabled(stdout)}
	// --no-color is accepted by every command, anywhere on the line.
	kept := args[:0:0]
	for _, x := range args {
		if x == "--no-color" || x == "-no-color" {
			a.color = false
			continue
		}
		kept = append(kept, x)
	}
	args = kept
	if len(args) == 0 {
		a.help(stdout)
		return ExitOK
	}
	cmd, rest := args[0], args[1:]
	var run func([]string) error
	switch cmd {
	case "scan", "audit":
		run = a.scan
	case "harden", "fix":
		run = a.harden
	case "explain", "show":
		run = a.explain
	case "list", "ls":
		run = a.list
	case "report", "render":
		run = a.report
	case "diff":
		run = a.diff
	case "doctor":
		run = a.doctor
	case "install-cinc":
		run = a.installCINC
	case "update":
		run = a.update
	case "upgrade":
		run = a.upgrade
	case "export":
		run = a.export
	case "version", "--version", "-V":
		run = a.versionCmd
	case "help", "-h", "--help":
		if len(rest) > 0 {
			return Main([]string{rest[0], "-h"}, stdout, stderr)
		}
		a.help(stdout)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "sdw-armor: unknown command %q\n\n", cmd)
		a.help(stderr)
		return ExitUsage
	}
	err = run(rest)
	if err == nil {
		return ExitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	var ue usageError
	if errors.As(err, &ue) {
		fmt.Fprintf(stderr, "sdw-armor %s: %s\n", cmd, ue.msg)
		return ExitUsage
	}
	var ee exitError
	if errors.As(err, &ee) {
		if ee.err != nil && ee.Error() != "" {
			fmt.Fprintf(stderr, "sdw-armor %s: %s\n", cmd, ee.Error())
		}
		return ee.code
	}
	fmt.Fprintf(stderr, "sdw-armor %s: %v\n", cmd, err)
	return ExitEngineError
}

func (a *app) versionCmd(args []string) error {
	fs := newFlags("version", "Print version information.", "")
	if _, err := fs.parse(args); err != nil {
		return err
	}
	l := a.look()
	row := func(k, v string) { fmt.Fprintln(a.stdout, l.muted(fmt.Sprintf("%-9s ", k))+l.ink(v)) }
	fmt.Fprintln(a.stdout, l.gradient("sdw-armor", ui.Brand...)+" "+l.bold(ui.White, version.Version))
	if version.Commit != "" {
		row("commit", version.Commit)
	}
	if version.Date != "" {
		row("built", version.Date)
	}
	row("controls", fmt.Sprintf("%d across %d pillars (catalog schema %d)", len(a.cat.Controls), len(a.cat.Pillars), a.cat.Schema))
	return nil
}

func colorEnabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" || os.Getenv("CLICOLOR_FORCE") == "1" {
		return true
	}
	return isTerminal(w)
}

func isTerminal(w io.Writer) bool {
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

// ---- flag parsing with interspersed positionals -----------------------------

type flags struct {
	*flag.FlagSet
	usage    string
	synopsis string
	out      io.Writer
}

func newFlags(name, synopsis, usage string) *flags {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	f := &flags{FlagSet: fs, usage: usage, synopsis: synopsis, out: os.Stderr}
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return f
}

func (f *flags) printHelp(w io.Writer) {
	fmt.Fprintf(w, "%s\n\nUsage:\n  sdw-armor %s %s\n\nFlags:\n", f.synopsis, f.Name(), f.usage)
	f.SetOutput(w)
	f.PrintDefaults()
	f.SetOutput(io.Discard)
}

// parse accepts flags anywhere on the command line and returns positionals.
func (f *flags) parse(args []string) ([]string, error) {
	var pos []string
	for {
		if err := f.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				f.printHelp(os.Stdout)
				return nil, flag.ErrHelp
			}
			return nil, usageError{err.Error()}
		}
		rest := f.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		if rest[0] == "--" {
			return append(pos, rest[1:]...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// multi is a repeatable string flag that also splits on commas when asked.
type multi struct {
	vals  []string
	split bool
}

func (m *multi) String() string { return strings.Join(m.vals, ",") }
func (m *multi) Set(v string) error {
	if m.split {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				m.vals = append(m.vals, p)
			}
		}
		return nil
	}
	m.vals = append(m.vals, v)
	return nil
}

// banner prints the logo on stderr, for people at a terminal.
func (a *app) banner(quiet bool) {
	if quiet || !isTerminal(a.stderr) {
		return
	}
	t := ui.Detect(a.stderr, a.color)
	v := version.Version
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	fmt.Fprintln(a.stderr)
	for _, l := range t.Profile.Banner(t.Width, v, fmt.Sprintf("%d controls · %d pillars", len(a.cat.Controls), len(a.cat.Pillars))) {
		fmt.Fprintln(a.stderr, l)
	}
	fmt.Fprintln(a.stderr)
}
