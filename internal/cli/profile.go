package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/catalog"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/scan"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/ui"
)

// profileFromFlags resolves --profile and the older --level. It returns ""
// when neither is set: the profile is then asked for (chooseProfile).
func (a *app) profileFromFlags(sf *scanFlags) (string, error) {
	var fromLevel string
	switch sf.level {
	case 0:
	case 1, 2:
		fromLevel = catalog.ProfileForLevel(sf.level)
	default:
		return "", usagef("--level must be 1 or 2 (or use --profile %s)", strings.Join(a.cat.ProfileKeys(), "|"))
	}
	if sf.profile == "" {
		return fromLevel, nil
	}
	key := a.profileKey(sf.profile)
	if key == "" {
		return "", usagef("unknown --profile %q (use %s)", sf.profile, strings.Join(a.cat.ProfileKeys(), ", "))
	}
	if fromLevel != "" && fromLevel != key {
		return "", usagef("--level %d is the %s profile, not %s: keep --profile only", sf.level, fromLevel, key)
	}
	return key, nil
}

// profileKey accepts a key, a title (English or French) or a number 1-3.
func (a *app) profileKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= len(a.cat.Profiles) {
		return a.cat.Profiles[n-1].Key
	}
	for _, p := range a.cat.Profiles {
		if s == p.Key || s == strings.ToLower(p.Title) || s == strings.ToLower(p.TitleFR) {
			return p.Key
		}
	}
	return ""
}

var errNoProfile = errors.New("no scan profile")

// chooseProfile makes sure a full scan has a profile: the one given on the
// command line, else the answer to a question on a terminal. Without a
// terminal (CI, cron, a script) the choice cannot be guessed: it is a usage
// error that lists the profiles. An explicit list of controls needs none.
func (a *app) chooseProfile(o *scan.Options) error {
	if o.Filter.Profile != "" || len(o.Filter.IDs) > 0 {
		return nil
	}
	if !isTerminal(os.Stdin) || !isTerminal(a.stderr) {
		return usageError{a.profileMissing()}
	}
	key, err := a.pickProfile(bufio.NewReader(os.Stdin), a.stderr, o.Filter)
	if err != nil {
		return usageError{a.profileMissing()}
	}
	o.Filter.Profile = key
	return nil
}

func (a *app) profileMissing() string {
	var b strings.Builder
	b.WriteString("choose a scan profile with --profile:\n")
	for _, p := range a.cat.Profiles {
		fmt.Fprintf(&b, "  %-9s %s\n            e.g. %s\n", p.Key, p.Summary, lowerFirst(p.Example))
	}
	b.WriteString("(on a terminal, sdw-armor asks)")
	return b.String()
}

// pickProfile shows the profiles, with the number of controls each one runs
// under the other filters, and reads the choice: a number, a key or a title.
func (a *app) pickProfile(in *bufio.Reader, w io.Writer, f catalog.Filter) (string, error) {
	l := a.look()
	fmt.Fprintln(w)
	fmt.Fprintln(w, l.section("SCAN PROFILE", "--profile skips this question"))
	for i, p := range a.cat.Profiles {
		f.Profile = p.Key
		n := len(a.cat.Select(f))
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  "+l.bold(ui.Cyan, strconv.Itoa(i+1))+"  "+ui.Pad(l.bold(ui.Ink, p.Title), 10)+l.muted(fmt.Sprintf("%3d controls", n)))
		for _, line := range ui.Wrap(p.Summary, l.w-6) {
			fmt.Fprintln(w, "     "+l.steel(line))
		}
		for _, line := range ui.Wrap("e.g. "+lowerFirst(p.Example), l.w-6) {
			fmt.Fprintln(w, "     "+l.ink(line))
		}
	}
	fmt.Fprintln(w)
	for tries := 0; tries < 5; tries++ {
		fmt.Fprintf(w, "  Profile [1-%d]: ", len(a.cat.Profiles))
		line, err := in.ReadString('\n')
		if key := a.profileKey(line); key != "" {
			p, _ := a.cat.ProfileByKey(key)
			fmt.Fprintln(w, "  "+l.ok(l.ink(p.Title)+l.muted(" (next time: --profile "+p.Key+")")))
			return key, nil
		}
		if err != nil {
			fmt.Fprintln(w)
			return "", errNoProfile
		}
		if strings.TrimSpace(line) != "" {
			fmt.Fprintln(w, "  "+l.warn(l.ink(fmt.Sprintf("%q is not a profile: type a number from 1 to %d", strings.TrimSpace(line), len(a.cat.Profiles)))))
		}
	}
	return "", errNoProfile
}

// lowerFirst writes an example after "e.g.": "A private server" becomes "a
// private server".
func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}
