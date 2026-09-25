package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/cinc"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/target"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/ui"
)

func (a *app) installCINC(args []string) error {
	f := newFlags("install-cinc", `Install CINC on this machine or on a target: explicitly, and verified.

CINC Auditor (the scan engine) and CINC Client (the harden runtime) are in no
distribution repository, so no package manager installs them for you. This
command resolves the package for the target's platform on omnitruck.cinc.sh,
downloads it on this machine, checks the published SHA-256, streams it to the
target, checks it again there and installs it with dpkg or rpm. No installer
script is ever run, and the target needs no Internet access.`, "[target] [flags]")
	var client, both, printOnly, yes, sudo bool
	var ver, identity string
	var pkgs multi
	f.BoolVar(&client, "client", false, "install CINC Client (what harden needs) instead of CINC Auditor")
	f.BoolVar(&both, "both", false, "install CINC Auditor and CINC Client")
	f.StringVar(&ver, "version", "", "version to install (default: latest stable; a major such as 18 works)")
	f.Var(&pkgs, "package", "install from this local .deb/.rpm instead of downloading (air-gapped; repeatable)")
	f.BoolVar(&printOnly, "print", false, "print the verified install commands for the target and change nothing")
	f.BoolVar(&yes, "yes", false, "do not ask for confirmation")
	f.BoolVar(&sudo, "sudo", false, "install through sudo (non-interactive; SDW_SUDO_PASSWORD if it needs a password)")
	f.StringVar(&identity, "i", "", "SSH private key file")
	pos, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return usagef("one target at a time")
	}
	targetArg := ""
	if len(pos) == 1 {
		targetArg = pos[0]
	}
	t, err := target.Parse(targetArg)
	if err != nil {
		return usageError{err.Error()}
	}
	t.Sudo, t.Identity, t.SudoPassword = sudo, identity, os.Getenv("SDW_SUDO_PASSWORD")
	projects := []string{cinc.Auditor}
	switch {
	case both:
		projects = []string{cinc.Auditor, cinc.Client}
	case client:
		projects = []string{cinc.Client}
	}
	for _, pkg := range pkgs.vals {
		if cinc.ProjectOf(pkg) == "" || cinc.PkgType(pkg) == "" {
			return usagef("--package %s: expected a cinc-auditor or cinc .deb/.rpm package file", pkg)
		}
	}
	if t.Kind == target.Local && runtime.GOOS != "linux" {
		fmt.Fprintf(a.stdout, "On %s, download CINC Auditor from https://cinc.sh/start/auditor/ (downloads.cinc.sh publishes\na .sha256 next to each package): check it with `shasum -a 256 -c` before opening the installer.\nThe engine only needs to be on this machine to audit ssh:// and docker:// targets.\n", runtime.GOOS)
		if printOnly {
			return nil
		}
		return exitError{ExitPrereq, errors.New("automatic installation is only implemented for Linux (deb/rpm)")}
	}
	ctx, cancel := signalContext(30 * time.Minute)
	defer cancel()
	l := a.look()
	plat, perr := cinc.Detect(ctx, t)
	if printOnly {
		if perr != nil {
			return exitError{ExitPrereq, perr}
		}
		for _, proj := range projects {
			fmt.Fprintf(a.stdout, "# %s for %s (%s)\n%s\n", cinc.Label(proj), plat.Pretty, plat, cinc.Recipe(cinc.Base(), proj, plat, ver))
		}
		return nil
	}
	in := bufio.NewReader(os.Stdin)
	interactive := isTerminal(os.Stdin)
	hc := &http.Client{Timeout: 30 * time.Minute}
	failed := 0
	a.banner(false)
	for _, proj := range projects {
		bin := cinc.Binary(proj)
		fmt.Fprintln(a.stdout)
		fmt.Fprintln(a.stdout, l.section(strings.ToUpper(cinc.Label(proj)), "→ "+t.String()))
		if path, ok := t.Has(ctx, bin); ok {
			v, _ := t.Output(ctx, target.Quote(path)+" version 2>/dev/null | head -1", false)
			fmt.Fprintln(a.stdout, "   "+l.ok(l.ink("already installed")+l.muted(": "+path+" "+strings.TrimSpace(v))))
			continue
		}
		opts := cinc.Options{Version: ver, Packages: pkgs.vals, HTTP: hc}
		var rows [][2]string
		if file := opts.PackageFor(proj); file != "" {
			m, err := cinc.Local(file)
			if err != nil {
				return exitError{ExitUsage, err}
			}
			rows = [][2]string{{"package", l.ink(file)}, {"sha256", l.cyan(m.SHA256) + l.muted(" (the file you provided)")}}
		} else {
			if perr != nil {
				return exitError{ExitPrereq, perr}
			}
			m, err := cinc.Resolve(ctx, hc, cinc.Base(), proj, plat, ver)
			if err != nil {
				return exitError{ExitPrereq, err}
			}
			opts.Resolved = &m
			rows = [][2]string{
				{"platform", l.ink(plat.Pretty) + l.muted(" ("+plat.String()+")")},
				{"version", l.bold(ui.White, m.Version)},
				{"package", l.steel(m.URL)},
				{"sha256", l.cyan(m.SHA256) + l.muted(" published by omnitruck, checked before anything runs")},
			}
		}
		for _, r := range l.kv(rows) {
			fmt.Fprintln(a.stdout, "   "+ui.Trunc(r, l.w-4))
		}
		switch {
		case yes:
		case interactive:
			if !confirm(in, a.stdout, "Install it?") {
				fmt.Fprintln(a.stdout, "   "+l.muted("skipped, nothing changed."))
				continue
			}
		default:
			return usagef("no terminal to confirm: pass --yes (or --print to get the commands)")
		}
		err := a.installWithProgress(ctx, t, proj, opts)
		if err != nil {
			fmt.Fprintln(a.stdout, "   "+l.bad(l.paint(ui.Red, err.Error())))
			failed++
			continue
		}
		path, ok := t.Has(ctx, bin)
		if !ok {
			fmt.Fprintln(a.stdout, "   "+l.bad(l.paint(ui.Red, fmt.Sprintf("%s not found on %s after the installation", bin, t))))
			failed++
			continue
		}
		v, _ := t.Output(ctx, target.Quote(path)+" version 2>/dev/null | head -1", false)
		fmt.Fprintln(a.stdout, "   "+l.ok(l.bold(ui.Green, bin+" "+strings.TrimSpace(v))+l.muted(" installed · "+path)))
	}
	fmt.Fprintln(a.stdout)
	if failed > 0 {
		return exitError{ExitPrereq, fmt.Errorf("%d installation(s) failed", failed)}
	}
	return nil
}

// installWithProgress runs the verified installation with a live download
// bar and a checklist of its steps.
func (a *app) installWithProgress(ctx context.Context, t *target.Target, proj string, opts cinc.Options) error {
	l := a.look()
	term := ui.Detect(a.stdout, a.color)
	var mu sync.Mutex
	var done, total int64
	phase := "Downloading"
	start := time.Now()
	live := ui.NewLive(term, 80*time.Millisecond, func(f ui.Frame) []string {
		mu.Lock()
		defer mu.Unlock()
		glyph := l.p.Paint(ui.Along(ui.Brand, float64(f.N%24)/23), ui.Spin(f.N))
		head := "   " + glyph + " " + l.p.Shimmer(phase+"…", f.N, ui.Steel, ui.White)
		if phase != "Downloading" || done == 0 {
			return []string{head}
		}
		frac := 0.0
		size := "?"
		if total > 0 {
			frac = float64(done) / float64(total)
			size = humanBytes(total)
		}
		speed := float64(done) / time.Since(start).Seconds()
		return []string{head, "     " + l.p.Line(frac, max(10, min(40, f.Width-50)), ui.AlongFn(ui.Brand), ui.Hex("#1E293B")) + "  " +
			l.ink(humanBytes(done)+" / "+size) + l.muted(fmt.Sprintf("  %s/s", humanBytes(int64(speed))))}
	})
	opts.OnDownload = func(d, tot int64) {
		mu.Lock()
		done, total = d, tot
		mu.Unlock()
	}
	opts.Progress = func(s string) {
		mu.Lock()
		prev := phase
		switch {
		case strings.HasPrefix(s, "downloading"):
			phase = "Downloading"
		case strings.HasPrefix(s, "sha256 verified"):
			phase = "Installing with the package manager"
		case strings.HasPrefix(s, "installing"):
			phase = "Transferring and installing"
		}
		mu.Unlock()
		if strings.HasPrefix(s, "sha256 verified") {
			msg := l.ink(fmt.Sprintf("downloaded %s", humanBytes(total))) + l.muted(" · sha256 matches the published one")
			if prev == "Downloading" && live.Enabled() {
				live.Println("   " + l.ok(msg))
			} else {
				fmt.Fprintln(a.stdout, "   "+l.ok(msg))
			}
		}
	}
	live.Start()
	_, err := cinc.Install(ctx, t, proj, opts)
	live.Stop()
	if err == nil {
		fmt.Fprintln(a.stdout, "   "+l.ok(l.ink("sha256 checked again on the target, installed with the package manager")))
	}
	return err
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
