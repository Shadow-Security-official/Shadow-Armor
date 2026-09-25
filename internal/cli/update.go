package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/selfupdate"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/ui"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/version"
)

// Seams for tests: the binary to replace and the signature check.
var (
	executable      = os.Executable
	verifySignature = selfupdate.VerifySignature
)

func releaseClient() *selfupdate.Client {
	return &selfupdate.Client{
		HTTP:      &http.Client{Timeout: 15 * time.Minute},
		API:       selfupdate.API(),
		UserAgent: "sdw-armor/" + version.Version,
	}
}

// update checks for a newer release and installs nothing.
func (a *app) update(args []string) error {
	f := newFlags("update", `Check whether a newer sdw-armor release is published. Nothing is downloaded
or installed: run sdw-armor upgrade for that.

Exit code 0 when this is the latest release, 1 when a newer one exists, 3 when
the releases cannot be read (network, rate limit).`, "[flags]")
	pos, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("update takes no argument")
	}
	ctx, cancel := signalContext(time.Minute)
	defer cancel()
	l := a.look()
	a.banner(false)
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, l.section("UPDATE", "releases of "+selfupdate.Repo))
	rel, err := releaseClient().Latest(ctx)
	if err != nil {
		return exitError{ExitPrereq, err}
	}
	cur := version.Version
	rows := [][2]string{
		{"installed", l.ink(cur) + devNote(l, cur)},
		{"latest", l.bold(ui.White, rel.Version()) + l.muted(" · published "+rel.Published.Format("2006-01-02")+" · "+rel.URL)},
	}
	for _, r := range l.kv(rows) {
		fmt.Fprintln(a.stdout, "   "+ui.Trunc(r, l.w-4))
	}
	fmt.Fprintln(a.stdout)
	switch c := selfupdate.Compare(rel.Version(), cur); {
	case !selfupdate.IsRelease(cur):
		fmt.Fprintln(a.stdout, "   "+l.warn(l.ink("development build: sdw-armor upgrade --force installs release "+rel.Version())))
		return nil
	case c <= 0:
		fmt.Fprintln(a.stdout, "   "+l.ok(l.bold(ui.Green, "up to date")))
		return nil
	}
	fmt.Fprintln(a.stdout, "   "+l.paint(ui.Cyan, "↑")+" "+l.bold(ui.Cyan, rel.Version()+" is available"))
	if notes := rel.Notes(5); len(notes) > 0 {
		fmt.Fprintln(a.stdout)
		for _, n := range notes {
			fmt.Fprintln(a.stdout, "     "+l.faint("·")+" "+l.steel(ui.Trunc(n, l.w-8)))
		}
		fmt.Fprintln(a.stdout, "     "+l.muted("… "+rel.URL))
	}
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, "   "+l.paint(ui.Violet, "❯ ")+l.cyan(sudoPrefix()+"sdw-armor upgrade")+l.muted("   download, verify and install it"))
	return exitError{ExitPolicy, nil}
}

func devNote(l look, v string) string {
	if selfupdate.IsRelease(v) {
		return ""
	}
	return l.muted(" (development build)")
}

func sudoPrefix() string {
	if os.Geteuid() == 0 {
		return ""
	}
	return "sudo "
}

// upgrade downloads, verifies and installs the latest (or a given) release.
func (a *app) upgrade(args []string) error {
	f := newFlags("upgrade", `Download, verify and install the latest sdw-armor release in place of the
running binary.

The file is checked against the release's SHA256SUMS before anything is
replaced. When cosign is installed, the signature of SHA256SUMS is verified
too (it must come from this project's release workflow); otherwise, the GitHub
CLI (2.49+, logged in) verifies the build provenance. --strict refuses to
install when neither is available. The new binary must run and report the
expected version before it replaces the old one (an atomic rename). A binary
installed by the .deb or .rpm package is upgraded with dpkg or rpm instead.`, "[flags]")
	var yes, strict, force bool
	var want string
	f.StringVar(&want, "version", "", "install this release (vX.Y.Z) instead of the latest, e.g. to go back")
	f.BoolVar(&yes, "yes", false, "do not ask for confirmation")
	f.BoolVar(&strict, "strict", false, "refuse to install unless cosign or the GitHub CLI verified who built the release")
	f.BoolVar(&force, "force", false, "reinstall the same version, or replace a development build")
	pos, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("upgrade takes no argument (use --version vX.Y.Z)")
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return exitError{ExitPrereq, fmt.Errorf("no release for %s", runtime.GOOS)}
	}
	ctx, cancel := signalContext(30 * time.Minute)
	defer cancel()
	l := a.look()
	a.banner(false)
	cl := releaseClient()
	var rel selfupdate.Release
	if want != "" {
		rel, err = cl.ByTag(ctx, want)
	} else {
		rel, err = cl.Latest(ctx)
	}
	if err != nil {
		return exitError{ExitPrereq, err}
	}
	cur := version.Version
	exe, err := executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return exitError{ExitPrereq, fmt.Errorf("cannot locate the running binary: %w", err)}
	}
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, l.section("UPGRADE", exe))
	cmp := selfupdate.Compare(rel.Version(), cur)
	switch {
	case !selfupdate.IsRelease(cur) && !force:
		fmt.Fprintln(a.stdout, "   "+l.warn(l.ink("this is a development build ("+cur+"): pass --force to replace it with release "+rel.Version())))
		return nil
	case cmp == 0 && !force:
		fmt.Fprintln(a.stdout, "   "+l.ok(l.ink("sdw-armor "+cur+" is the latest release: nothing to do")))
		return nil
	case cmp < 0 && want == "" && !force:
		fmt.Fprintln(a.stdout, "   "+l.ok(l.ink("sdw-armor "+cur+" is newer than the latest release ("+rel.Version()+"): nothing to do")))
		return nil
	}

	how := selfupdate.Installer(ctx, exe)
	var asset string
	var method string
	switch how {
	case "deb", "rpm":
		if os.Geteuid() != 0 {
			return exitError{ExitPrereq, fmt.Errorf("%s is owned by the sdw-armor %s package: run sudo sdw-armor upgrade", exe, how)}
		}
		asset = selfupdate.PackageName(how, rel.Version(), runtime.GOARCH)
		method = map[string]string{"deb": "dpkg -i", "rpm": "rpm -U"}[how] + " (the sdw-armor package owns " + exe + ")"
	default:
		if err := writable(filepath.Dir(exe)); err != nil {
			return exitError{ExitPrereq, fmt.Errorf("cannot write to %s: run %ssdw-armor upgrade", filepath.Dir(exe), sudoPrefix())}
		}
		asset = selfupdate.BinaryName(runtime.GOOS, runtime.GOARCH)
		method = "replace " + exe + " (atomic rename)"
	}
	file, ok := rel.Asset(asset)
	if !ok {
		return exitError{ExitPrereq, fmt.Errorf("release %s has no %s", rel.Tag, asset)}
	}
	sums, ok := rel.Asset(selfupdate.SumsFile)
	if !ok {
		return exitError{ExitPrereq, fmt.Errorf("release %s has no %s: refusing to install an unverifiable file", rel.Tag, selfupdate.SumsFile)}
	}
	rows := [][2]string{
		{"installed", l.ink(cur) + devNote(l, cur)},
		{"release", l.bold(ui.White, rel.Version()) + l.muted(" · published "+rel.Published.Format("2006-01-02")+" · "+rel.URL)},
		{"file", l.ink(asset) + l.muted(" · "+humanBytes(file.Size))},
		{"install", l.steel(method)},
	}
	for _, r := range l.kv(rows) {
		fmt.Fprintln(a.stdout, "   "+ui.Trunc(r, l.w-4))
	}
	switch {
	case yes:
	case isTerminal(os.Stdin):
		verb := "Install"
		if cmp < 0 {
			verb = "Go back to"
		}
		if !confirm(bufio.NewReader(os.Stdin), a.stdout, verb+" sdw-armor "+rel.Version()+"?") {
			fmt.Fprintln(a.stdout, "   "+l.muted("nothing changed."))
			return nil
		}
	default:
		return usagef("no terminal to confirm: pass --yes")
	}

	dir, err := os.MkdirTemp("", "sdw-armor-upgrade-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	sumsPath := filepath.Join(dir, selfupdate.SumsFile)
	if _, err := cl.Download(ctx, sums.URL, sumsPath, nil); err != nil {
		return exitError{ExitPrereq, err}
	}
	raw, err := os.ReadFile(sumsPath)
	if err != nil {
		return err
	}
	expected := selfupdate.ParseSums(raw)[asset]
	if expected == "" {
		return exitError{ExitPrereq, fmt.Errorf("%s of %s does not list %s: refusing to install it", selfupdate.SumsFile, rel.Tag, asset)}
	}
	path := filepath.Join(dir, asset)
	got, err := a.downloadWithBar(ctx, cl, file, path)
	if err != nil {
		return exitError{ExitPrereq, err}
	}
	if got != expected {
		return exitError{ExitPrereq, fmt.Errorf("SHA-256 mismatch for %s: got %s, %s says %s. Nothing was changed", asset, got, selfupdate.SumsFile, expected)}
	}
	fmt.Fprintln(a.stdout, "   "+l.ok(l.ink("downloaded "+humanBytes(file.Size))+l.muted(" · sha256 matches "+selfupdate.SumsFile)))

	bundle := ""
	if sig, ok := rel.Asset(selfupdate.SigFile); ok {
		bundle = filepath.Join(dir, selfupdate.SigFile)
		if _, err := cl.Download(ctx, sig.URL, bundle, nil); err != nil {
			bundle = ""
		}
	}
	v, err := verifySignature(ctx, sumsPath, bundle, path)
	switch {
	case err != nil:
		return exitError{ExitPrereq, fmt.Errorf("%v. Nothing was changed", err)}
	case v.Tool != "":
		fmt.Fprintln(a.stdout, "   "+l.ok(l.ink(v.Tool+": ")+l.steel(v.Detail)))
	case strict:
		return exitError{ExitPrereq, errors.New("--strict: neither cosign nor a logged-in GitHub CLI (2.49+) is available to verify who built the release. Nothing was changed")}
	default:
		fmt.Fprintln(a.stdout, "   "+l.warn(l.steel("who built it is not checked: install cosign (or gh 2.49+, logged in) for that; --strict requires it")))
	}

	switch how {
	case "deb", "rpm":
		cmdline := []string{"dpkg", "-i", path}
		if how == "rpm" {
			cmdline = []string{"rpm", "-U", "--replacepkgs", path}
			if cmp < 0 {
				cmdline = []string{"rpm", "-U", "--oldpackage", "--replacepkgs", path}
			}
		}
		if out, err := exec.CommandContext(ctx, cmdline[0], cmdline[1:]...).CombinedOutput(); err != nil {
			return exitError{ExitEngineError, fmt.Errorf("%s failed: %s", strings.Join(cmdline[:2], " "), lastLines(string(out), 5))}
		}
		fmt.Fprintln(a.stdout, "   "+l.ok(l.ink("installed with "+cmdline[0])))
	default:
		if err := os.Chmod(path, 0o700); err != nil { //nolint:gosec // in a private 0700 directory, executable to be tested before it is installed
			return err
		}
		if got, err := binaryVersion(ctx, path); err != nil || got != rel.Version() {
			return exitError{ExitPrereq, fmt.Errorf("the downloaded binary does not run as expected (%q, %v). Nothing was changed", got, err)}
		}
		fmt.Fprintln(a.stdout, "   "+l.ok(l.ink("the new binary runs: sdw-armor "+rel.Version())))
		if err := replaceFile(exe, path); err != nil {
			return exitError{ExitPrereq, err}
		}
	}
	now, err := binaryVersion(ctx, exe)
	if err != nil || now != rel.Version() {
		return exitError{ExitEngineError, fmt.Errorf("%s reports %q after the upgrade (%v)", exe, now, err)}
	}
	fmt.Fprintln(a.stdout, "   "+ui.Trunc(l.ok(l.bold(ui.Green, "sdw-armor "+cur+" → "+now)+l.muted(" · "+exe)), l.w-4))
	fmt.Fprintln(a.stdout, "   "+l.muted("release notes: "+rel.URL))
	return nil
}

// downloadWithBar downloads one release file with a live progress bar.
func (a *app) downloadWithBar(ctx context.Context, cl *selfupdate.Client, file selfupdate.Asset, dest string) (string, error) {
	l := a.look()
	var mu sync.Mutex
	var done, total int64
	total = file.Size
	start := time.Now()
	live := ui.NewLive(ui.Detect(a.stdout, a.color), 80*time.Millisecond, func(f ui.Frame) []string {
		mu.Lock()
		defer mu.Unlock()
		glyph := l.p.Paint(ui.Along(ui.Brand, float64(f.N%24)/23), ui.Spin(f.N))
		head := "   " + glyph + " " + l.p.Shimmer("Downloading "+file.Name+"…", f.N, ui.Steel, ui.White)
		frac := 0.0
		if total > 0 {
			frac = float64(done) / float64(total)
		}
		speed := float64(done) / max(time.Since(start).Seconds(), 0.001)
		return []string{head, "     " + l.p.Line(frac, max(10, min(40, f.Width-50)), ui.AlongFn(ui.Brand), ui.Hex("#1E293B")) + "  " +
			l.ink(humanBytes(done)+" / "+humanBytes(total)) + l.muted(fmt.Sprintf("  %s/s", humanBytes(int64(speed))))}
	})
	live.Start()
	sum, err := cl.Download(ctx, file.URL, dest, func(d, t int64) {
		mu.Lock()
		done = d
		if t > 0 {
			total = t
		}
		mu.Unlock()
	})
	live.Stop()
	return sum, err
}

// binaryVersion runs "<path> version" and returns the version it reports.
func binaryVersion(ctx context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "version", "--no-color").Output()
	if err != nil {
		return "", err
	}
	first := strings.Fields(strings.SplitN(string(out), "\n", 2)[0])
	if len(first) < 2 || first[0] != "sdw-armor" {
		return "", fmt.Errorf("unexpected output %q", strings.TrimSpace(string(out)))
	}
	return first[1], nil
}

// writable checks that files can be created in dir.
func writable(dir string) error {
	f, err := os.CreateTemp(dir, ".sdw-armor-write-test-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

// replaceFile puts src in place of dst with an atomic rename in dst's
// directory, keeping dst's permissions. A running dst keeps working.
func replaceFile(dst, src string) error {
	mode := os.FileMode(0o755)
	if st, err := os.Stat(dst); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".sdw-armor-upgrade-*")
	if err != nil {
		return fmt.Errorf("cannot write next to %s: %w", dst, err)
	}
	in, err := os.Open(src)
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	_, err = io.Copy(tmp, in)
	_ = in.Close()
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), mode)
	}
	if err == nil {
		err = os.Rename(tmp.Name(), dst)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("replace %s: %w", dst, err)
	}
	return nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
