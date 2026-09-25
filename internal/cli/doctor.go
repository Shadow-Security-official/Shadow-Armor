package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/engine"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/target"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/ui"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/version"
)

func (a *app) doctor(args []string) error {
	f := newFlags("doctor", "Check prerequisites on this machine and, when given, on a target.", "[target] [flags]")
	var sudo bool
	var identity, eng, image string
	f.BoolVar(&sudo, "sudo", false, "check that non-interactive sudo works on the target")
	f.StringVar(&identity, "i", "", "SSH private key file")
	f.StringVar(&eng, "engine", "", "local engine path")
	f.StringVar(&image, "engine-image", "", "image of the Docker engine")
	pos, err := f.parse(args)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	l := a.look()
	failed := 0
	row := func(mark, what, detail string) {
		fmt.Fprintln(a.stdout, "   "+mark+" "+ui.Pad(l.ink(what), 24)+" "+l.steel(ui.Trunc(detail, l.w-32)))
	}
	ok := func(good bool, what, detail, hint string) {
		mark := l.paint(ui.Green, "✓")
		if !good {
			mark = l.paint(ui.Red, "✗")
			failed++
		}
		row(mark, what, detail)
		if !good && hint != "" {
			for i, h := range ui.Wrap(hint, l.w-12) {
				br := "   "
				if i == 0 {
					br = "╰─ "
				}
				fmt.Fprintln(a.stdout, "     "+l.faint(br)+l.cyan(h))
			}
		}
	}
	info := func(what, detail string) { row(l.paint(ui.Violet, "•"), what, detail) }
	a.banner(false)
	fmt.Fprintln(a.stdout, l.section("THIS MACHINE", ""))
	info("sdw-armor", version.Version+fmt.Sprintf(" (%d controls embedded)", len(a.cat.Controls)))
	e, err := engine.Find(ctx, eng)
	if err != nil {
		ok(false, "local engine", err.Error(), "CINC Auditor is in no distribution repository: `sdw-armor install-cinc --sudo` installs a SHA-256 verified package (asks first), `sdw-armor install-cinc --print` shows the commands; or scan with --on-target")
	} else {
		ok(e.Major() >= 5, "local engine", fmt.Sprintf("%s %s (%s)", e.Name, e.Version, e.Path), "InSpec/CINC Auditor 5 or newer is required")
	}
	img := engine.ImageRef(image)
	if derr := engine.DockerReady(ctx); derr != nil {
		info("docker engine", "unavailable ("+strings.TrimPrefix(derr.Error(), engine.ErrDockerUnavailable.Error()+": ")+")")
	} else if digest, present := engine.ImageDigest(ctx, img); present {
		info("docker engine", "ready: "+img+shortDigest(digest)+" (--engine docker; auto when no native engine)")
	} else {
		info("docker engine", "docker is ready; "+img+" is not pulled yet (--engine docker pulls it)")
	}
	info("running as", fmt.Sprintf("uid %d", os.Geteuid()))

	if len(pos) == 1 {
		t, err := target.Parse(pos[0])
		if err != nil {
			return usageError{err.Error()}
		}
		t.Sudo, t.Identity = sudo, identity
		fmt.Fprintln(a.stdout)
		fmt.Fprintln(a.stdout, l.section("TARGET", t.String()))
		switch t.Kind {
		case target.SSH:
			_, lerr := exec.LookPath("ssh")
			ok(lerr == nil, "ssh client", "uses your ~/.ssh/config, agent and ProxyJump", "install an OpenSSH client")
		case target.Docker:
			_, lerr := exec.LookPath("docker")
			ok(lerr == nil, "docker CLI", "", "install the docker CLI")
		}
		user, err := t.Probe(ctx)
		ok(err == nil, "reachable", user, fmt.Sprint(err))
		if err == nil {
			if sudo {
				_, serr := t.Output(ctx, "true", true)
				ok(serr == nil, "non-interactive sudo", "", "allow NOPASSWD for the audit account, or set SDW_SUDO_PASSWORD")
			} else if user != "root" {
				fmt.Fprintln(a.stdout, "     "+l.faint("╰─ ")+l.paint(ui.Amber, "not root: pass --sudo so the probes that need root can run"))
			}
			if path, has := t.Has(ctx, "cinc-auditor"); has {
				info("cinc-auditor on target", path+" (--on-target available)")
			} else {
				info("cinc-auditor on target", fmt.Sprintf("absent (only --on-target needs it: sdw-armor install-cinc %s --sudo, or --bootstrap-cinc)", t))
			}
			if path, has := t.Has(ctx, "cinc-client"); has {
				info("cinc-client on target", path+" (harden available)")
			} else {
				info("cinc-client on target", fmt.Sprintf("absent (harden needs it: sdw-armor install-cinc %s --client --sudo, or --bootstrap-cinc)", t))
			}
			osr, _ := t.Output(ctx, ". /etc/os-release 2>/dev/null && echo \"$PRETTY_NAME\"", false)
			info("operating system", osr)
			init, _ := t.Output(ctx, "[ -d /run/systemd/system ] && echo systemd || (ps -o comm= -p 1 2>/dev/null || echo unknown)", false)
			info("init", strings.TrimSpace(init))
			ctr, _ := t.Output(ctx, "[ -f /.dockerenv ] && echo docker || ([ -f /run/.containerenv ] && echo podman) || echo none", false)
			info("container", ctr+" (host-level controls are skipped in containers)")
			if _, has := t.Has(ctx, "sshd"); has {
				info("sshd", "present (audited with sshd -T)")
			}
		}
	}
	fmt.Fprintln(a.stdout)
	if failed > 0 {
		fmt.Fprintln(a.stdout, "   "+l.bad(l.bold(ui.Red, fmt.Sprintf("%d check(s) failed", failed)))+l.muted(": the fix is under each one"))
		fmt.Fprintln(a.stdout)
		return exitError{ExitPrereq, fmt.Errorf("%d check(s) failed", failed)}
	}
	fmt.Fprintln(a.stdout, "   "+l.ok(l.bold(ui.Green, "ready")))
	fmt.Fprintln(a.stdout)
	return nil
}

func shortDigest(d string) string {
	if i := strings.Index(d, "@sha256:"); i >= 0 && len(d) >= i+8+12 {
		return " @" + d[i+1:i+8+12]
	}
	return ""
}
