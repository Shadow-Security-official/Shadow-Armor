package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/harden"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/scan"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/target"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/ui"
)

// The reboot is detached so the SSH session can close cleanly first.
const rebootScript = `nohup sh -c 'sleep 2; systemctl reboot 2>/dev/null || shutdown -r now 2>/dev/null || reboot' >/dev/null 2>&1 &`

// rebootAndProve reboots the target after a harden run, waits for the new
// boot and re-scans it with the pre-reboot report as reboot baseline.
func (a *app) rebootAndProve(ctx context.Context, sf *scanFlags, o scan.Options, plan *harden.Plan, base, pre *model.Report, specs []outputSpec, ask bool, in *bufio.Reader, timeout time.Duration) error {
	l := a.look()
	t := o.Target
	if pre == nil || pre.Target.Host == nil || pre.Target.Host.BootID == "" {
		return exitError{ExitPrereq, fmt.Errorf("cannot read the boot identity of %s (/proc/sys/kernel/random/boot_id): the reboot could not be proven", t)}
	}
	if ask && !confirm(in, a.stdout, fmt.Sprintf("Reboot %s now to prove these fixes survive a real reboot?", t)) {
		fmt.Fprintln(a.stdout, "  "+l.muted("not rebooted. To prove it later: save this state (-o json:before.json), reboot, then run"))
		fmt.Fprintln(a.stdout, "    "+l.paint(ui.Violet, "❯ ")+l.cyan(fmt.Sprintf("sdw-armor scan %s --reboot-baseline before.json", t)))
		return nil
	}
	oldBoot := pre.Target.Host.BootID
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, l.section("REBOOT", fmt.Sprintf("%s · boot %s", t, shortID(oldBoot))))
	if _, err := t.Run(ctx, rebootScript, true, nil, io.Discard, io.Discard); err != nil {
		return exitError{ExitEngineError, fmt.Errorf("reboot %s: %w", t, err)}
	}
	start := time.Now()
	term := ui.Detect(a.stdout, a.color)
	var mu sync.Mutex
	phase := "Waiting for " + t.String() + " to go down and come back"
	live := ui.NewLive(term, 90*time.Millisecond, func(f ui.Frame) []string {
		mu.Lock()
		defer mu.Unlock()
		glyph := l.p.Paint(ui.Along(ui.Brand, float64(f.N%24)/23), ui.Spin(f.N))
		return []string{"   " + glyph + " " + l.p.Shimmer(phase+"…", f.N, ui.Steel, ui.White) + "  " + l.muted(ui.Clock(f.Elapsed)+" · boot "+shortID(oldBoot)+" → ?")}
	})
	live.Start()
	h, err := waitForNewBoot(ctx, t, oldBoot, timeout, func(s string) {
		if !live.Enabled() && !sf.quiet {
			fmt.Fprintln(a.stderr, "   "+l.muted("› "+s))
		}
	})
	if err != nil {
		live.Stop()
		return exitError{ExitPrereq, err}
	}
	mu.Lock()
	phase = "Waiting for the boot to finish (systemctl is-system-running --wait)"
	mu.Unlock()
	back := time.Since(start).Round(time.Second)
	// Let the boot finish: runtime checks must see the services the boot starts.
	settle, cancel := context.WithTimeout(ctx, 5*time.Minute)
	state, _ := t.Output(settle, "systemctl is-system-running --wait 2>/dev/null || true", true)
	cancel()
	live.Stop()
	fmt.Fprintln(a.stdout, "   "+l.ok(l.ink(fmt.Sprintf("back after %s", back))+l.muted(fmt.Sprintf(" · new boot %s", shortID(h.BootID)))))
	if state = strings.TrimSpace(state); state != "" {
		fmt.Fprintln(a.stdout, "   "+l.ok(l.ink("system "+state)))
	}

	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, l.section("AFTER THE REBOOT", "every selected control, against the pre-reboot state"))
	o.RebootBaseline = pre
	post, err := a.runScan(ctx, sf, o)
	if err != nil {
		return err
	}
	res := map[string]model.ControlResult{}
	for _, c := range post.Controls {
		res[c.ID] = c
	}
	notProven := 0
	for _, it := range plan.Items {
		c, ok := res[it.Control]
		mark, now := l.paint(ui.Green, "✓"), l.muted("not audited")
		switch {
		case ok && c.Status == model.Pass && c.Proof != nil && c.Proof.Reboot == model.ProofProven:
			now = l.paint(ui.Green, "pass · reboot-proven")
		case ok && c.Status == model.Pass:
			now = l.paint(ui.Green, "pass") + l.muted(" · fixed by the reboot")
		default:
			mark = l.paint(ui.Red, "✗")
			if ok {
				now = l.paint(ui.Red, string(c.Status))
			}
			notProven++
		}
		left := fmt.Sprintf("   %s %s  %s", mark, l.bold(ui.Ink, it.Control), l.ink(it.Title))
		room := l.w - ui.Width(now) - 2
		fmt.Fprintln(a.stdout, ui.Pad(ui.Trunc(left, room), room)+" "+now)
	}
	var proven, lost []string
	for _, c := range post.Controls {
		if c.Proof == nil {
			continue
		}
		switch c.Proof.Reboot {
		case model.ProofProven:
			proven = append(proven, c.ID)
		case model.ProofLost:
			lost = append(lost, c.ID)
		}
	}
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, "   "+l.paint(ui.Green, "█")+" "+l.ink(fmt.Sprintf("%d pass(es) reboot-proven", len(proven)))+l.muted(": they survived a real reboot"))
	if len(lost) > 0 {
		fmt.Fprintln(a.stdout, "   "+l.bad(l.paint(ui.Red, fmt.Sprintf("%d lost at the reboot: %s", len(lost), strings.Join(lost, ", ")))))
	}
	fmt.Fprintln(a.stdout)
	for _, s := range l.transition(pre.Summary, post.Summary, "after harden", "after the reboot") {
		fmt.Fprintln(a.stdout, s)
	}
	fmt.Fprintln(a.stdout)
	if len(specs) > 0 {
		if err := a.writeOutputs(specs, post, false, true); err != nil {
			return err
		}
	}
	if notProven > 0 || len(lost) > 0 {
		return exitError{ExitPolicy, fmt.Errorf("%d fixed control(s) not compliant after the reboot, %d pass(es) lost at the reboot", notProven, len(lost))}
	}
	return nil
}

// waitForNewBoot polls the target until it answers with another boot id.
func waitForNewBoot(ctx context.Context, t *target.Target, oldBoot string, timeout time.Duration, progress func(string)) (*model.Host, error) {
	deadline := time.Now().Add(timeout)
	start := time.Now()
	last := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
		}
		actx, cancel := context.WithTimeout(ctx, 20*time.Second)
		h, err := scan.HostOf(actx, t)
		cancel()
		if err == nil && h.BootID != "" && h.BootID != oldBoot {
			return h, nil
		}
		if time.Now().After(deadline) {
			if err == nil {
				return nil, fmt.Errorf("%s still runs boot %s after %s: the reboot did not happen", t, shortID(oldBoot), timeout)
			}
			return nil, fmt.Errorf("%s did not come back within %s (last error: %v)", t, timeout, err)
		}
		if time.Since(last) >= 30*time.Second {
			last = time.Now()
			progress(fmt.Sprintf("waiting for %s to come back (%s)", t, time.Since(start).Round(time.Second)))
		}
	}
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
