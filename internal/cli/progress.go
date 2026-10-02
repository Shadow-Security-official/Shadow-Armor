package cli

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/engine"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/scan"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/ui"
)

// What the scanner is doing, by pillar of the control it just finished.
var pillarVerbs = map[int]string{
	1:  "Probing kernel self-protection",
	2:  "Mapping the attack surface",
	3:  "Hunting risky clients",
	4:  "Checking configuration integrity",
	5:  "Following the audit trail",
	6:  "Interrogating sshd -T",
	7:  "Weighing the sudo policy",
	8:  "Inspecting local accounts",
	9:  "Testing the password policy",
	10: "Checking patch levels",
	11: "Tracing encryption layers",
	12: "Probing crypto and MFA",
}

// Shown while the engine loads the profile and runs its first probes.
var loadingVerbs = []string{
	"Loading the profile",
	"Probing the effective configuration",
	"Resolving sshd -T, sysctl and systemd",
	"Expanding PAM stacks and sudoers includes",
	"Reading audit rules and boot settings",
	"Collecting package and account inventories",
}

type recent struct{ id, status, title string }

// scanLive is the animated progress of a scan on stderr: a checklist of
// finished steps, then a live region with a spinner, a shimmering verb, the
// progress line, running counts and the last results.
type scanLive struct {
	a     *app
	t     ui.Term
	p     ui.Profile
	live  *ui.Live
	quiet bool
	plain bool // not a terminal: plain status lines

	mu                     sync.Mutex
	status                 string
	stepStart              time.Time
	start                  time.Time
	done, total            int
	pass, fail, skip, errs int
	last                   []recent
	pillar                 int
}

func (a *app) scanProgress(quiet, verbose bool, o *scan.Options) *scanLive {
	t := ui.Detect(a.stderr, a.color)
	s := &scanLive{a: a, t: t, p: t.Profile, quiet: quiet, plain: !t.TTY || verbose, start: time.Now(), stepStart: time.Now()}
	if quiet {
		return s
	}
	o.Progress = s.step
	o.OnEvent = s.event
	if !s.plain {
		s.live = ui.NewLive(t, 80*time.Millisecond, s.frame)
		s.live.Start()
	}
	return s
}

// step records a new phase; the previous one is ticked off above the live
// region.
func (s *scanLive) step(msg string) {
	s.mu.Lock()
	prev, took := s.status, time.Since(s.stepStart)
	s.status, s.stepStart = msg, time.Now()
	s.mu.Unlock()
	if s.plain {
		fmt.Fprintf(s.a.stderr, "› %s\n", msg)
		return
	}
	if prev != "" && !strings.Contains(prev, " auditing ") {
		s.live.Println(s.tick(prev, took))
	}
	s.live.Redraw()
}

func (s *scanLive) tick(msg string, took time.Duration) string {
	d := ""
	if took >= time.Second {
		d = s.p.Paint(ui.Faint, " "+took.Round(100*time.Millisecond).String())
	}
	return "  " + s.p.Paint(ui.Green, "✓") + " " + s.p.Paint(ui.Steel, msg) + d
}

func (s *scanLive) event(e engine.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done, s.total = e.Done, e.Total
	if e.ID == "" {
		return
	}
	switch e.Status {
	case "passed":
		s.pass++
	case "failed":
		s.fail++
	case "skipped", "waived":
		s.skip++
	default:
		s.errs++
	}
	title := ""
	if c, ok := s.a.cat.Control(e.ID); ok {
		title = c.Title
		s.pillar = c.Pillar
	}
	s.last = append(s.last, recent{e.ID, e.Status, title})
	if len(s.last) > 3 {
		s.last = s.last[len(s.last)-3:]
	}
}

func (s *scanLive) frame(f ui.Frame) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.p
	glyph := p.Paint(ui.Along(ui.Brand, float64(f.N%24)/23), ui.Spin(f.N))
	verb := s.status
	if verb == "" {
		verb = "Preparing the audit"
	}
	if strings.Contains(verb, " auditing ") {
		// The engine loads the profile and probes the target before the
		// first result: say what is happening, a phrase every few seconds.
		verb = loadingVerbs[int(time.Since(s.stepStart).Seconds()/4)%len(loadingVerbs)]
		if s.total > 0 {
			verb = "Evaluating controls"
		}
	}
	if v, ok := pillarVerbs[s.pillar]; ok && s.done > 0 {
		verb = v
	}
	verb = strings.ToUpper(verb[:1]) + verb[1:] + "…"
	clock := p.Paint(ui.Muted, ui.Clock(f.Elapsed)+" · ctrl+c to cancel")
	head := "  " + glyph + " " + p.Shimmer(verb, f.N, ui.Steel, ui.White)
	lines := []string{ui.Pad(head, f.Width-ui.Width(clock)-3) + " " + clock}
	if s.total > 0 {
		frac := float64(s.done) / float64(s.total)
		counts := p.Paint(ui.Green, fmt.Sprintf("✓ %d", s.pass)) + "  " + p.Paint(ui.Red, fmt.Sprintf("✗ %d", s.fail)) + "  " + p.Paint(ui.Muted, fmt.Sprintf("↺ %d", s.skip))
		if s.errs > 0 {
			counts += "  " + p.Paint(ui.Purple, fmt.Sprintf("! %d", s.errs))
		}
		num := p.Paint(ui.Ink, fmt.Sprintf("%d/%d", s.done, s.total)) + p.Paint(ui.Muted, fmt.Sprintf(" %3.0f%%", frac*100))
		barW := max(10, min(60, f.Width-ui.Width(num)-ui.Width(counts)-12))
		lines = append(lines, "    "+p.Line(frac, barW, ui.AlongFn(ui.Brand), ui.Hex("#1E293B"))+"  "+num+"   "+counts)
		for _, r := range s.last {
			mark := map[string]string{"passed": p.Paint(ui.Green, "✓"), "failed": p.Paint(ui.Red, "✗"), "skipped": p.Paint(ui.Muted, "↺"), "waived": p.Paint(ui.Blue, "≈")}[r.status]
			if mark == "" {
				mark = p.Paint(ui.Purple, "!")
			}
			lines = append(lines, "    "+mark+" "+p.Paint(ui.Muted, r.id)+" "+p.Paint(ui.Faint, r.title))
		}
	}
	return lines
}

// finish stops the animation and leaves a one-line summary.
func (s *scanLive) finish(rep *model.Report, err error) {
	if s.quiet {
		return
	}
	if s.live != nil {
		s.live.Stop()
	}
	if err != nil || rep == nil {
		return
	}
	n := rep.Summary.Counts.Total
	mode := rep.Engine.Mode
	if mode == "docker" {
		mode = "docker engine"
	}
	msg := fmt.Sprintf("%d controls evaluated in %s · %s %s, %s", n, time.Since(s.start).Round(100*time.Millisecond), rep.Engine.Name, rep.Engine.Version, mode)
	if s.plain {
		fmt.Fprintf(s.a.stderr, "› %s\n", msg)
		return
	}
	fmt.Fprintln(s.a.stderr, s.tick(msg, 0))
}
