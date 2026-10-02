package cli

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/ui"
)

// chefView turns the Chef "doc" formatter output of a converge into a
// readable, animated list: one line per resource that changed (what it
// did), a live line for the resource being converged, counts, and the raw
// output kept aside for failures.
type chefView struct {
	l      look
	live   *ui.Live
	plain  bool
	whyRun bool

	mu       sync.Mutex
	buf      []byte
	raw      []string
	total    int
	seen     int
	updated  int
	upToDate int
	skipped  int
	cur      *chefRes
	errLines []string
	summary  string
	start    time.Time
	width    int
}

type chefRes struct {
	typ, name, action string
	changes           []string
	inDiff            bool
}

var (
	chefTotalRe   = regexp.MustCompile(`^Converging (\d+) resources`)
	chefResRe     = regexp.MustCompile(`^  \* ([a-z_]+)\[(.*)\] action ([a-z_]+)(?: \((.*)\))?\s*$`)
	chefChangeRe  = regexp.MustCompile(`^    - ([A-Za-z].*)$`)
	chefDiffRe    = regexp.MustCompile(`^    (---|\+\+\+) `)
	chefDoneRe    = regexp.MustCompile(`^(?:Cinc|Chef) (?:Infra )?Client finished|^Infra Phase complete`)
	chefErrorRe   = regexp.MustCompile(`ERROR:|FATAL:|^=====|Error executing action|^\s+(?:Errno|Mixlib|Chef)::`)
	chefWhyRunRe  = regexp.MustCompile(`^\s+- Would `)
	chefSummaryRe = regexp.MustCompile(`Infra Phase complete, (.*)$`)
	// Warnings the cookbook logs (rules left for review, ports kept open).
	chefLogRe = regexp.MustCompile(`^\s*\* log\[(.+?)\] action write`)
)

func (a *app) newChefView(whyRun bool) *chefView {
	t := ui.Detect(a.stdout, a.color)
	v := &chefView{l: a.look(), plain: !t.TTY, whyRun: whyRun, start: time.Now(), width: t.Width}
	if !v.plain {
		v.live = ui.NewLive(t, 80*time.Millisecond, v.frame)
	}
	return v
}

func (v *chefView) begin() {
	if v.live != nil {
		v.live.Start()
	}
}

// Write parses the output line by line.
func (v *chefView) Write(b []byte) (int, error) {
	v.mu.Lock()
	v.buf = append(v.buf, b...)
	var lines []string
	for {
		i := strings.IndexByte(string(v.buf), '\n')
		if i < 0 {
			break
		}
		lines = append(lines, strings.TrimRight(string(v.buf[:i]), "\r"))
		v.buf = v.buf[i+1:]
	}
	v.mu.Unlock()
	for _, l := range lines {
		v.line(l)
	}
	return len(b), nil
}

func (v *chefView) out(lines ...string) {
	if v.live != nil {
		v.live.Println(lines...)
		return
	}
	for _, l := range lines {
		fmt.Println(l)
	}
}

func (v *chefView) line(s string) {
	v.mu.Lock()
	v.raw = append(v.raw, s)
	if len(v.raw) > 400 {
		v.raw = v.raw[len(v.raw)-400:]
	}
	var done *chefRes
	var note string
	switch {
	case chefLogRe.MatchString(s):
		note = chefLogRe.FindStringSubmatch(s)[1]
		v.seen++
		v.upToDate++
		done, v.cur = v.cur, nil
	case chefTotalRe.MatchString(s):
		v.total, _ = strconv.Atoi(chefTotalRe.FindStringSubmatch(s)[1])
	case chefResRe.MatchString(s):
		m := chefResRe.FindStringSubmatch(s)
		done = v.cur
		v.seen++
		r := &chefRes{typ: m[1], name: m[2], action: m[3]}
		switch note := m[4]; {
		case strings.HasPrefix(note, "up to date"):
			v.upToDate++
			r = nil
		case strings.HasPrefix(note, "skipped"):
			v.skipped++
			r = nil
		}
		v.cur = r
	case chefDiffRe.MatchString(s) && v.cur != nil:
		v.cur.inDiff = true
	case chefChangeRe.MatchString(s) && v.cur != nil:
		c := chefChangeRe.FindStringSubmatch(s)[1]
		// Inside a diff, only "- verb ..." sentences are changes again.
		if v.cur.inDiff && !regexp.MustCompile(`^[a-z]+ `).MatchString(c) {
			break
		}
		if chefWhyRunRe.MatchString(s) {
			v.whyRun = true
		}
		v.cur.inDiff = false
		v.cur.changes = append(v.cur.changes, c)
	case chefSummaryRe.MatchString(s):
		v.summary = chefSummaryRe.FindStringSubmatch(s)[1]
		done, v.cur = v.cur, nil
	case chefDoneRe.MatchString(s):
		done, v.cur = v.cur, nil
	case chefErrorRe.MatchString(s):
		v.errLines = append(v.errLines, s)
	}
	v.mu.Unlock()
	if done != nil {
		v.finishRes(done)
	}
	if note != "" && !strings.HasPrefix(note, "shadow-armor-plan") {
		for i, l := range ui.Wrap(note, max(40, v.l.w-6)) {
			mark := " "
			if i == 0 {
				mark = v.l.paint(ui.Amber, "!")
			}
			v.out("   " + mark + " " + v.l.ink(l))
		}
	}
}

// finishRes prints a resource that changed something.
func (v *chefView) finishRes(r *chefRes) {
	if len(r.changes) == 0 || strings.Contains(r.name, "/shadow-armor/journal/") {
		v.mu.Lock()
		v.upToDate++
		v.mu.Unlock()
		return
	}
	v.mu.Lock()
	v.updated++
	v.mu.Unlock()
	l := v.l
	mark := l.paint(ui.Green, "✓")
	if v.whyRun {
		mark = l.paint(ui.Amber, "~")
	}
	name := r.name
	if len(name) > 46 {
		name = "…" + name[len(name)-45:]
	}
	what := summarizeChanges(r.changes)
	v.out(fmt.Sprintf("   %s %s %s %s", mark, ui.Pad(l.muted(r.typ), 16), ui.Pad(l.ink(name), 47), l.steel(ui.Trunc(what, max(20, v.l.w-70)))))
}

var changeRewrites = []struct {
	re  *regexp.Regexp
	out string
}{
	{regexp.MustCompile(`^(?:Would )?create new file .*`), "created"},
	{regexp.MustCompile(`^(?:Would )?update content in file .*`), "content updated"},
	{regexp.MustCompile(`^(?:Would )?change mode from '.*' to '(.*)'`), "mode $1"},
	{regexp.MustCompile(`^(?:Would )?change owner from '.*' to '(.*)'`), "owner $1"},
	{regexp.MustCompile(`^(?:Would )?change group from '.*' to '(.*)'`), "group $1"},
	{regexp.MustCompile(`^(?:Would )?remove package (.*)`), "removed"},
	{regexp.MustCompile(`^(?:Would )?install version .* of package (.*)`), "installed"},
	{regexp.MustCompile(`^(?:Would )?execute (.*)`), "ran $1"},
	{regexp.MustCompile(`^(?:Would )?create new directory .*`), "directory created"},
	{regexp.MustCompile(`^(?:Would )?(?:disable|enable|stop|start|restart|reload|mask) service .*`), "$0"},
	{regexp.MustCompile(`^suppressed sensitive resource`), "content hidden (sensitive)"},
}

func summarizeChanges(cs []string) string {
	var out []string
	seen := map[string]bool{}
	for _, c := range cs {
		s := c
		for _, rw := range changeRewrites {
			if rw.re.MatchString(c) {
				s = rw.re.ReplaceAllString(c, rw.out)
				break
			}
		}
		s = strings.TrimPrefix(s, "Would ")
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return strings.Join(out, " · ")
}

func (v *chefView) frame(f ui.Frame) []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	l := v.l
	p := l.p
	verb := "Converging"
	if v.whyRun {
		verb = "Simulating (why-run)"
	}
	cur := ""
	if v.cur != nil {
		cur = v.cur.typ + "[" + v.cur.name + "]"
	}
	glyph := p.Paint(ui.Along(ui.Brand, float64(f.N%24)/23), ui.Spin(f.N))
	head := "   " + glyph + " " + p.Shimmer(verb+"…", f.N, ui.Steel, ui.White) + "  " + l.muted(ui.Trunc(cur, f.Width-40))
	lines := []string{head}
	if v.total > 0 {
		frac := float64(v.seen) / float64(v.total)
		counts := l.paint(ui.Green, fmt.Sprintf("%d changed", v.updated)) + l.muted(fmt.Sprintf(" · %d already compliant", v.upToDate+v.skipped))
		lines = append(lines, "     "+p.Line(frac, max(10, min(50, f.Width-50)), ui.AlongFn(ui.Brand), ui.Hex("#1E293B"))+"  "+l.ink(fmt.Sprintf("%d/%d", v.seen, v.total))+"  "+counts+"  "+l.muted(ui.Clock(f.Elapsed)))
	}
	return lines
}

// end stops the animation and prints the summary; failed runs show the
// tail of the raw output.
func (v *chefView) end(failed bool) {
	v.mu.Lock()
	last := v.cur
	v.cur = nil
	v.mu.Unlock()
	if last != nil {
		v.finishRes(last)
	}
	if v.live != nil {
		v.live.Stop()
	}
	l := v.l
	took := time.Since(v.start).Round(100 * time.Millisecond)
	if failed {
		fmt.Println("   " + l.bad(l.bold(ui.Red, "the Chef run failed")) + l.muted(" · last lines of its output:"))
		tail := v.raw
		if len(tail) > 30 {
			tail = tail[len(tail)-30:]
		}
		for _, s := range tail {
			fmt.Println("     " + l.faint("│ ") + l.steel(s))
		}
		return
	}
	verb := "changed"
	if v.whyRun {
		verb = "would change"
	}
	fmt.Println("   " + l.ok(l.ink(fmt.Sprintf("%d resource(s) %s", v.updated, verb))+l.muted(fmt.Sprintf(" · %d already compliant · %s", v.upToDate+v.skipped, took))))
}
