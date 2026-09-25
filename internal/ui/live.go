package ui

import (
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"time"
)

// Frame is what a live region renders from.
type Frame struct {
	N       int           // frame number
	Elapsed time.Duration // since Start
	Width   int           // terminal width now
}

// Live redraws a small region at the bottom of a terminal several times a
// second (spinners, progress), while other lines can still be printed above
// it. Off a terminal it draws nothing: callers print plain lines instead.
type Live struct {
	t      Term
	render func(Frame) []string
	every  time.Duration

	mu      sync.Mutex
	drawn   int
	frame   int
	start   time.Time
	stop    chan struct{}
	done    chan struct{}
	running bool
}

// NewLive prepares a live region on t.
func NewLive(t Term, every time.Duration, render func(Frame) []string) *Live {
	if every <= 0 {
		every = 90 * time.Millisecond
	}
	return &Live{t: t, render: render, every: every}
}

// Enabled reports whether the region animates (a terminal).
func (l *Live) Enabled() bool { return l != nil && l.t.TTY }

// Start begins the animation.
func (l *Live) Start() {
	if !l.Enabled() || l.running {
		return
	}
	l.running = true
	l.start = time.Now()
	l.stop, l.done = make(chan struct{}), make(chan struct{})
	_, _ = io.WriteString(l.t.W, "\x1b[?25l") // hide the cursor
	go func() {
		defer close(l.done)
		tk := time.NewTicker(l.every)
		defer tk.Stop()
		l.draw()
		for {
			select {
			case <-l.stop:
				return
			case <-tk.C:
				l.draw()
			}
		}
	}()
}

// Stop clears the region and gives the cursor back.
func (l *Live) Stop() {
	if !l.Enabled() || !l.running {
		return
	}
	close(l.stop)
	<-l.done
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clear()
	_, _ = io.WriteString(l.t.W, "\x1b[?25h")
	l.running = false
}

// Println prints lines above the live region (they stay on screen).
func (l *Live) Println(lines ...string) {
	if !l.Enabled() || !l.running {
		for _, s := range lines {
			_, _ = fmt.Fprintln(l.t.W, s)
		}
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clear()
	for _, s := range lines {
		_, _ = fmt.Fprintln(l.t.W, s)
	}
	l.paint()
}

// Redraw forces a frame now (after a state change).
func (l *Live) Redraw() {
	if l.Enabled() && l.running {
		l.draw()
	}
}

func (l *Live) draw() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clear()
	l.paint()
	l.frame++
}

// clear moves back to the first line of the region and erases it.
func (l *Live) clear() {
	if l.drawn == 0 {
		return
	}
	s := "\r"
	if l.drawn > 1 {
		s += fmt.Sprintf("\x1b[%dA", l.drawn-1)
	}
	_, _ = io.WriteString(l.t.W, s+"\x1b[J")
	l.drawn = 0
}

func (l *Live) paint() {
	l.t.Refresh()
	w := l.t.Width
	if w < 20 {
		w = 20
	}
	lines := l.render(Frame{N: l.frame, Elapsed: time.Since(l.start), Width: w})
	for i := range lines {
		// Never let a line wrap: the region could not be erased cleanly.
		lines[i] = Trunc(lines[i], w-1)
	}
	_, _ = io.WriteString(l.t.W, strings.Join(lines, "\n"))
	l.drawn = len(lines)
}

// Spinner glyphs, breathing in and out. None of them has an emoji form:
// terminals that draw emoji (✳ becomes a green square in Windows Terminal)
// would break the alignment.
var spin = []string{"·", "✢", "*", "✶", "✻", "✽", "✻", "✶", "*", "✢"}

// Spin returns the spinner glyph of a frame.
func Spin(n int) string { return spin[n%len(spin)] }

// Shimmer paints text in base with a bright band sweeping across it.
func (p Profile) Shimmer(text string, frame int, base, hi RGB) string {
	if p == NoColor {
		return text
	}
	rs := []rune(text)
	band := 4.0
	span := float64(len(rs)) + 2*band
	pos := math.Mod(float64(frame)*0.9, span) - band
	var b strings.Builder
	for i, r := range rs {
		d := math.Abs(float64(i) - pos)
		t := math.Max(0, 1-d/band)
		b.WriteString(p.Fg(Mix(base, hi, t*t)))
		b.WriteRune(r)
	}
	b.WriteString(reset)
	return b.String()
}

// Clock formats an elapsed time as m:ss.
func Clock(d time.Duration) string {
	s := int(d.Seconds())
	if s >= 3600 {
		return fmt.Sprintf("%d:%02d:%02d", s/3600, s/60%60, s%60)
	}
	return fmt.Sprintf("%d:%02d", s/60, s%60)
}
