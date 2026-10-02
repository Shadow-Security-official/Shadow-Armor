package engine

import (
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Event is one step of a running audit, parsed from the engine's
// progress-bar reporter (CINC Auditor and Chef InSpec 5+).
type Event struct {
	Done, Total int
	// ID and Status are set when a control finished: passed, failed,
	// skipped, error or waived.
	ID     string
	Status string
}

var (
	ansiRe     = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)
	countRe    = regexp.MustCompile(`\[(\d+)/(\d+)\]`)
	finishedRe = regexp.MustCompile(`\[(PASSED|FAILED|SKIPPED|ERROR|WAIVED)\]\s+(\S+)`)
)

// ProgressWriter turns the progress-bar reporter stream into events. It is
// an io.Writer for the engine's output (the reporter writes to stderr);
// lines that are not progress are passed on to other.
type ProgressWriter struct {
	mu    sync.Mutex
	fn    func(Event)
	other io.Writer
	buf   []byte
	last  Event
}

// NewProgressWriter calls fn for every progress update and forwards every
// other line to other (which may be nil).
func NewProgressWriter(fn func(Event), other io.Writer) *ProgressWriter {
	return &ProgressWriter{fn: fn, other: other}
}

func (p *ProgressWriter) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.buf = append(p.buf, b...)
	for {
		i := strings.IndexAny(string(p.buf), "\r\n")
		if i < 0 {
			break
		}
		p.line(string(p.buf[:i]))
		p.buf = p.buf[i+1:]
	}
	if len(p.buf) > 64<<10 { // a reporter that never ends a line: keep memory bounded
		p.buf = p.buf[len(p.buf)-4096:]
	}
	return len(b), nil
}

// Flush forwards a trailing partial line.
func (p *ProgressWriter) Flush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.buf) > 0 {
		p.line(string(p.buf))
		p.buf = nil
	}
}

func (p *ProgressWriter) line(raw string) {
	s := ansiRe.ReplaceAllString(raw, "")
	progress := countRe.MatchString(s) || finishedRe.MatchString(s) || strings.TrimSpace(s) == ""
	if !progress {
		if p.other != nil {
			_, _ = io.WriteString(p.other, raw+"\n")
		}
		return
	}
	if m := countRe.FindStringSubmatch(s); m != nil {
		d, _ := strconv.Atoi(m[1])
		t, _ := strconv.Atoi(m[2])
		if d != p.last.Done || t != p.last.Total {
			p.last.Done, p.last.Total = d, t
			if p.fn != nil {
				p.fn(Event{Done: d, Total: t})
			}
		}
	}
	if m := finishedRe.FindStringSubmatch(s); m != nil && p.fn != nil {
		p.fn(Event{Done: p.last.Done, Total: p.last.Total, ID: m[2], Status: strings.ToLower(m[1])})
	}
}
