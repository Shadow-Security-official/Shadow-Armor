package engine

import (
	"strings"
	"testing"
)

// Captured from CINC Auditor 7.2.1 / Chef InSpec 5.24 with --reporter progress-bar.
const sample = "\r[###############                 ] [1/2] [ 50.00%]\r                    \r\x1b[38;5;9m\xc3\x97 [FAILED]   SA-02.04  Only expected ports listen beyond loopback  \x1b[0m\n" +
	"\r[###############                 ] [1/2] [ 50.00%]\r[################################] [2/2] [100.00%]\r                \r\x1b[38;5;41m\xe2\x9c\x94 [PASSED]   SA-03.01  The telnet client is not installed  \x1b[0m\n" +
	"\r[################################] [2/2] [100.00%]"

func TestProgressWriter(t *testing.T) {
	var got []string
	var other strings.Builder
	w := NewProgressWriter(func(e Event) {
		if e.ID != "" {
			got = append(got, e.ID+"="+e.Status)
		} else {
			got = append(got, "progress")
		}
	}, &other)
	// Feed it in small chunks, as a pipe would; a warning is mixed in.
	sample := "WARN: something the operator should see\n" + sample
	for i := 0; i < len(sample); i += 7 {
		end := i + 7
		if end > len(sample) {
			end = len(sample)
		}
		if _, err := w.Write([]byte(sample[i:end])); err != nil {
			t.Fatal(err)
		}
	}
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "SA-02.04=failed") || !strings.Contains(joined, "SA-03.01=passed") {
		t.Fatalf("events: %s", joined)
	}
	w.Flush()
	if other.String() != "WARN: something the operator should see\n" {
		t.Fatalf("other lines: %q", other.String())
	}
	if w.last.Done != 2 || w.last.Total != 2 {
		t.Fatalf("progress %d/%d", w.last.Done, w.last.Total)
	}
}
