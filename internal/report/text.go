// Package report renders a qualified report: terminal text, JSON, a
// self-contained HTML page, SARIF, JUnit XML and Markdown.
package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
)

var severityOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func stdName(r *model.Report, key string) string {
	if key == "" || key == "all" {
		return "all standards"
	}
	for _, s := range r.Standards {
		if s.Key == key {
			return s.Name
		}
	}
	return key
}

func pendingWhat(cr model.ControlResult) string {
	if cr.Remediation.Reboot || strings.HasPrefix(cr.ID, "SA-10.05") {
		return "reboot"
	}
	return "reboot or reload"
}

// ProofText renders the proof columns: what the verdict establishes now,
// on disk and after a reboot.
func ProofText(pr *model.Proof) string {
	if pr == nil {
		return "proof not recorded"
	}
	mark := func(v string) string {
		switch v {
		case model.ProofProven:
			return "✓"
		case model.ProofFailed:
			return "✗"
		case model.ProofNA:
			return "n/a"
		}
		return "?"
	}
	reboot := map[string]string{
		model.ProofProven:      "✓ proven (survived a real reboot)",
		model.ProofExpected:    "✓ expected",
		model.ProofFailed:      "✗ would be undone",
		model.ProofLost:        "✗ lost at the last reboot",
		model.ProofNotMeasured: "? not measured",
		model.ProofNA:          "n/a (a reboot clears it)",
	}[pr.Reboot]
	if reboot == "" {
		reboot = "?"
	}
	return "now " + mark(pr.Now) + " · on disk " + mark(pr.OnDisk) + " · after reboot " + reboot
}

// failingEvidence lists the failed assertions as "what: why" lines.
func failingEvidence(cr model.ControlResult, max int) []string {
	var out []string
	for _, e := range cr.Evidence {
		if e.Status != "failed" && e.Status != "error" {
			continue
		}
		s := EvidenceLine(e)
		out = append(out, s)
		if len(out) == max {
			if n := countFailed(cr) - max; n > 0 {
				out = append(out, fmt.Sprintf("… and %d more", n))
			}
			break
		}
	}
	return out
}

// EvidenceLine renders one assertion compactly: what was checked, then
// what was found.
func EvidenceLine(e model.Evidence) string {
	if e.Message != "" {
		return EvidenceDesc(e) + " → " + e.Message
	}
	return EvidenceDesc(e)
}

// EvidenceDesc is what one assertion checked, without its outcome.
func EvidenceDesc(e model.Evidence) string {
	d := e.Desc
	if i := strings.Index(d, " is expected"); i > 0 {
		d = d[:i]
	}
	d = strings.TrimSpace(d)
	for _, suffix := range []string{" value", " items"} {
		d = strings.TrimSuffix(d, suffix)
	}
	if e.Kind == "runtime" || e.Kind == "persistent" {
		d = "[" + e.Kind + "] " + strings.TrimSuffix(d, " "+e.Kind)
	}
	return d
}

// failingItems returns up to max failed assertions and how many were left out.
func failingItems(cr model.ControlResult, max int) ([]model.Evidence, int) {
	var out []model.Evidence
	n := 0
	for _, e := range cr.Evidence {
		if e.Status != "failed" && e.Status != "error" {
			continue
		}
		n++
		if len(out) < max {
			out = append(out, e)
		}
	}
	return out, n - len(out)
}

func countFailed(cr model.ControlResult) int {
	n := 0
	for _, e := range cr.Evidence {
		if e.Status == "failed" || e.Status == "error" {
			n++
		}
	}
	return n
}

func bySeverity(cs []model.ControlResult) {
	sort.SliceStable(cs, func(i, j int) bool {
		a, b := severityOrder[cs[i].Severity], severityOrder[cs[j].Severity]
		if a != b {
			return a < b
		}
		return cs[i].ID < cs[j].ID
	})
}

func idList(ids []string, max int) string {
	if len(ids) <= max {
		return strings.Join(ids, ", ")
	}
	return strings.Join(ids[:max], ", ") + fmt.Sprintf(" +%d", len(ids)-max)
}

func trunc(s string, n int) string {
	r := []rune(s)
	if n <= 1 || len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
