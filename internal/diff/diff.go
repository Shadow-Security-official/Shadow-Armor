// Package diff compares two Shadow-Armor reports: what got fixed, what
// regressed, and what drifted from durable to runtime-only compliance.
package diff

import (
	"sort"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
)

type Change struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Before   string `json:"before"`
	After    string `json:"after"`
}

type Result struct {
	BeforeTarget string        `json:"before_target"`
	AfterTarget  string        `json:"after_target"`
	Before       model.Summary `json:"before"`
	After        model.Summary `json:"after"`
	Fixed        []Change      `json:"fixed"`
	Regressed    []Change      `json:"regressed"`
	Drifted      []Change      `json:"drifted"` // durable <-> runtime-only, pending changes
	New          []Change      `json:"new"`     // controls only present in the later report
	Removed      []Change      `json:"removed"`
	StillFailing int           `json:"still_failing"`
	// Rebooted: the two reports are the same host across a reboot, so a
	// regression is a fix that did not survive it, and passes seen in both
	// survived a real reboot.
	Rebooted       bool `json:"rebooted"`
	SurvivedReboot int  `json:"survived_reboot"`
}

func label(c model.ControlResult) string {
	if c.Qualifier != "" && (c.Status == model.Pass || c.Status == model.Fail) {
		return string(c.Status) + "/" + string(c.Qualifier)
	}
	return string(c.Status)
}

func bad(s model.Status) bool { return s == model.Fail || s == model.Error }

// Compare computes the changes from before to after.
func Compare(before, after *model.Report) Result {
	r := Result{BeforeTarget: before.Target.URI, AfterTarget: after.Target.URI, Before: before.Summary, After: after.Summary}
	r.Rebooted, _ = model.Rebooted(before.Target.Host, after.Target.Host)
	prev := map[string]model.ControlResult{}
	for _, c := range before.Controls {
		prev[c.ID] = c
	}
	seen := map[string]bool{}
	for _, c := range after.Controls {
		seen[c.ID] = true
		p, ok := prev[c.ID]
		ch := Change{ID: c.ID, Title: c.Title, Severity: c.Severity, After: label(c)}
		if !ok {
			if bad(c.Status) {
				r.New = append(r.New, ch)
			}
			continue
		}
		ch.Before = label(p)
		switch {
		case bad(p.Status) && c.Status == model.Pass:
			r.Fixed = append(r.Fixed, ch)
		case p.Status == model.Pass && bad(c.Status):
			r.Regressed = append(r.Regressed, ch)
		case p.Status == model.Pass && c.Status == model.Pass && r.Rebooted:
			r.SurvivedReboot++
			if p.Qualifier != c.Qualifier {
				r.Drifted = append(r.Drifted, ch)
			}
		case bad(p.Status) && bad(c.Status):
			r.StillFailing++
			if p.Qualifier != c.Qualifier {
				r.Drifted = append(r.Drifted, ch)
			}
		case p.Status == c.Status && p.Qualifier != c.Qualifier:
			r.Drifted = append(r.Drifted, ch)
		}
	}
	for _, p := range before.Controls {
		if !seen[p.ID] {
			r.Removed = append(r.Removed, Change{ID: p.ID, Title: p.Title, Severity: p.Severity, Before: label(p)})
		}
	}
	for _, l := range [][]Change{r.Fixed, r.Regressed, r.Drifted, r.New, r.Removed} {
		sort.Slice(l, func(i, j int) bool { return l[i].ID < l[j].ID })
	}
	return r
}
