// Package score implements the published Shadow-Armor scoring formula.
//
// The exact same algorithm is implemented in JavaScript for the HTML report
// (internal/report/assets/score.js); TestParityWithJavaScript keeps them equal.
//
//	weight(severity)   critical 10, high 5, medium 3, low 1, info 0
//	evaluated          controls whose status is pass, fail or error
//	                   (skip and waived are left out; error counts as a failure)
//	score              100 x sum(weight of passes) / sum(weight of evaluated), 1 decimal
//	raw grade          A >= 90, B >= 80, C >= 65, D >= 50, else E
//	caps               any critical control failing or in error  -> at most D
//	                   an A that rests on runtime-only passes     -> B
//	grade              the worse of the raw grade and every cap
//	no evaluated control                                          -> grade "N/A"
//
// "Rests on": the runtime cap applies when the grade would not stay A if every
// runtime-only pass (persistence contradicted or not proven) failed after a
// reboot. An A that holds even in that worst case is kept, so failing a
// runtime-only control can never earn a better grade than passing it.
package score

import (
	"math"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
)

// Grades from best to worst.
var Grades = []string{"A", "B", "C", "D", "E"}

// Thresholds of the raw grade.
var Thresholds = []struct {
	Grade string
	Min   float64
}{{"A", 90}, {"B", 80}, {"C", 65}, {"D", 50}, {"E", 0}}

// DefaultWeights mirrors catalog.json severity_weights.
var DefaultWeights = map[string]float64{"critical": 10, "high": 5, "medium": 3, "low": 1, "info": 0}

// Rank of a grade: 0 = A ... 4 = E, 5 = N/A.
func Rank(g string) int {
	for i, x := range Grades {
		if x == g {
			return i
		}
	}
	return len(Grades)
}

func worse(a, b string) string {
	if Rank(b) > Rank(a) {
		return b
	}
	return a
}

// RawGrade maps a score to a letter.
func RawGrade(s float64) string {
	for _, t := range Thresholds {
		if s >= t.Min {
			return t.Grade
		}
	}
	return "E"
}

// InLens reports whether a control counts under a standard lens.
func InLens(c model.ControlResult, lens string) bool {
	return c.Map.Has(lens)
}

// Compute scores a set of controls under a lens ("all" or a standard key).
func Compute(controls []model.ControlResult, weights map[string]float64, lens string) model.Summary {
	if weights == nil {
		weights = DefaultWeights
	}
	if lens == "" {
		lens = "all"
	}
	var in []model.ControlResult
	for _, c := range controls {
		if InLens(c, lens) {
			in = append(in, c)
		}
	}
	sum := one(in, weights)
	sum.Lens = lens
	pillarIDs := map[int]bool{}
	for _, c := range in {
		pillarIDs[c.Pillar] = true
	}
	for id := 1; id <= 12; id++ {
		if !pillarIDs[id] {
			continue
		}
		var sub []model.ControlResult
		for _, c := range in {
			if c.Pillar == id {
				sub = append(sub, c)
			}
		}
		ps := one(sub, weights)
		sum.Pillars = append(sum.Pillars, model.PillarSummary{ID: id, Score: ps.Score, Grade: ps.Grade, Counts: ps.Counts})
	}
	return sum
}

func one(controls []model.ControlResult, weights map[string]float64) model.Summary {
	var s model.Summary
	var earned, possible, unproven float64
	var critical, runtimeOnly []string
	criticalUnproven := false
	for _, c := range controls {
		s.Counts.Total++
		w := weights[c.Severity]
		switch c.Status {
		case model.Pass:
			s.Counts.Pass++
			earned += w
			possible += w
			if c.Qualifier == model.RuntimeOnly {
				s.Counts.RuntimeOnly++
				runtimeOnly = append(runtimeOnly, c.ID)
				unproven += w
				if c.Severity == "critical" {
					criticalUnproven = true
				}
			}
			if c.Proof != nil && c.Proof.Reboot == model.ProofProven {
				s.Counts.RebootProven++
			}
		case model.Fail, model.Error:
			if c.Status == model.Fail {
				s.Counts.Fail++
			} else {
				s.Counts.Error++
			}
			if c.Qualifier == model.Pending {
				s.Counts.Pending++
			}
			possible += w
			if c.Severity == "critical" {
				critical = append(critical, c.ID)
			}
		case model.Skip:
			s.Counts.Skip++
		case model.Waived:
			s.Counts.Waived++
		}
	}
	if possible == 0 {
		s.Grade, s.RawGrade = "N/A", "N/A"
		return s
	}
	v := math.Round(1000*earned/possible) / 10
	s.Score = &v
	s.RawGrade = RawGrade(v)
	s.Grade = s.RawGrade
	if len(critical) > 0 {
		s.Caps = append(s.Caps, model.Cap{Grade: "D", Reason: "critical control failing", IDs: critical})
		s.Grade = worse(s.Grade, "D")
	}
	s.QualifiedPasses = len(runtimeOnly)
	if s.Grade == "A" && len(runtimeOnly) > 0 {
		// Worst case after a reboot: every runtime-only pass fails.
		worst := RawGrade(math.Round(1000*(earned-unproven)/possible) / 10)
		if len(critical) > 0 || criticalUnproven {
			worst = worse(worst, "D")
		}
		if worst != "A" {
			s.Caps = append(s.Caps, model.Cap{Grade: "B", Reason: "the A rests on passes whose persistence is not proven (runtime-only)", IDs: runtimeOnly})
			s.Grade = "B"
			s.RuntimeQualified = true
		}
	}
	return s
}

// Projected grades the controls as if every automatic fix were applied and
// every pending reboot or reload done: failing, erroring and runtime-only
// controls with an automatic remediation, and pending ones, count as durable
// passes. It is the grade `sdw-armor harden` (then a reboot) can reach.
func Projected(controls []model.ControlResult, weights map[string]float64, lens string) (model.Summary, int) {
	out := make([]model.ControlResult, len(controls))
	fixed := 0
	for i, c := range controls {
		fixable := c.Remediation.Auto && (c.Status == model.Fail || c.Status == model.Error || c.Qualifier == model.RuntimeOnly)
		if fixable || c.Qualifier == model.Pending {
			if InLens(c, lens) {
				fixed++
			}
			c.Status, c.Qualifier = model.Pass, model.Durable
		}
		out[i] = c
	}
	return Compute(out, weights, lens), fixed
}
