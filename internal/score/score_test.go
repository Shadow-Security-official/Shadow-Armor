package score

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/catalog"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
)

type vector struct {
	Name     string                `json:"name"`
	Lens     string                `json:"lens"`
	Controls []model.ControlResult `json:"controls"`
	Want     struct {
		Score *float64 `json:"score"`
		Grade string   `json:"grade"`
		Raw   string   `json:"raw_grade"`
	} `json:"want"`
}

func repoRoot(t *testing.T) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func loadVectors(t *testing.T) []vector {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "testdata", "score-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	return vs
}

func TestVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			got := Compute(v.Controls, nil, v.Lens)
			if got.Grade != v.Want.Grade || got.RawGrade != v.Want.Raw {
				t.Fatalf("grade %s raw %s, want %s raw %s (caps %+v)", got.Grade, got.RawGrade, v.Want.Grade, v.Want.Raw, got.Caps)
			}
			if (got.Score == nil) != (v.Want.Score == nil) || (got.Score != nil && *got.Score != *v.Want.Score) {
				t.Fatalf("score %v, want %v", deref(got.Score), deref(v.Want.Score))
			}
		})
	}
}

func deref(f *float64) any {
	if f == nil {
		return nil
	}
	return *f
}

// TestParityWithJavaScript runs the HTML report's score.js on the same
// vectors: the grade a browser shows must be the grade the CLI prints.
func TestParityWithJavaScript(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	root := repoRoot(t)
	script := `
const s = require(process.argv[1]);
const vs = require(process.argv[2]);
const out = vs.map(v => s.compute(v.controls, null, v.lens));
process.stdout.write(JSON.stringify(out));`
	cmd := exec.Command(node, "-e", script, filepath.Join(root, "internal", "report", "assets", "score.js"), filepath.Join(root, "testdata", "score-vectors.json"))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	var js []model.Summary
	if err := json.Unmarshal(out, &js); err != nil {
		t.Fatalf("decode js output: %v\n%s", err, out)
	}
	for i, v := range loadVectors(t) {
		goSum := Compute(v.Controls, nil, v.Lens)
		a, _ := json.Marshal(goSum)
		b, _ := json.Marshal(js[i])
		var ga, jb map[string]any
		_ = json.Unmarshal(a, &ga)
		_ = json.Unmarshal(b, &jb)
		ja, _ := json.Marshal(ga)
		jj, _ := json.Marshal(jb)
		if string(ja) != string(jj) {
			t.Errorf("%s: Go and JS disagree\n go: %s\n js: %s", v.Name, ja, jj)
		}
	}
}

func TestLensFiltersByMapping(t *testing.T) {
	cs := []model.ControlResult{
		{ID: "A", Severity: "high", Status: model.Pass, Pillar: 1, Map: catalog.Mapping{PCI: []string{"8.3.6"}}},
		{ID: "B", Severity: "high", Status: model.Fail, Pillar: 1, Map: catalog.Mapping{ANSSI: []string{"R31"}}},
	}
	if s := Compute(cs, nil, "pci"); s.Grade != "A" || s.Counts.Total != 1 {
		t.Fatalf("pci lens: %+v", s)
	}
	if s := Compute(cs, nil, "anssi"); s.Grade != "E" {
		t.Fatalf("anssi lens: %+v", s)
	}
}

func TestProjected(t *testing.T) {
	cs := []model.ControlResult{
		{ID: "A", Severity: "high", Status: model.Pass, Qualifier: model.Durable, Pillar: 1},
		{ID: "B", Severity: "high", Status: model.Fail, Pillar: 1, Remediation: catalog.Remediation{Auto: true}},
		{ID: "C", Severity: "high", Status: model.Fail, Pillar: 1},
		{ID: "D", Severity: "low", Status: model.Fail, Qualifier: model.Pending, Pillar: 1},
		{ID: "E", Severity: "medium", Status: model.Pass, Qualifier: model.RuntimeOnly, Pillar: 1, Remediation: catalog.Remediation{Auto: true}},
	}
	s, n := Projected(cs, nil, "all")
	if n != 3 || s.Score == nil || *s.Score != 73.7 || s.Counts.Fail != 1 {
		t.Fatalf("projected %+v over %d fixes", s, n)
	}
	if cs[1].Status != model.Fail {
		t.Fatal("Projected must not modify its input")
	}
}
