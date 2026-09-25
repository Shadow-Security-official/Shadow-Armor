package harden

import (
	"encoding/json"
	"testing"

	shadowarmor "github.com/Shadow-Security-official/Shadow-Armor"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/catalog"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
)

func TestResolvePlaceholders(t *testing.T) {
	vals := map[string]any{"n": float64(4), "ports": []any{float64(22), float64(443)}, "dirs": []any{"/a", "/b"}, "s": "027"}
	in := map[string]any{
		"one":   "{{n}}",
		"text":  "umask {{s}}\n",
		"list":  "{{ports}}",
		"paths": []any{"{{dirs}}", "/c"},
	}
	out := resolve(in, vals).(map[string]any)
	b, _ := json.Marshal(out)
	want := `{"list":[22,443],"one":4,"paths":["/a","/b","/c"],"text":"umask 027\n"}`
	if string(b) != want {
		t.Fatalf("got %s want %s", b, want)
	}
	empty := resolve([]any{}, vals)
	if b, _ := json.Marshal(empty); string(b) != "[]" {
		t.Fatalf("empty list became %s", b)
	}
}

func TestNewPlanFiltersPlatformAndResolvesInputs(t *testing.T) {
	cat, err := catalog.Load(shadowarmor.Profile)
	if err != nil {
		t.Fatal(err)
	}
	rep := &model.Report{Target: model.Target{URI: "local://", Platform: model.Platform{Name: "ubuntu", Release: "24.04"}}}
	chosen := []model.ControlResult{{ID: "SA-06.04", Status: model.Fail}, {ID: "SA-09.07", Status: model.Fail}, {ID: "SA-09.12", Status: model.Fail}}
	p, err := New(cat, rep, chosen, map[string]any{"sdw_ssh_max_auth_tries": float64(3)})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Items) != 2 || len(p.NotAutomated) != 1 || p.NotAutomated[0] != "SA-09.12" {
		t.Fatalf("items %d, not automated %v", len(p.Items), p.NotAutomated)
	}
	settings := p.Items[0].Actions[0]["settings"].(map[string]any)
	if settings["MaxAuthTries"] != int64(3) {
		t.Fatalf("MaxAuthTries = %#v", settings["MaxAuthTries"])
	}
	for _, a := range p.Items[1].Actions {
		if a["platform"] == "rhel" {
			t.Fatal("rhel action kept on ubuntu")
		}
	}
	if _, err := p.Attributes(); err != nil {
		t.Fatal(err)
	}
}

func TestEveryActionDescribes(t *testing.T) {
	cat, err := catalog.Load(shadowarmor.Profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cat.Controls {
		for _, a := range c.Remediation.Actions {
			if d := Describe(a); d == "" || d[0] == '{' {
				t.Errorf("%s: kind %v has no description", c.ID, a["kind"])
			}
		}
	}
}
