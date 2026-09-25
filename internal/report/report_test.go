package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/catalog"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/score"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/ui"
)

// A hostile target can put anything in file names and messages.
const evil = `</script><script>alert(1)</script><img src=x onerror=alert(2)>`

func fixture() *model.Report {
	r := &model.Report{
		Schema: model.Schema, Tool: model.Tool{Name: "Shadow-Armor", Version: "0.0.0-test"},
		GeneratedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Target:      model.Target{URI: "ssh://web01", Kind: "ssh", Platform: model.Platform{Name: "ubuntu", Release: "24.04"}},
		Engine:      model.Engine{Name: "cinc-auditor", Version: "7.2.1", Mode: "on-target", Duration: 3.2},
		Selection:   model.Selection{Level: 1, Standard: "all", Count: 3},
		Weights:     score.DefaultWeights,
		Pillars:     []model.PillarMeta{{ID: 6, Key: "ssh", Title: "SSH access", TitleFR: "SSH"}, {ID: 1, Key: "app-rights", Title: "Apps"}},
		Controls: []model.ControlResult{
			{ID: "SA-06.01", Title: "SSH root login is disabled", Pillar: 6, Severity: "high", Level: 1, Status: model.Fail,
				Evidence:    []model.Evidence{{Kind: "effective", Status: "failed", Desc: "sshd -T PermitRootLogin " + evil + " value is expected to be in \"no\"", Message: evil}},
				Map:         catalog.Mapping{CIS: []string{"5.4"}, ANSSI: []string{"R79"}, NIST: []string{"AC-6(2)"}, PCI: []string{"2.2.6"}},
				Remediation: catalog.Remediation{Auto: true, Summary: "Set PermitRootLogin no"}, Source: "profile/controls/06-ssh.rb:30"},
			{ID: "SA-01.02", Title: "ASLR", Pillar: 1, Severity: "high", Level: 1, Status: model.Pass, Qualifier: model.RuntimeOnly,
				Proof: &model.Proof{Now: model.ProofProven, OnDisk: model.ProofFailed, Reboot: model.ProofFailed},
				Map:   catalog.Mapping{NIST: []string{"SI-16"}}, Remediation: catalog.Remediation{Auto: true, Summary: "x"}},
			{ID: "SA-01.13", Title: "Sandboxing", Pillar: 1, Severity: "low", Level: 2, Status: model.Skip, Reason: "systemd is not running",
				Map: catalog.Mapping{NIST: []string{"SC-39"}}, Remediation: catalog.Remediation{Summary: "y", Manual: "z"}},
		},
	}
	r.Summary = score.Compute(r.Controls, r.Weights, "all")
	return r
}

func TestHTMLIsSelfContainedAndInjectionSafe(t *testing.T) {
	var b bytes.Buffer
	if err := HTML(&b, fixture()); err != nil {
		t.Fatal(err)
	}
	page := b.String()
	if strings.Contains(page, evil) || strings.Contains(page, "<img src=x") {
		t.Fatal("hostile evidence reached the page unescaped")
	}
	if strings.Count(page, "</script>") != 3 {
		t.Fatalf("expected exactly the 3 script blocks of the template, got %d", strings.Count(page, "</script>"))
	}
	if m := regexp.MustCompile(`(?i)(src|href|url)\s*[=(]\s*["']?(https?:)?//`).FindString(page); m != "" {
		t.Fatalf("external resource reference %q in the page", m)
	}
	if !strings.Contains(page, "script-src 'sha256-") {
		t.Fatal("missing hash-based CSP")
	}
	for _, ph := range []string{"{{CSS}}", "{{DATA}}", "{{APP}}", "{{SCORE}}", "{{CSP}}"} {
		if strings.Contains(page, ph) {
			t.Fatalf("placeholder %s left in the page", ph)
		}
	}
}

func TestSARIF(t *testing.T) {
	var b bytes.Buffer
	if err := SARIF(&b, fixture()); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 || len(log.Runs[0].Results) != 1 || log.Runs[0].Results[0].RuleID != "SA-06.01" || log.Runs[0].Results[0].Level != "error" {
		t.Fatalf("unexpected SARIF: %s", b.String())
	}
}

func TestJUnit(t *testing.T) {
	var b bytes.Buffer
	if err := JUnit(&b, fixture()); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Suites []struct {
			Failures int `xml:"failures,attr"`
			Skipped  int `xml:"skipped,attr"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal(b.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	f, s := 0, 0
	for _, su := range v.Suites {
		f += su.Failures
		s += su.Skipped
	}
	if f != 1 || s != 1 {
		t.Fatalf("failures %d skipped %d", f, s)
	}
}

func TestTextAndMarkdown(t *testing.T) {
	r := fixture()
	var b bytes.Buffer
	Text(&b, r, TextOptions{Profile: ui.NoColor, Width: 110})
	out := b.String()
	for _, want := range []string{"SA-06.01", "GRADE D", "RUNTIME-ONLY", "now ✓ · on disk ✗ · after reboot ✗ would be undone", "sdw-armor harden ssh://web01", "HARDEN PATH"} {
		if !strings.Contains(out, want) {
			t.Errorf("text report lacks %q", want)
		}
	}
	b.Reset()
	if err := Markdown(&b, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "| high | `SA-06.01`") {
		t.Errorf("markdown lacks the failure row:\n%s", b.String())
	}
	if strings.Contains(b.String(), "<script>") {
		t.Error("markdown not escaped")
	}
}
