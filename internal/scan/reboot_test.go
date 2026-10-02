package scan

import (
	"strings"
	"testing"
	"time"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/score"
)

func TestParseHost(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	h := parseHost("0b6e1c52-4d1f-4b9e-9a1f-1a2b3c4d5e6f\n5c1d9e0b7a8f4e6d9c2b1a0f9e8d7c6b\n3600.2\nweb01\n", now)
	if h.BootID != "0b6e1c52-4d1f-4b9e-9a1f-1a2b3c4d5e6f" || h.Hostname != "web01" {
		t.Fatalf("%+v", h)
	}
	if len(h.MachineHash) != 32 || strings.Contains(h.MachineHash, "5c1d9e0b") {
		t.Fatalf("the machine id must be hashed, got %q", h.MachineHash)
	}
	if h.BootedAt == nil || !h.BootedAt.Equal(now.Add(-time.Hour)) {
		t.Fatalf("booted at %v", h.BootedAt)
	}
	if e := parseHost("", now); e.BootID != "" || e.MachineHash != "" || e.BootedAt != nil {
		t.Fatalf("empty output: %+v", e)
	}
}

func rep(boot string, at time.Time, controls ...model.ControlResult) *model.Report {
	booted := at.Add(-time.Minute)
	r := &model.Report{GeneratedAt: at, Weights: score.DefaultWeights, Controls: controls,
		Target: model.Target{Host: &model.Host{Hostname: "web01", MachineHash: "m1", BootID: boot, BootedAt: &booted}}}
	r.Summary = score.Compute(r.Controls, r.Weights, "all")
	return r
}

func ctl(id string, st model.Status, q model.Qualifier, reboot string) model.ControlResult {
	return model.ControlResult{ID: id, Severity: "high", Pillar: 1, Status: st, Qualifier: q,
		Proof: &model.Proof{Now: model.ProofProven, OnDisk: model.ProofNotMeasured, Reboot: reboot}}
}

func TestApplyRebootBaseline(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	before := rep("boot-1", t0,
		ctl("SA-01", model.Pass, model.Durable, model.ProofExpected),
		ctl("SA-02", model.Pass, model.RuntimeOnly, model.ProofNotMeasured),
		ctl("SA-03", model.Pass, model.RuntimeOnly, model.ProofFailed),
		ctl("SA-04", model.Fail, model.Pending, model.ProofExpected),
	)
	after := rep("boot-2", t0.Add(time.Hour),
		ctl("SA-01", model.Pass, model.Durable, model.ProofExpected),
		ctl("SA-02", model.Pass, model.RuntimeOnly, model.ProofNotMeasured),
		ctl("SA-03", model.Fail, "", model.ProofFailed),
		ctl("SA-04", model.Pass, model.Durable, model.ProofExpected),
	)
	res, err := ApplyRebootBaseline(after, before)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Proven, ",") != "SA-01,SA-02" || strings.Join(res.Lost, ",") != "SA-03" {
		t.Fatalf("proven %v lost %v", res.Proven, res.Lost)
	}
	by := map[string]model.ControlResult{}
	for _, c := range after.Controls {
		by[c.ID] = c
	}
	if c := by["SA-02"]; c.Qualifier != model.Durable || c.Proof.Reboot != model.ProofProven {
		t.Fatalf("a runtime-only pass that survived a reboot is reboot-proven: %+v %+v", c, c.Proof)
	}
	if c := by["SA-03"]; c.Proof.Reboot != model.ProofLost || !strings.Contains(c.Reason, "lost at the reboot") {
		t.Fatalf("lost: %+v", c)
	}
	if c := by["SA-04"]; c.Proof.Reboot != model.ProofExpected {
		t.Fatalf("a pending fix confirmed by the reboot is not a reboot-proven pass: %+v", c.Proof)
	}
	if after.Summary.Counts.RebootProven != 2 || after.Summary.Counts.RuntimeOnly != 0 {
		t.Fatalf("summary not recomputed: %+v", after.Summary.Counts)
	}

	same := rep("boot-2", t0.Add(2*time.Hour), ctl("SA-01", model.Pass, model.Durable, model.ProofExpected))
	if _, err := ApplyRebootBaseline(same, after); err == nil || !strings.Contains(err.Error(), "no reboot") {
		t.Fatalf("same boot must be refused, got %v", err)
	}
	other := rep("boot-9", t0.Add(3*time.Hour))
	other.Target.Host.MachineHash = "m2"
	if _, err := ApplyRebootBaseline(other, before); err == nil || !strings.Contains(err.Error(), "different machines") {
		t.Fatalf("another machine must be refused, got %v", err)
	}
	late := rep("boot-3", t0.Add(4*time.Hour))
	early := rep("boot-4", t0.Add(3*time.Hour))
	if _, err := ApplyRebootBaseline(early, late); err == nil || !strings.Contains(err.Error(), "not older") {
		t.Fatalf("a baseline newer than the scan must be refused, got %v", err)
	}
}
