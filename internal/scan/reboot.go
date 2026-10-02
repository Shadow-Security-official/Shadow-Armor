package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/score"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/target"
)

const hostScript = `cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo; cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null || echo; cut -d' ' -f1 /proc/uptime 2>/dev/null || echo; uname -n`

// HostOf reads the machine and boot identity of the target. It needs no
// privilege and changes nothing.
func HostOf(ctx context.Context, t *target.Target) (*model.Host, error) {
	out, err := t.Output(ctx, hostScript, false)
	if err != nil {
		return nil, err
	}
	return parseHost(out, time.Now()), nil
}

func parseHost(out string, now time.Time) *model.Host {
	lines := strings.Split(out, "\n")
	for len(lines) < 4 {
		lines = append(lines, "")
	}
	h := &model.Host{BootID: strings.TrimSpace(lines[0]), Hostname: strings.TrimSpace(lines[3])}
	if id := strings.TrimSpace(lines[1]); id != "" {
		sum := sha256.Sum256([]byte("shadow-armor/machine-id/" + id))
		h.MachineHash = hex.EncodeToString(sum[:])[:32]
	}
	if up, err := strconv.ParseFloat(strings.TrimSpace(lines[2]), 64); err == nil && up > 0 {
		b := now.Add(-time.Duration(up * float64(time.Second))).UTC().Round(time.Second)
		h.BootedAt = &b
	}
	return h
}

// RebootResult summarises what a reboot baseline proved.
type RebootResult struct {
	Baseline string   // boot id of the baseline
	Proven   []string // passed before and after the reboot
	Lost     []string // passed before, fail after
}

// ApplyRebootBaseline compares a report with one taken in an earlier boot of
// the same host. A control that passed then and passes now survived a real
// reboot: its reboot proof becomes "proven" and a runtime-only qualifier is
// lifted (the empirical proof beats the inference). A control that passed
// then and fails now was lost at the reboot. The summary is recomputed.
func ApplyRebootBaseline(cur, base *model.Report) (RebootResult, error) {
	var res RebootResult
	if ok, why := model.Rebooted(base.Target.Host, cur.Target.Host); !ok {
		return res, errors.New(why)
	}
	if !base.GeneratedAt.Before(cur.GeneratedAt) {
		return res, fmt.Errorf("the baseline (%s) is not older than this scan (%s)", base.GeneratedAt.Format(time.RFC3339), cur.GeneratedAt.Format(time.RFC3339))
	}
	res.Baseline = base.Target.Host.BootID
	before := map[string]model.ControlResult{}
	for _, c := range base.Controls {
		before[c.ID] = c
	}
	when := base.GeneratedAt.Format("2006-01-02 15:04 MST")
	for i := range cur.Controls {
		c := &cur.Controls[i]
		b, ok := before[c.ID]
		if !ok || b.Status != model.Pass {
			continue
		}
		switch c.Status {
		case model.Pass:
			if c.Proof == nil {
				c.Proof = &model.Proof{}
			}
			c.Proof.Reboot = model.ProofProven
			c.Proof.RebootBaseline = res.Baseline
			c.Reason = "survived a real reboot (passed in the baseline of " + when + " and after the reboot)"
			switch {
			case c.Qualifier == model.RuntimeOnly && c.Proof.OnDisk == model.ProofFailed:
				c.Reason += ", although the persisted configuration Shadow-Armor reads contradicts it: something else re-applies it at boot"
			case c.Qualifier == model.RuntimeOnly:
				c.Reason += ": the reboot proves what the live-only check could not"
			}
			c.Qualifier = model.Durable
			res.Proven = append(res.Proven, c.ID)
		case model.Fail, model.Error:
			if c.Proof == nil {
				c.Proof = &model.Proof{}
			}
			c.Proof.Reboot = model.ProofLost
			c.Proof.RebootBaseline = res.Baseline
			c.Reason = strings.TrimSpace("lost at the reboot: passed in the baseline of " + when + ", fails since the reboot. " + c.Reason)
			res.Lost = append(res.Lost, c.ID)
		}
	}
	cur.Summary = score.Compute(cur.Controls, cur.Weights, cur.Summary.Lens)
	return res, nil
}
