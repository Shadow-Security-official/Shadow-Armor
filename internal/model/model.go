// Package model defines the Shadow-Armor report: the qualified result of every
// control, the evidence behind it and the score. It is the JSON contract
// shared by the CLI, the HTML report, `sdw-armor diff` and `harden`.
package model

import (
	"time"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/catalog"
)

// Schema identifies the report format.
const Schema = "shadow-armor/report@1"

// Status of a control after qualification.
type Status string

const (
	Pass   Status = "pass"
	Fail   Status = "fail"
	Error  Status = "error" // could not be evaluated: counts as a failure (fail-closed)
	Skip   Status = "skip"  // not applicable on this target
	Waived Status = "waived"
)

// Qualifier says what a verdict proves.
type Qualifier string

const (
	// Durable: compliant now and after a reboot (or the check is on durable state).
	Durable Qualifier = "durable"
	// RuntimeOnly: compliant now, but the persisted configuration would undo
	// it at the next reboot/reload, or nothing on disk proves it survives
	// one. Caps an A that rests on it to B.
	RuntimeOnly Qualifier = "runtime-only"
	// Pending: not compliant now, but the persisted configuration is: a
	// reboot or reload will fix it.
	Pending Qualifier = "pending"
)

// Proof says what the assertions of a control establish, column by column.
// Values: proven, failed, not_measured; the reboot column also takes
// expected (the persisted state is compliant), proven (observed across a
// real reboot) and n/a (transient state that a reboot clears).
type Proof struct {
	Now    string `json:"now"`
	OnDisk string `json:"on_disk"`
	Reboot string `json:"reboot"`
	// Boot the pass was first observed in, when Reboot is proven.
	RebootBaseline string `json:"reboot_baseline,omitempty"`
}

const (
	ProofProven      = "proven"
	ProofFailed      = "failed"
	ProofNotMeasured = "not_measured"
	ProofExpected    = "expected"
	ProofNA          = "n/a"
	// ProofLost: passed in the reboot baseline, fails after the reboot.
	ProofLost = "lost"
)

// Evidence is one assertion of a control, as the engine reported it.
type Evidence struct {
	Kind    string `json:"kind"` // runtime | persistent | config | inventory | filesystem | transient
	Status  string `json:"status"`
	Desc    string `json:"desc"`
	Message string `json:"message,omitempty"`
}

type Waiver struct {
	Justification string `json:"justification,omitempty"`
	Expires       string `json:"expires,omitempty"`
}

type ControlResult struct {
	ID          string              `json:"id"`
	Title       string              `json:"title"`
	Pillar      int                 `json:"pillar"`
	Severity    string              `json:"severity"`
	Level       int                 `json:"level"`
	Scope       string              `json:"scope,omitempty"`
	Status      Status              `json:"status"`
	Qualifier   Qualifier           `json:"qualifier,omitempty"`
	Reason      string              `json:"reason,omitempty"`
	Rationale   string              `json:"rationale,omitempty"`
	Check       string              `json:"check,omitempty"`
	Proof       *Proof              `json:"proof,omitempty"`
	Evidence    []Evidence          `json:"evidence,omitempty"`
	Map         catalog.Mapping     `json:"map"`
	Remediation catalog.Remediation `json:"remediation"`
	Waiver      *Waiver             `json:"waiver,omitempty"`
	Source      string              `json:"source,omitempty"` // profile file:line of the control
}

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

type Platform struct {
	Name    string `json:"name"`
	Release string `json:"release"`
	Family  string `json:"family,omitempty"`
	Arch    string `json:"arch,omitempty"`
}

type Target struct {
	URI       string   `json:"uri"`
	Kind      string   `json:"kind"`
	Platform  Platform `json:"platform"`
	Container string   `json:"container,omitempty"`
	Host      *Host    `json:"host,omitempty"`
}

// Host identifies the machine and the boot a scan observed, so two reports
// can prove that a state survived a real reboot.
type Host struct {
	Hostname string `json:"hostname,omitempty"`
	// MachineHash is a hash of /etc/machine-id (the raw ID is confidential,
	// see machine-id(5)): equal hashes mean the same installation.
	MachineHash string `json:"machine_hash,omitempty"`
	// BootID changes at every boot (/proc/sys/kernel/random/boot_id).
	BootID   string     `json:"boot_id,omitempty"`
	BootedAt *time.Time `json:"booted_at,omitempty"`
}

// Rebooted reports whether two observations are the same host across a
// reboot (and why not, when they are not).
func Rebooted(before, after *Host) (bool, string) {
	switch {
	case before == nil || after == nil || before.BootID == "" || after.BootID == "":
		return false, "a report has no boot identity (made by an older sdw-armor?)"
	case before.MachineHash != "" && after.MachineHash != "" && before.MachineHash != after.MachineHash:
		return false, "the reports come from different machines (machine-id differs)"
	case before.MachineHash == "" && after.MachineHash == "" && before.Hostname != after.Hostname:
		return false, "the reports come from different hosts"
	case before.BootID == after.BootID:
		return false, "no reboot happened between the two scans (same boot id)"
	}
	return true, ""
}

type Engine struct {
	Name     string  `json:"name"`
	Version  string  `json:"version"`
	Mode     string  `json:"mode"`            // local | remote | on-target | docker
	Image    string  `json:"image,omitempty"` // Docker engine image (with its digest)
	Duration float64 `json:"duration_s"`
}

type Selection struct {
	Level    int    `json:"level"`
	Pillars  []int  `json:"pillars,omitempty"`
	Standard string `json:"standard"`
	Count    int    `json:"count"`
}

// PillarMeta and StandardMeta travel with the report so a saved report (and
// the HTML page) is self-describing.
type PillarMeta struct {
	ID      int    `json:"id"`
	Key     string `json:"key"`
	Title   string `json:"title"`
	TitleFR string `json:"title_fr"`
}

type StandardMeta struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type Report struct {
	Schema      string             `json:"schema"`
	Tool        Tool               `json:"tool"`
	GeneratedAt time.Time          `json:"generated_at"`
	Target      Target             `json:"target"`
	Engine      Engine             `json:"engine"`
	Profile     string             `json:"profile_version"`
	Selection   Selection          `json:"selection"`
	Inputs      map[string]any     `json:"inputs,omitempty"`
	Weights     map[string]float64 `json:"weights"`
	Pillars     []PillarMeta       `json:"pillars"`
	Standards   []StandardMeta     `json:"standards"`
	Controls    []ControlResult    `json:"controls"`
	Summary     Summary            `json:"summary"`
}

// Summary is the scored view of a report (see internal/score).
type Summary struct {
	Lens     string   `json:"lens"`
	Score    *float64 `json:"score"`
	Grade    string   `json:"grade"`
	RawGrade string   `json:"raw_grade"`
	Caps     []Cap    `json:"caps,omitempty"`
	// RuntimeQualified: the A was capped to B because it rests on passes
	// whose persistence is not proven (QualifiedPasses of them).
	RuntimeQualified bool            `json:"runtime_qualified"`
	QualifiedPasses  int             `json:"qualified_passes"`
	Counts           Counts          `json:"counts"`
	Pillars          []PillarSummary `json:"pillars"`
}

type Cap struct {
	Grade  string   `json:"grade"`
	Reason string   `json:"reason"`
	IDs    []string `json:"ids,omitempty"`
}

type Counts struct {
	Pass         int `json:"pass"`
	Fail         int `json:"fail"`
	Error        int `json:"error"`
	Skip         int `json:"skip"`
	Waived       int `json:"waived"`
	RuntimeOnly  int `json:"runtime_only"`
	Pending      int `json:"pending"`
	RebootProven int `json:"reboot_proven"`
	Total        int `json:"total"`
}

type PillarSummary struct {
	ID     int      `json:"id"`
	Score  *float64 `json:"score"`
	Grade  string   `json:"grade"`
	Counts Counts   `json:"counts"`
}
