// Package catalog loads the Shadow-Armor control catalog: the single source
// of truth for control metadata, standard mappings, input defaults and
// declarative remediations. The same file is read by the InSpec profile, so
// the CLI and a plain `cinc-auditor exec` always agree.
package catalog

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// Path of the catalog inside the embedded profile.
const Path = "profile/files/catalog.json"

type Catalog struct {
	Schema          int                 `json:"schema"`
	Name            string              `json:"name"`
	Pillars         []Pillar            `json:"pillars"`
	Standards       map[string]Standard `json:"standards"`
	SeverityWeights map[string]float64  `json:"severity_weights"`
	Inputs          []Input             `json:"inputs"`
	Controls        []Control           `json:"controls"`

	byID map[string]*Control
}

type Pillar struct {
	ID      int    `json:"id"`
	Key     string `json:"key"`
	Title   string `json:"title"`
	TitleFR string `json:"title_fr"`
	Summary string `json:"summary"`
}

type Standard struct {
	Name   string `json:"name"`
	Detail string `json:"detail"`
}

type Input struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
	Desc  string          `json:"desc"`
}

type Control struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	TitleFR  string `json:"title_fr,omitempty"`
	Pillar   int    `json:"pillar"`
	Severity string `json:"severity"`
	Level    int    `json:"level"`
	Scope    string `json:"scope"`
	// Evidence lists the kinds of state the control's assertions read, the
	// type of its unprefixed assertions first: config, inventory, filesystem,
	// transient, then runtime (runtime* properties, or a live-only check) and
	// persistent (persistent* properties). See internal/verdict.
	Evidence    []string    `json:"evidence"`
	Rationale   string      `json:"rationale"`
	Check       string      `json:"check"`
	Map         Mapping     `json:"map"`
	Remediation Remediation `json:"remediation"`
}

// Mapping holds every standard reference of one control.
type Mapping struct {
	CIS          []string `json:"cis,omitempty"`
	CISBenchmark string   `json:"cis_benchmark,omitempty"`
	ANSSI        []string `json:"anssi,omitempty"`
	NIST         []string `json:"nist,omitempty"`
	NIST171      []string `json:"nist171,omitempty"`
	PCI          []string `json:"pci,omitempty"`
	STIG         []string `json:"stig,omitempty"`
}

// Remediation is declarative: a list of typed actions the cookbook knows how
// to converge, or manual guidance when a safe automatic fix does not exist.
type Remediation struct {
	Auto    bool             `json:"auto"`
	Summary string           `json:"summary"`
	Risk    string           `json:"risk,omitempty"`
	Reboot  bool             `json:"reboot,omitempty"`
	Guards  []string         `json:"guards,omitempty"`
	Actions []map[string]any `json:"actions,omitempty"`
	Manual  string           `json:"manual,omitempty"`
}

// Standards the CLI can filter or "lens" on.
var StandardKeys = []string{"cis", "anssi", "nist", "nist171", "pci", "stig"}

// Refs returns the references of a control for one standard key.
func (m Mapping) Refs(std string) []string {
	switch std {
	case "cis":
		out := append([]string{}, prefixed("v8 ", m.CIS)...)
		if m.CISBenchmark != "" {
			out = append(out, m.CISBenchmark)
		}
		return out
	case "anssi":
		return m.ANSSI
	case "nist":
		return m.NIST
	case "nist171":
		return m.NIST171
	case "pci":
		return m.PCI
	case "stig":
		return m.STIG
	}
	return nil
}

// Has reports whether the control maps to the standard at all.
func (m Mapping) Has(std string) bool {
	if std == "" || std == "all" {
		return true
	}
	return len(m.Refs(std)) > 0
}

func prefixed(p string, in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = p + s
	}
	return out
}

// Load parses the catalog from a filesystem (normally the embedded profile).
func Load(fsys fs.FS) (*Catalog, error) {
	raw, err := fs.ReadFile(fsys, Path)
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	return Parse(raw)
}

func Parse(raw []byte) (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}
	if c.Schema != 1 {
		return nil, fmt.Errorf("unsupported catalog schema %d", c.Schema)
	}
	c.byID = make(map[string]*Control, len(c.Controls))
	for i := range c.Controls {
		ctl := &c.Controls[i]
		if _, dup := c.byID[ctl.ID]; dup {
			return nil, fmt.Errorf("duplicate control %s", ctl.ID)
		}
		c.byID[ctl.ID] = ctl
	}
	return &c, nil
}

func (c *Catalog) Control(id string) (*Control, bool) {
	ctl, ok := c.byID[strings.ToUpper(strings.TrimSpace(id))]
	return ctl, ok
}

func (c *Catalog) Pillar(id int) (Pillar, bool) {
	for _, p := range c.Pillars {
		if p.ID == id {
			return p, true
		}
	}
	return Pillar{}, false
}

// Weight of a severity in the score.
func (c *Catalog) Weight(sev string) float64 {
	return c.SeverityWeights[sev]
}

// InputDefaults returns every declared input with its default value.
func (c *Catalog) InputDefaults() map[string]any {
	out := make(map[string]any, len(c.Inputs))
	for _, in := range c.Inputs {
		var v any
		_ = json.Unmarshal(in.Value, &v)
		out[in.Name] = v
	}
	return out
}

// Filter selects controls for a scan.
type Filter struct {
	Level    int      // 1 = baseline, 2 = baseline + hardened (0 means 2)
	Pillars  []int    // empty = all
	Standard string   // "" or "all" = all; otherwise only controls mapped to it
	IDs      []string // explicit list (overrides the other criteria when set)
	Exclude  []string
}

func (c *Catalog) Select(f Filter) []Control {
	level := f.Level
	if level == 0 {
		level = 2
	}
	ids := setOf(f.IDs)
	excl := setOf(f.Exclude)
	pillars := map[int]bool{}
	for _, p := range f.Pillars {
		pillars[p] = true
	}
	var out []Control
	for _, ctl := range c.Controls {
		if excl[ctl.ID] {
			continue
		}
		if len(ids) > 0 {
			if ids[ctl.ID] {
				out = append(out, ctl)
			}
			continue
		}
		if ctl.Level > level {
			continue
		}
		if len(pillars) > 0 && !pillars[ctl.Pillar] {
			continue
		}
		if !ctl.Map.Has(f.Standard) {
			continue
		}
		out = append(out, ctl)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func setOf(in []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range in {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s != "" {
			m[s] = true
		}
	}
	return m
}

// ValidStandard reports whether s names a known standard key (or "all").
func ValidStandard(s string) bool {
	if s == "" || s == "all" {
		return true
	}
	for _, k := range StandardKeys {
		if k == s {
			return true
		}
	}
	return false
}

// StandardLabel is the human name of a standard key.
func (c *Catalog) StandardLabel(key string) string {
	if key == "" || key == "all" {
		return "All standards"
	}
	if s, ok := c.Standards[key]; ok {
		return s.Name
	}
	return key
}

// EvidenceKinds are the values a control's evidence list may hold.
var EvidenceKinds = []string{"config", "inventory", "filesystem", "transient", "runtime", "persistent"}

// DeclaredType is the evidence type of the control's unprefixed assertions:
// the first listed kind that is neither runtime nor persistent, runtime for a
// live-only control, config otherwise.
func (c Control) DeclaredType() string {
	live := false
	for _, k := range c.Evidence {
		switch k {
		case "persistent":
		case "runtime":
			live = true
		default:
			return k
		}
	}
	if live {
		return "runtime"
	}
	return "config"
}

// Proves describes, for people, what the control's evidence covers.
func (c Control) Proves() string {
	label := map[string]string{"config": "resolved config", "inventory": "inventory", "filesystem": "files", "transient": "live (transient)", "runtime": "live", "persistent": "boot"}
	out := make([]string, 0, len(c.Evidence))
	for _, k := range c.Evidence {
		out = append(out, label[k])
	}
	return strings.Join(out, " + ")
}
