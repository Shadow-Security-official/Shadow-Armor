package engine

import "encoding/json"

// InSpec JSON reporter output (the subset Shadow-Armor reads). The format is
// shared by CINC Auditor and Chef InSpec 5+.

type InspecReport struct {
	Platform   InspecPlatform  `json:"platform"`
	Profiles   []InspecProfile `json:"profiles"`
	Statistics struct {
		Duration float64 `json:"duration"`
	} `json:"statistics"`
	Version string `json:"version"`
}

type InspecPlatform struct {
	Name     string `json:"name"`
	Release  string `json:"release"`
	TargetID string `json:"target_id"`
}

type InspecProfile struct {
	Name     string          `json:"name"`
	Version  string          `json:"version"`
	SHA256   string          `json:"sha256"`
	Controls []InspecControl `json:"controls"`
}

type InspecControl struct {
	ID             string          `json:"id"`
	Title          *string         `json:"title"`
	Impact         float64         `json:"impact"`
	Tags           json.RawMessage `json:"tags"`
	SourceLocation struct {
		Ref  string `json:"ref"`
		Line int    `json:"line"`
	} `json:"source_location"`
	WaiverData map[string]any `json:"waiver_data"`
	Results    []InspecResult `json:"results"`
}

type InspecResult struct {
	Status      string  `json:"status"`
	CodeDesc    string  `json:"code_desc"`
	RunTime     float64 `json:"run_time"`
	Message     string  `json:"message"`
	SkipMessage string  `json:"skip_message"`
	Exception   string  `json:"exception"`
	ResourceID  string  `json:"resource_id"`
}

// ParseReport decodes an InSpec JSON report.
func ParseReport(raw []byte) (*InspecReport, error) {
	var r InspecReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
