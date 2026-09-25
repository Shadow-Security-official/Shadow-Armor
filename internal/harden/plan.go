// Package harden turns failing controls into a reviewed, opt-in remediation
// plan and converges it with a native Chef run (cinc-client --local-mode).
package harden

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/catalog"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
)

const PlanSchema = "shadow-armor/plan@1"

// Item is one control the plan will fix.
type Item struct {
	Control  string           `json:"control"`
	Title    string           `json:"title"`
	Severity string           `json:"severity"`
	Before   string           `json:"before"` // fail, error, fail/pending, pass/runtime-only
	Summary  string           `json:"summary"`
	Risk     string           `json:"risk,omitempty"`
	Reboot   bool             `json:"reboot,omitempty"`
	Guards   []string         `json:"guards,omitempty"`
	Actions  []map[string]any `json:"actions"`
}

type Plan struct {
	Schema    string         `json:"schema"`
	RunID     string         `json:"run_id"`
	Target    string         `json:"target"`
	Platform  model.Platform `json:"platform"`
	CreatedAt time.Time      `json:"created_at"`
	Items     []Item         `json:"items"`
	// NotAutomated lists chosen controls whose fix is not automated on this
	// platform (every action targets another platform family).
	NotAutomated []string `json:"not_automated,omitempty"`
}

// Family maps an InSpec platform name to the catalog's platform families.
func Family(name string) string {
	switch strings.ToLower(name) {
	case "ubuntu", "debian", "linuxmint", "kali", "raspbian", "pop", "elementary":
		return "debian"
	case "redhat", "rhel", "centos", "rocky", "almalinux", "fedora", "oracle", "ol", "amazon", "scientific", "centos stream":
		return "rhel"
	}
	return ""
}

// Candidates are controls worth fixing that have an automatic remediation:
// failures, errors and runtime-only passes (persistence missing). Waived and
// non-applicable controls are never touched.
func Candidates(rep *model.Report) []model.ControlResult {
	var out []model.ControlResult
	for _, c := range rep.Controls {
		if !c.Remediation.Auto {
			continue
		}
		if c.Status == model.Fail || c.Status == model.Error || (c.Status == model.Pass && c.Qualifier == model.RuntimeOnly) {
			out = append(out, c)
		}
	}
	sevRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.SliceStable(out, func(i, j int) bool {
		if sevRank[out[i].Severity] != sevRank[out[j].Severity] {
			return sevRank[out[i].Severity] < sevRank[out[j].Severity]
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// ManualOnly lists failing controls that need a human.
func ManualOnly(rep *model.Report) []model.ControlResult {
	var out []model.ControlResult
	for _, c := range rep.Controls {
		if !c.Remediation.Auto && (c.Status == model.Fail || c.Status == model.Error) {
			out = append(out, c)
		}
	}
	return out
}

func beforeLabel(c model.ControlResult) string {
	if c.Qualifier != "" && c.Qualifier != model.Durable {
		return string(c.Status) + "/" + string(c.Qualifier)
	}
	return string(c.Status)
}

// New builds a plan for the chosen controls of a report.
func New(cat *catalog.Catalog, rep *model.Report, chosen []model.ControlResult, inputs map[string]any) (*Plan, error) {
	vals := cat.InputDefaults()
	for k, v := range rep.Inputs {
		vals[k] = v
	}
	for k, v := range inputs {
		vals[k] = v
	}
	fam := Family(rep.Target.Platform.Name)
	p := &Plan{Schema: PlanSchema, RunID: runID(), Target: rep.Target.URI, Platform: rep.Target.Platform, CreatedAt: time.Now().UTC().Truncate(time.Second)}
	for _, c := range chosen {
		ctl, ok := cat.Control(c.ID)
		if !ok || !ctl.Remediation.Auto {
			return nil, fmt.Errorf("%s has no automatic remediation", c.ID)
		}
		it := Item{Control: c.ID, Title: ctl.Title, Severity: ctl.Severity, Before: beforeLabel(c), Summary: resolveString(ctl.Remediation.Summary, vals),
			Risk: ctl.Remediation.Risk, Reboot: ctl.Remediation.Reboot, Guards: ctl.Remediation.Guards}
		for _, a := range ctl.Remediation.Actions {
			if pf, _ := a["platform"].(string); pf != "" && fam != "" && pf != fam {
				continue
			}
			ra, ok := resolve(a, vals).(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s: malformed action", c.ID)
			}
			ra["control"] = c.ID
			it.Actions = append(it.Actions, ra)
		}
		if len(it.Actions) == 0 {
			p.NotAutomated = append(p.NotAutomated, c.ID)
			continue
		}
		p.Items = append(p.Items, it)
	}
	return p, nil
}

// Drop removes the items of the given controls from the plan.
func (p *Plan) Drop(controls []string) {
	skip := map[string]bool{}
	for _, c := range controls {
		skip[c] = true
	}
	kept := p.Items[:0]
	for _, it := range p.Items {
		if !skip[it.Control] {
			kept = append(kept, it)
		}
	}
	p.Items = kept
}

func runID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}

var placeholder = regexp.MustCompile(`\{\{\s*([a-z0-9_]+)\s*\}\}`)

// resolve replaces {{input}} placeholders; a string that is exactly one
// placeholder takes the input's type (list, number...), and a list element
// that resolves to a list is spliced in.
func resolve(v any, vals map[string]any) any {
	switch x := v.(type) {
	case string:
		if m := placeholder.FindStringSubmatch(x); m != nil && m[0] == strings.TrimSpace(x) {
			if val, ok := vals[m[1]]; ok {
				return normalize(val)
			}
		}
		return resolveString(x, vals)
	case []any:
		out := make([]any, 0, len(x))
		for _, e := range x {
			r := resolve(e, vals)
			if l, ok := r.([]any); ok {
				if s, isStr := e.(string); isStr && placeholder.MatchString(s) {
					out = append(out, l...)
					continue
				}
			}
			out = append(out, r)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = resolve(e, vals)
		}
		return out
	}
	return v
}

func resolveString(s string, vals map[string]any) string {
	return placeholder.ReplaceAllStringFunc(s, func(m string) string {
		name := placeholder.FindStringSubmatch(m)[1]
		if v, ok := vals[name]; ok {
			switch t := v.(type) {
			case string:
				return t
			case float64:
				if t == float64(int64(t)) {
					return fmt.Sprintf("%d", int64(t))
				}
				return fmt.Sprint(t)
			default:
				b, _ := json.Marshal(t)
				return string(b)
			}
		}
		return m
	})
}

// normalize converts JSON-decoded numbers that are integers to int64 so the
// cookbook sees 4, not 4.0.
func normalize(v any) any {
	switch t := v.(type) {
	case float64:
		if t == float64(int64(t)) {
			return int64(t)
		}
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = normalize(e)
		}
		return out
	}
	return v
}

// Controls lists the control IDs of the plan.
func (p *Plan) Controls() []string {
	out := make([]string, len(p.Items))
	for i, it := range p.Items {
		out[i] = it.Control
	}
	return out
}

// Actions flattens every action of the plan, in order.
func (p *Plan) Actions() []map[string]any {
	var out []map[string]any
	for _, it := range p.Items {
		out = append(out, it.Actions...)
	}
	return out
}

// Attributes is the JSON handed to cinc-client --json-attributes.
func (p *Plan) Attributes() ([]byte, error) {
	return json.MarshalIndent(map[string]any{
		"shadow_armor": map[string]any{"run_id": p.RunID, "actions": p.Actions()},
	}, "", "  ")
}

func (p *Plan) NeedsReboot() bool {
	for _, it := range p.Items {
		if it.Reboot {
			return true
		}
	}
	return false
}

// Save writes the plan (mode 0600).
func (p *Plan) Save(path string) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// Load reads a plan file.
func Load(path string) (*Plan, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Plan
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("%s: not a plan: %v", path, err)
	}
	if p.Schema != PlanSchema {
		return nil, fmt.Errorf("%s: unsupported plan schema %q", path, p.Schema)
	}
	return &p, nil
}

// Describe renders one action as a human sentence for the plan review.
func Describe(a map[string]any) string {
	s := func(k string) string { v, _ := a[k].(string); return v }
	list := func(k string) string {
		switch v := a[k].(type) {
		case []any:
			parts := make([]string, len(v))
			for i, e := range v {
				parts[i] = fmt.Sprint(e)
			}
			return strings.Join(parts, ", ")
		case map[string]any:
			var parts []string
			for _, fam := range []string{"debian", "rhel", "default"} {
				if l, ok := v[fam].([]any); ok {
					for _, e := range l {
						parts = append(parts, fmt.Sprint(e)+" ("+fam+")")
					}
				}
			}
			return strings.Join(parts, ", ")
		}
		return fmt.Sprint(a[k])
	}
	kv := func(k, sep string) string {
		m, _ := a[k].(map[string]any)
		keys := make([]string, 0, len(m))
		for key := range m {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, key := range keys {
			v := m[key]
			if mm, ok := v.(map[string]any); ok {
				v = "strongest of [" + strings.Trim(fmt.Sprint(mm["prefer"]), "[]") + "] supported here"
			}
			parts[i] = key + sep + fmt.Sprint(v)
		}
		return strings.Join(parts, "; ")
	}
	switch s("kind") {
	case "sshd_config":
		return "sshd drop-in /etc/ssh/sshd_config.d/00-shadow-armor.conf (read first): " + kv("settings", " ") + "; validated with sshd -t, then reload"
	case "sysctl":
		return "/etc/sysctl.d/99-zz-shadow-armor.conf: " + kv("settings", " = ") + "; applied live with sysctl -w"
	case "packages_absent":
		return "remove if installed: " + list("packages")
	case "packages_present":
		return "install (without recommended packages): " + list("packages")
	case "services_disabled":
		return "stop, disable and mask if present: " + list("units")
	case "services_enabled":
		return "enable and start the first available of: " + list("units")
	case "file_mode":
		o := ""
		if s("owner") != "" {
			o = ", owner " + s("owner")
		}
		return "remove permission bits beyond " + s("max") + o + ": " + list("paths")
	case "kv_file":
		return s("path") + ": " + kv("settings", " ")
	case "systemd_dropin":
		return "/etc/" + s("config") + ".d/60-shadow-armor.conf [" + s("section") + "]: " + kv("settings", "=")
	case "modprobe_disable":
		return "/etc/modprobe.d/60-shadow-armor.conf: install <m> /bin/false + blacklist, unload now: " + list("modules")
	case "audit_rules":
		if b, _ := a["immutable"].(bool); b {
			return "/etc/audit/rules.d/99-zz-shadow-armor-finalize.rules: -e 2 (locks audit rules until reboot)"
		}
		return "/etc/audit/rules.d/60-shadow-armor.rules: " + list("rules") + "; augenrules --load"
	case "sudoers_defaults":
		return "/etc/sudoers.d/zz-shadow-armor (visudo-validated): Defaults " + list("defaults")
	case "file_content":
		return "write " + s("path") + " (mode " + s("mode") + ")"
	case "line_in_file":
		return s("path") + ": ensure line '" + s("line") + "'"
	case "grub_cmdline":
		return "kernel command line (grubby or /etc/default/grub + update-grub): " + kv("params", "=") + " (next boot)"
	case "mount_options":
		return "mount " + s("mountpoint") + " with " + list("add") + " (fstab or systemd mount unit, remount live)"
	case "firewall":
		return "ufw/firewalld default-deny inbound; every port listening now, the sshd ports and tcp " + list("allow_tcp") + " stay open"
	case "pam_feature":
		return "PAM " + s("feature") + " (authselect on RHEL-family, pam-auth-update profile on Debian/Ubuntu)"
	case "group_present":
		return "create group " + s("group")
	case "group_members_empty":
		return "remove every member of group " + s("group")
	case "command":
		return "run: " + list("commands")
	case "account_inactive":
		return fmt.Sprintf("useradd -D -f %v and chage --inactive %v for interactive accounts (root excepted; never disables an account at once)", a["days"], a["days"])
	case "password_aging":
		return "login.defs password aging and chage for interactive accounts (no maximum age for root; never expires a password at once): " + strings.Join(nonEmpty(
			pair("max", a["max_days"]), pair("min", a["min_days"]), pair("warn", a["warn_days"])), ", ")
	case "lock_empty_passwords":
		return "lock (passwd -l) every account with an empty password"
	case "expire_weak_hashes":
		return "force a password change (chage -d 0) for accounts with a weak hash"
	case "system_accounts_nologin":
		return "set the shell of system accounts to nologin (accounts with a crontab or authorized_keys left for review)"
	case "home_permissions":
		return "remove group-write and other permissions from interactive home directories"
	case "dotfile_permissions":
		return "remove group/other write from dot files, delete .rhosts/.shosts"
	case "user_secret_permissions":
		return "~/.ssh to 0700, private keys and credential files to owner-only"
	case "private_key_permissions":
		return "remove 'other' access to private key directories and PEM private keys under /etc"
	case "mfa_secret_permissions":
		return "OTP seeds and FIDO key maps to owner-only"
	case "strip_world_writable":
		return "chmod o-w on world-writable files of local filesystems (container and VM storage skipped)"
	case "sticky_world_writable_dirs":
		return "chmod +t on world-writable directories (container and VM storage skipped)"
	case "cron_allow":
		return "create /etc/cron.allow (and /etc/at.allow when at is installed): root + every user that has a crontab now"
	case "aide_init":
		return "initialise the AIDE database (can take minutes)"
	case "automatic_updates":
		return "unattended-upgrades (Debian/Ubuntu) or dnf-automatic security updates (RHEL-family)"
	case "security_updates":
		return "apply pending security updates with the package manager"
	}
	b, _ := json.Marshal(a)
	return string(b)
}

func pair(k string, v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%s %v days", k, v)
}

func nonEmpty(in ...string) []string {
	var out []string
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
