package cli

import (
	"encoding/json"
	"fmt"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/harden"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/ui"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	shadowarmor "github.com/Shadow-Security-official/Shadow-Armor"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/catalog"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/target"
)

func (a *app) explain(args []string) error {
	f := newFlags("explain", "Show what a control checks, why it matters, its mappings and its fix.", "<control-id> [flags]")
	var asJSON, fr bool
	f.BoolVar(&asJSON, "json", false, "print the catalog entry as JSON")
	f.BoolVar(&fr, "fr", false, "show pillar titles in French")
	pos, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("give exactly one control id, e.g. sdw-armor explain SA-06.01")
	}
	c, ok := a.cat.Control(pos[0])
	if !ok {
		return usagef("unknown control %q (see `sdw-armor list`)", pos[0])
	}
	if asJSON {
		enc := json.NewEncoder(a.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(c)
	}
	l := a.look()
	pl, _ := a.cat.Pillar(c.Pillar)
	ptitle := pl.Title
	if fr {
		ptitle = pl.TitleFR
	}
	w := a.stdout
	sc := ui.SeverityColor(c.Severity)
	wrapW := l.w - 8
	para := func(text string) []string {
		var out []string
		for _, line := range ui.Wrap(text, wrapW) {
			out = append(out, "  "+l.ink(line))
		}
		return out
	}
	var body []string
	add := func(label string, lines ...string) {
		body = append(body, "", l.bold(ui.Violet, label))
		body = append(body, lines...)
	}
	body = append(body, l.bold(ui.White, c.Title))
	body = append(body, l.muted(fmt.Sprintf("pillar %02d · %s · level %d · %s", c.Pillar, ptitle, c.Level, scopeText(c.Scope))))
	add("WHY", para(c.Rationale)...)
	add("EFFECTIVE PROBE", para(c.Check)...)
	add("WHAT A PASS PROVES", para(provesText(*c))...)
	var maps [][2]string
	for _, k := range catalog.StandardKeys {
		refs := c.Map.Refs(k)
		if len(refs) == 0 {
			continue
		}
		var tags []string
		for _, r := range refs {
			tags = append(tags, l.paint(ui.Cyan, r))
		}
		maps = append(maps, [2]string{a.cat.StandardLabel(k), strings.Join(tags, l.faint(" · "))})
	}
	var mlines []string
	for _, r := range l.kv(maps) {
		mlines = append(mlines, "  "+ui.Trunc(r, wrapW))
	}
	add("MAPPINGS", mlines...)
	r := c.Remediation
	mode := l.muted("manual")
	if r.Auto {
		mode = l.paint(ui.Cyan, "↯ automatic") + l.muted(" · sdw-armor harden --rules "+c.ID)
	}
	rem := []string{"  " + mode}
	rem = append(rem, para(r.Summary)...)
	if r.Risk != "" {
		for _, line := range ui.Wrap("risk: "+r.Risk, wrapW) {
			rem = append(rem, "  "+l.paint(ui.Amber, line))
		}
	}
	if r.Reboot {
		rem = append(rem, "  "+l.paint(ui.Sky, "◐ takes full effect after a reboot"))
	}
	if len(r.Guards) > 0 {
		rem = append(rem, "  "+l.muted("safety guards: ")+l.steel(strings.Join(r.Guards, ", ")))
	}
	if r.Manual != "" {
		for _, line := range ui.Wrap(r.Manual, wrapW) {
			rem = append(rem, "  "+l.steel(line))
		}
	}
	for _, act := range r.Actions {
		rem = append(rem, "  "+l.cyan("→ ")+l.steel(ui.Trunc(harden.Describe(act), wrapW-2)))
	}
	add("REMEDIATION", rem...)
	body = append(body, "")
	fmt.Fprintln(w)
	title := l.bold(sc, c.ID) + " " + l.sev(c.Severity)
	for _, line := range l.box(title, l.muted("sdw-armor explain "+c.ID+" --json · docs/CONTROLS.md"), body, ui.Mix(sc, ui.Faint, 0.6)) {
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w)
	return nil
}

// provesText explains what a PASS of the control establishes.
func provesText(c catalog.Control) string {
	has := func(k string) bool {
		for _, x := range c.Evidence {
			if x == k {
				return true
			}
		}
		return false
	}
	durable := c.DeclaredType() != "runtime" && c.DeclaredType() != "transient" && has(c.DeclaredType())
	var why string
	switch {
	case has("runtime") && has("persistent"):
		why = "the live state now and the configuration the next boot applies: a PASS survives a reboot by construction; if they disagree the verdict says so (runtime-only or pending)."
	case has("persistent"):
		why = "the configuration the next boot applies."
	case has("transient"):
		why = "live state that a reboot can only clear: the reboot column does not apply."
	case durable:
		why = "state kept on disk and read as the system uses it: it survives a reboot."
	case has("runtime"):
		why = "live state only: nothing on disk tells what the next boot does, so a PASS is runtime-only until a scan after a real reboot proves it (--reboot-baseline, harden --reboot)."
	}
	return "Evidence: " + c.Proves() + ". Reads " + why
}

func scopeText(s string) string {
	if s == "host" {
		return "host only (not applicable inside containers)"
	}
	return "hosts and containers"
}

func (a *app) list(args []string) error {
	f := newFlags("list", "List controls, pillars, standards or inputs.", "[flags]")
	var level int
	var std string
	var pillars multi
	pillars.split = true
	var showPillars, showInputs, showStandards, asJSON, auto, fr, md bool
	f.IntVar(&level, "level", 2, "maximum level (1 or 2)")
	f.StringVar(&std, "standard", "all", "only controls mapped to this standard")
	f.Var(&pillars, "pillar", "only these pillars")
	f.BoolVar(&showPillars, "pillars", false, "list the 12 pillars")
	f.BoolVar(&showInputs, "inputs", false, "list tunable inputs and their defaults")
	f.BoolVar(&showStandards, "standards", false, "list supported standards")
	f.BoolVar(&auto, "auto", false, "only controls with an automatic remediation")
	f.BoolVar(&asJSON, "json", false, "JSON output")
	f.BoolVar(&fr, "fr", false, "French pillar titles")
	f.BoolVar(&md, "markdown", false, "Markdown matrix of every control and its mappings (docs/CONTROLS.md)")
	if _, err := f.parse(args); err != nil {
		return err
	}
	if md {
		return a.controlsMarkdown()
	}
	w := a.stdout
	l := a.look()
	switch {
	case showPillars:
		if asJSON {
			return json.NewEncoder(w).Encode(a.cat.Pillars)
		}
		for _, pl := range a.cat.Pillars {
			n := 0
			for _, c := range a.cat.Controls {
				if c.Pillar == pl.ID {
					n++
				}
			}
			fmt.Fprintln(w, "  "+l.bold(ui.Violet, fmt.Sprintf("%02d", pl.ID))+"  "+ui.Pad(l.cyan(pl.Key), 16)+l.bold(ui.Ink, pl.Title)+l.muted(fmt.Sprintf("  %d controls", n)))
			fmt.Fprintln(w, "      "+ui.Pad("", 16)+l.muted(pl.TitleFR))
		}
		return nil
	case showInputs:
		if asJSON {
			return json.NewEncoder(w).Encode(a.cat.Inputs)
		}
		for _, in := range a.cat.Inputs {
			v := string(in.Value)
			if len(v) > 70 {
				v = v[:67] + "..."
			}
			fmt.Fprintln(w, "  "+l.bold(ui.Cyan, in.Name)+l.muted(" = ")+l.ink(v))
			fmt.Fprintln(w, "    "+l.steel(in.Desc))
		}
		return nil
	case showStandards:
		keys := make([]string, 0, len(a.cat.Standards))
		for k := range a.cat.Standards {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s := a.cat.Standards[k]
			fmt.Fprintln(w, "  "+ui.Pad(l.bold(ui.Cyan, k), 9)+l.ink(s.Name))
			fmt.Fprintln(w, "           "+l.steel(s.Detail))
		}
		return nil
	}
	if !catalog.ValidStandard(std) {
		return usagef("unknown --standard %q", std)
	}
	pids, err := a.parsePillars(pillars.vals)
	if err != nil {
		return err
	}
	sel := a.cat.Select(catalog.Filter{Level: level, Standard: std, Pillars: pids})
	if auto {
		var k []catalog.Control
		for _, c := range sel {
			if c.Remediation.Auto {
				k = append(k, c)
			}
		}
		sel = k
	}
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(sel)
	}
	cur := 0
	for _, c := range sel {
		if c.Pillar != cur {
			cur = c.Pillar
			pl, _ := a.cat.Pillar(cur)
			t := pl.Title
			if fr {
				t = pl.TitleFR
			}
			fmt.Fprintln(w)
			fmt.Fprintln(w, l.section(fmt.Sprintf("%02d %s", pl.ID, strings.ToUpper(t)), ""))
		}
		fix := l.muted("manual")
		if c.Remediation.Auto {
			fix = l.cyan("↯ auto")
		}
		refs := ""
		if std != "all" {
			refs = "  " + l.muted(strings.Join(c.Map.Refs(std), " · "))
		}
		fmt.Fprintln(w, "   "+ui.Pad(l.bold(ui.SeverityColor(c.Severity), c.ID), 10)+l.muted(fmt.Sprintf("L%d ", c.Level))+ui.Pad(l.paint(ui.SeverityColor(c.Severity), c.Severity), 9)+ui.Pad(fix, 8)+l.ink(c.Title)+refs)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  "+l.muted(fmt.Sprintf("%d controls", len(sel))))
	return nil
}

func (a *app) export(args []string) error {
	f := newFlags("export", "Write the embedded InSpec profile or Chef cookbook to a directory, for plain cinc-auditor / Chef use or review.", "profile|cookbook <dir>")
	pos, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return usagef("usage: sdw-armor export profile|cookbook <dir>")
	}
	var root string
	switch pos[0] {
	case "profile":
		root = "profile"
	case "cookbook":
		root = "cookbook/shadow_armor"
	default:
		return usagef("export what? profile or cookbook")
	}
	dest := pos[1]
	if entries, err := os.ReadDir(dest); err == nil && len(entries) > 0 {
		return usagef("%s exists and is not empty", dest)
	}
	var fsys fs.FS = shadowarmor.Profile
	if root != "profile" {
		fsys = shadowarmor.Cookbook
	}
	if err := target.ExtractTo(fsys, root, dest); err != nil {
		return err
	}
	// Exported trees are meant to be read and shared.
	_ = filepath.WalkDir(dest, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return os.Chmod(p, 0o755) //nolint:gosec // exported profiles are public, readable trees
		}
		return os.Chmod(p, 0o644) //nolint:gosec // idem
	})
	fmt.Fprintf(a.stdout, "exported %s to %s\n", pos[0], dest)
	if pos[0] == "profile" {
		fmt.Fprintf(a.stdout, "run it without sdw-armor: cinc-auditor exec %s -t ssh://user@host --sudo\n", dest)
	}
	return nil
}

// controlsMarkdown renders docs/CONTROLS.md from the catalog.
func (a *app) controlsMarkdown() error {
	w := a.stdout
	c := a.cat
	fmt.Fprintf(w, "<!-- Generated by `sdw-armor list --markdown` from profile/files/catalog.json. Do not edit by hand. -->\n\n")
	fmt.Fprintf(w, "# Shadow-Armor controls\n\n%d controls in 12 pillars. Level 1 is the baseline (`--level 1`, default), level 2 adds hardened controls.\n", len(c.Controls))
	fmt.Fprintf(w, "*Fix*: `auto` = converged by `sdw-armor harden`, `manual` = documented steps (`sdw-armor explain <id>`).\n")
	fmt.Fprintf(w, "*Scope*: `host` controls audit the kernel, boot chain or host daemons and are not applicable inside containers.\n")
	fmt.Fprintf(w, "*Proves*: the evidence a PASS rests on. `live + boot` checks the running system and the configuration the next boot applies; `resolved config`, `files` and `inventory` are durable state read as the system uses it; `live` alone is runtime-only until a scan after a reboot proves it (see [SCORING.md](SCORING.md)).\n\n")
	fmt.Fprintf(w, "Standards: ")
	var std []string
	for _, k := range catalog.StandardKeys {
		std = append(std, fmt.Sprintf("**%s** = %s", strings.ToUpper(k), c.StandardLabel(k)))
	}
	fmt.Fprintf(w, "%s. CIS lists CIS Controls v8 safeguards; the CIS Benchmark recommendation title, when one exists, is shown by `sdw-armor explain`.\n\n", strings.Join(std, " · "))
	fmt.Fprintf(w, "| # | Pillar | Controls |\n|---|---|---|\n")
	for _, p := range c.Pillars {
		n := 0
		for _, ctl := range c.Controls {
			if ctl.Pillar == p.ID {
				n++
			}
		}
		fmt.Fprintf(w, "| %02d | [%s](#%02d-%s) · *%s* | %d |\n", p.ID, p.Title, p.ID, p.Key, p.TitleFR, n)
	}
	for _, p := range c.Pillars {
		fmt.Fprintf(w, "\n## %02d %s\n\n<a id=\"%02d-%s\"></a>*%s* — %s\n\n", p.ID, p.Title, p.ID, p.Key, p.TitleFR, p.Summary)
		fmt.Fprintf(w, "| ID | Control | Sev. | L | Scope | Fix | Proves | CIS v8 | ANSSI | NIST 800-53 | NIST 800-171 | PCI DSS | STIG SRG |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
		for _, ctl := range c.Controls {
			if ctl.Pillar != p.ID {
				continue
			}
			fix := "manual"
			if ctl.Remediation.Auto {
				fix = "auto"
			}
			cell := func(v []string) string { return strings.Join(v, ", ") }
			stig := make([]string, len(ctl.Map.STIG))
			for i, s := range ctl.Map.STIG {
				stig[i] = strings.TrimPrefix(s, "SRG-OS-")
			}
			fmt.Fprintf(w, "| %s | %s | %s | %d | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", ctl.ID, ctl.Title, ctl.Severity, ctl.Level, ctl.Scope, fix, ctl.Proves(),
				cell(ctl.Map.CIS), cell(ctl.Map.ANSSI), cell(ctl.Map.NIST), cell(ctl.Map.NIST171), cell(ctl.Map.PCI), cell(stig))
		}
	}
	fmt.Fprintf(w, "\nSTIG column: `SRG-OS-` prefix omitted.\n")
	return nil
}
