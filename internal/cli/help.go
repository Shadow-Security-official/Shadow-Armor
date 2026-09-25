package cli

import (
	"fmt"
	"io"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/ui"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/version"
)

var commands = [][2]string{
	{"scan", "Audit a target and grade it A to E: text, html, json, sarif, junit, markdown"},
	{"harden", "Plan the fixes, opt in per rule, converge with a native Chef run, prove it"},
	{"explain", "What a control checks, why, what a PASS proves, its mappings and its fix"},
	{"list", "List controls by pillar, level or standard"},
	{"report", "Re-render a saved JSON report: another format, another standard lens"},
	{"diff", "Compare two reports: fixed, regressed, drifted, lost at a reboot"},
	{"doctor", "Check the prerequisites here and on a target"},
	{"install-cinc", "Install CINC Auditor/Client from a SHA-256 verified package, never a script"},
	{"export", "Write the embedded InSpec profile or Chef cookbook to a directory"},
	{"update", "Check whether a newer sdw-armor release exists (installs nothing)"},
	{"upgrade", "Download, verify and install the latest sdw-armor release"},
	{"version", "Print version information"},
}

// help prints the home screen: the logo, what Shadow-Armor does, the
// targets and the commands.
func (a *app) help(w io.Writer) {
	t := ui.Detect(w, a.color)
	p := t.Profile
	muted := func(s string) string { return p.Paint(ui.Muted, s) }
	ink := func(s string) string { return p.Paint(ui.Ink, s) }
	head := func(s string) string { c := ui.Ink; return "  " + p.Bold(&c, s) }
	v := version.Version
	if v != "" && v[0] != 'v' {
		v = "v" + v
	}
	fmt.Fprintln(w)
	for _, l := range p.Banner(t.Width, v, fmt.Sprintf("%d controls · 12 pillars", len(a.cat.Controls))) {
		fmt.Fprintln(w, l)
	}
	fmt.Fprintln(w)
	for _, l := range []string{
		"Audits the configuration services actually run (sshd -T, sysctl, systemctl, auditctl), not",
		"just the files on disk. Every control carries its CIS, ANSSI BP-028, NIST 800-53/800-171,",
		"PCI DSS and DISA STIG mappings, says what its PASS proves (now, on disk, after a reboot),",
		"is graded A to E with a published formula, and can be hardened as code.",
	} {
		fmt.Fprintln(w, "  "+p.Paint(ui.Steel, l))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, head("USAGE"))
	fmt.Fprintln(w, "    "+p.Paint(ui.Cyan, "sdw-armor")+" "+ink("<command>")+" "+muted("[target] [flags]"))
	fmt.Fprintln(w)
	fmt.Fprintln(w, head("TARGETS"))
	for _, r := range [][2]string{
		{"local", "this host (default)"},
		{"ssh://[user@]host[:port]", "over SSH, with your own ~/.ssh/config"},
		{"docker://<container>", "a running container"},
	} {
		fmt.Fprintln(w, "    "+ui.Pad(ink(r[0]), 28)+muted(r[1]))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, head("COMMANDS"))
	for _, c := range commands {
		fmt.Fprintln(w, "    "+p.Paint(ui.Violet, "❯ ")+ui.Pad(p.Paint(ui.Cyan, c[0]), 14)+p.Paint(ui.Steel, c[1]))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  "+muted("Run ")+ink("sdw-armor <command> -h")+muted(" for its flags · docs: https://github.com/Shadow-Security-official/Shadow-Armor"))
	fmt.Fprintln(w)
}
