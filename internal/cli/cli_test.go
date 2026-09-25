package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Main(args, &out, &errb)
	return out.String(), errb.String(), code
}

// docs/CONTROLS.md is generated from the catalog: it must not drift.
func TestControlsDocUpToDate(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	want, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "docs", "CONTROLS.md"))
	if err != nil {
		t.Fatal(err)
	}
	got, _, code := run(t, "list", "--markdown")
	if code != 0 || got != string(want) {
		t.Fatal("docs/CONTROLS.md is out of date: go run ./cmd/sdw-armor list --markdown > docs/CONTROLS.md")
	}
}

func TestCommands(t *testing.T) {
	cases := []struct {
		args []string
		code int
		want string
	}{
		{[]string{}, 0, "COMMANDS"},
		{[]string{"version"}, 0, "controls  162"},
		{[]string{"explain", "SA-06.01"}, 0, "PermitRootLogin"},
		{[]string{"explain", "nope"}, 2, ""},
		{[]string{"list", "--pillar", "ssh"}, 0, "SA-06.20"},
		{[]string{"list", "--pillars"}, 0, "crypto-mfa"},
		{[]string{"list", "--inputs"}, 0, "sdw_password_min_length"},
		{[]string{"list", "--standard", "stig", "--auto"}, 0, "controls"},
		{[]string{"scan", "--level", "3"}, 2, ""},
		{[]string{"scan", "--standard", "iso"}, 2, ""},
		{[]string{"scan", "ftp://x"}, 2, ""},
		{[]string{"scan", "--input", "sdw_nope=1"}, 2, ""},
		{[]string{"scan", "--bootstrap-cinc"}, 2, ""},
		{[]string{"scan", "-o", "pdf:x.pdf"}, 2, ""},
		{[]string{"bogus"}, 2, ""},
	}
	for _, c := range cases {
		out, errOut, code := run(t, append(c.args, "--no-color")...)
		if code != c.code {
			t.Errorf("%v: exit %d, want %d (stderr %q)", c.args, code, c.code, errOut)
		}
		if c.want != "" && !strings.Contains(out, c.want) {
			t.Errorf("%v: output lacks %q", c.args, c.want)
		}
	}
}

func TestExportProfile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "p")
	if _, errOut, code := run(t, "export", "profile", dir); code != 0 {
		t.Fatalf("export failed: %s", errOut)
	}
	for _, f := range []string{"inspec.yml", "files/catalog.json", "controls/06-ssh.rb", "libraries/00_sdw_core.rb"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}
	if _, _, code := run(t, "export", "profile", dir); code != 2 {
		t.Error("exporting into a non-empty directory must be refused")
	}
}
