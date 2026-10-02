package target

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

func TestParse(t *testing.T) {
	ok := map[string]string{
		"":                             "local://",
		"local":                        "local://",
		"ssh://web01":                  "ssh://web01",
		"ssh://admin@web01:2222":       "ssh://admin@web01:2222",
		"ssh://admin@[2001:db8::1]:22": "ssh://admin@[2001:db8::1]:22",
		"docker://my-app_1":            "docker://my-app_1",
	}
	for in, want := range ok {
		tg, err := Parse(in)
		if err != nil {
			t.Errorf("Parse(%q): %v", in, err)
			continue
		}
		if tg.String() != want {
			t.Errorf("Parse(%q).String() = %q, want %q", in, tg.String(), want)
		}
	}
	for _, bad := range []string{"web01", "ssh://", "ssh://u:pw@host", "docker://", "winrm://x", "ssh://h:0", "docker://a b"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) should fail", bad)
		}
	}
}

func TestQuote(t *testing.T) {
	cases := map[string]string{
		"simple":      "simple",
		"":            "''",
		"a b":         "'a b'",
		"it's":        `'it'"'"'s'`,
		"/tmp/x.json": "/tmp/x.json",
		"$(rm -rf /)": "'$(rm -rf /)'",
		"recipe[x]":   "'recipe[x]'",
	}
	for in, want := range cases {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSSHArgs(t *testing.T) {
	tg := &Target{Kind: SSH, User: "u", Host: "h", Port: 2222, Identity: "/k"}
	got := tg.SSHArgs()
	want := []string{"-o", "BatchMode=yes", "-p", "2222", "-i", "/k", "--", "u@h"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v != %v", got, want)
		}
	}
}

func TestTarGz(t *testing.T) {
	fsys := fstest.MapFS{"root/a.txt": {Data: []byte("a")}, "root/d/b.txt": {Data: []byte("b")}}
	var buf bytes.Buffer
	if err := TarGz(&buf, fsys, "root"); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("empty archive")
	}
}

// Has must find a binary that is on PATH (regression: a trailing `exit 1`
// used to turn a successful `command -v` into "not found").
func TestHasFindsBinaryOnPath(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "sdw-fake-engine")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	tg := &Target{Kind: Local}
	got, ok := tg.Has(context.Background(), "sdw-fake-engine")
	if !ok || got != bin {
		t.Fatalf("Has = %q, %v; want %q, true", got, ok, bin)
	}
	if _, ok := tg.Has(context.Background(), "sdw-surely-missing-binary"); ok {
		t.Fatal("Has found a missing binary")
	}
}

func TestParseSSHG(t *testing.T) {
	dir := t.TempDir()
	key := dir + "/.ssh/id_ed25519"
	if err := os.MkdirAll(dir+"/.ssh", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := "user admin\nhostname 10.0.0.7\nport 2222\nidentityfile ~/.ssh/id_rsa\nidentityfile ~/.ssh/id_ed25519\nproxyjump jump@bastion:22\nproxycommand none\n"
	c := parseSSHG(out, dir)
	if c.HostName != "10.0.0.7" || c.User != "admin" || c.Port != 2222 || c.ProxyJump != "jump@bastion:22" || c.ProxyCommand != "" {
		t.Fatalf("%+v", c)
	}
	if len(c.IdentityFile) != 1 || c.IdentityFile[0] != key {
		t.Fatalf("only existing keys, ~ expanded: %v", c.IdentityFile)
	}
}
