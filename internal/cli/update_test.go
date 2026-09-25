package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/selfupdate"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/version"
)

// fakeRelease serves a release v9.9.9 whose "binary" is a shell script.
func fakeRelease(t *testing.T, tamper bool) (bin []byte) {
	t.Helper()
	bin = []byte("#!/bin/sh\necho 'sdw-armor 9.9.9'\n")
	sum := sha256.Sum256(bin)
	sums := hex.EncodeToString(sum[:])
	if tamper {
		sums = strings.Repeat("0", 64)
	}
	asset := selfupdate.BinaryName(runtime.GOOS, runtime.GOARCH)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		switch r.URL.Path {
		case "/releases/latest":
			fmt.Fprintf(w, `{"tag_name":"v9.9.9","html_url":"%s/r","published_at":"2026-09-26T10:00:00Z","body":"- Faster.\n","assets":[
			  {"name":%q,"browser_download_url":"%s/bin","size":%d},
			  {"name":"SHA256SUMS","browser_download_url":"%s/sums","size":1}]}`, base, asset, base, len(bin), base)
		case "/bin":
			_, _ = w.Write(bin)
		case "/sums":
			fmt.Fprintf(w, "%s  %s\n", sums, asset)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("SDW_ARMOR_RELEASES", srv.URL)
	return bin
}

// installed puts a fake current binary in a temp dir and makes it "the
// running executable" for the duration of the test.
func installed(t *testing.T, ver string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("no shell")
	}
	exe := filepath.Join(t.TempDir(), "sdw-armor")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\necho 'sdw-armor "+ver+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	oldExe, oldVerify, oldVersion := executable, verifySignature, version.Version
	executable = func() (string, error) { return exe, nil }
	verifySignature = func(context.Context, string, string, string) (selfupdate.Verification, error) {
		return selfupdate.Verification{}, nil
	}
	version.Version = ver
	t.Cleanup(func() { executable, verifySignature, version.Version = oldExe, oldVerify, oldVersion })
	return exe
}

func TestUpdateReportsNewerRelease(t *testing.T) {
	fakeRelease(t, false)
	installed(t, "0.3.0")
	out, _, code := run(t, "update", "--no-color")
	if code != ExitPolicy || !strings.Contains(out, "9.9.9 is available") || !strings.Contains(out, "Faster.") {
		t.Fatalf("code %d\n%s", code, out)
	}
}

func TestUpgradeReplacesTheBinary(t *testing.T) {
	bin := fakeRelease(t, false)
	exe := installed(t, "0.3.0")
	out, errOut, code := run(t, "upgrade", "--yes", "--no-color")
	if code != ExitOK || !strings.Contains(out, "sdw-armor 0.3.0 → 9.9.9") {
		t.Fatalf("code %d\n%s\n%s", code, out, errOut)
	}
	if got, _ := os.ReadFile(exe); string(got) != string(bin) {
		t.Fatalf("binary not replaced:\n%s", got)
	}
	if st, _ := os.Stat(exe); st.Mode().Perm() != 0o755 {
		t.Errorf("mode %v", st.Mode())
	}
}

func TestUpgradeRefusesABadChecksum(t *testing.T) {
	fakeRelease(t, true)
	exe := installed(t, "0.3.0")
	before, _ := os.ReadFile(exe)
	_, errOut, code := run(t, "upgrade", "--yes", "--no-color")
	if code == ExitOK || !strings.Contains(errOut, "SHA-256 mismatch") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if after, _ := os.ReadFile(exe); string(after) != string(before) {
		t.Fatal("the binary changed despite the checksum mismatch")
	}
}

func TestUpgradeStrictNeedsASignatureCheck(t *testing.T) {
	fakeRelease(t, false)
	installed(t, "0.3.0")
	_, errOut, code := run(t, "upgrade", "--yes", "--strict", "--no-color")
	if code == ExitOK || !strings.Contains(errOut, "--strict") {
		t.Fatalf("code %d: %s", code, errOut)
	}
}

func TestUpgradeNothingToDo(t *testing.T) {
	fakeRelease(t, false)
	installed(t, "9.9.9")
	out, _, code := run(t, "upgrade", "--yes", "--no-color")
	if code != ExitOK || !strings.Contains(out, "nothing to do") {
		t.Fatalf("code %d\n%s", code, out)
	}
}
