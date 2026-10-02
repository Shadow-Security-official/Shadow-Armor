package cinc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestMap(t *testing.T) {
	cases := []struct {
		id, like, ver, arch string
		want                string
		pkg                 string
	}{
		{"ubuntu", "debian", "24.04", "x86_64", "ubuntu/24.04/x86_64", "deb"},
		{"debian", "", "12", "aarch64", "debian/12/aarch64", "deb"},
		{"debian", "", "13", "arm64", "debian/13/aarch64", "deb"},
		{"rocky", "rhel centos fedora", "9.4", "x86_64", "el/9/x86_64", "rpm"},
		{"almalinux", "rhel centos fedora", "8.10", "x86_64", "el/8/x86_64", "rpm"},
		{"rhel", "fedora", "10.0", "x86_64", "el/10/x86_64", "rpm"},
		{"ol", "fedora", "9.3", "x86_64", "el/9/x86_64", "rpm"},
		{"amzn", "centos rhel fedora", "2023", "aarch64", "amazon/2023/aarch64", "rpm"},
		{"opensuse-leap", "suse opensuse", "15.6", "x86_64", "sles/15/x86_64", "rpm"},
	}
	for _, c := range cases {
		p, err := Map(c.id, c.like, c.ver, c.arch)
		if err != nil {
			t.Fatalf("%s %s: %v", c.id, c.ver, err)
		}
		if p.String() != c.want || p.Pkg != c.pkg {
			t.Errorf("%s %s %s: got %s (%s), want %s (%s)", c.id, c.ver, c.arch, p, p.Pkg, c.want, c.pkg)
		}
	}
	for _, bad := range [][4]string{
		{"fedora", "", "40", "x86_64"},
		{"arch", "", "", "x86_64"},
		{"debian", "", "", "x86_64"},
		{"ubuntu", "debian", "24.04", "riscv64"},
	} {
		if _, err := Map(bad[0], bad[1], bad[2], bad[3]); err == nil {
			t.Errorf("%v: expected an error", bad)
		}
	}
}

func TestParseMetadata(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	text := "sha1\tdeadbeef\nsha256\t" + strings.ToUpper(sum) + "\nurl\thttps://downloads.cinc.sh/files/stable/cinc-auditor/7.2.1/ubuntu/24.04/cinc-auditor_7.2.1-1_amd64.deb\nversion\t7.2.1\n"
	m, err := ParseMetadata([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if m.SHA256 != sum || m.Version != "7.2.1" || !strings.HasSuffix(m.URL, "_amd64.deb") {
		t.Fatalf("unexpected %+v", m)
	}
	j, err := ParseMetadata([]byte(`{"sha256":"` + sum + `","url":"https://x/y.rpm","version":"18.8.11"}`))
	if err != nil || j.URL != "https://x/y.rpm" {
		t.Fatalf("json: %+v %v", j, err)
	}
	if _, err := ParseMetadata([]byte("url\thttps://x/y.deb\nsha256\tnothex\n")); err == nil {
		t.Fatal("an invalid checksum must be refused")
	}
}

func TestProjectOf(t *testing.T) {
	for f, want := range map[string]string{
		"/tmp/cinc-auditor_7.2.1-1_amd64.deb": Auditor,
		"cinc-auditor-7.2.1-1.el9.x86_64.rpm": Auditor,
		"cinc_18.8.11-1_amd64.deb":            Client,
		"cinc-18.8.11-1.el9.x86_64.rpm":       Client,
		"cinc-workstation_25.0.0-1_amd64.deb": "",
		"chef_18.8.11-1_amd64.deb":            "",
	} {
		if got := ProjectOf(f); got != want {
			t.Errorf("%s: got %q want %q", f, got, want)
		}
	}
}

func TestMetadataURLAndRecipe(t *testing.T) {
	p := Platform{P: "el", PV: "9", M: "x86_64", Pkg: "rpm"}
	u := MetadataURL(DefaultBase, Auditor, p, "")
	if u != "https://omnitruck.cinc.sh/stable/cinc-auditor/metadata?m=x86_64&p=el&pv=9" {
		t.Fatalf("url %s", u)
	}
	r := Recipe(DefaultBase, Client, p, "18")
	for _, want := range []string{"v=18", "sha256sum --check", "sudo rpm -U", "cinc-client version"} {
		if !strings.Contains(r, want) {
			t.Errorf("recipe lacks %q:\n%s", want, r)
		}
	}
	if regexp.MustCompile(`\|\s*(sudo\s+)?(ba)?sh\b`).MatchString(r) || strings.Contains(r, "install.sh") {
		t.Errorf("the recipe must never pipe a script into a shell:\n%s", r)
	}
}

func TestResolveAndFetch(t *testing.T) {
	payload := []byte("pretend this is a package")
	h := sha256.Sum256(payload)
	good := hex.EncodeToString(h[:])
	sum := good
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/stable/cinc-auditor/metadata"):
			if r.URL.Query().Get("p") != "debian" || r.URL.Query().Get("pv") != "12" {
				http.NotFound(w, r)
				return
			}
			fmt.Fprintf(w, "sha256\t%s\nurl\t%s/files/cinc-auditor_7.2.1-1_amd64.deb\nversion\t7.2.1\n", sum, srv.URL)
		case r.URL.Path == "/files/cinc-auditor_7.2.1-1_amd64.deb":
			w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	p := Platform{P: "debian", PV: "12", M: "x86_64", Pkg: "deb"}
	m, err := Resolve(ctx, srv.Client(), srv.URL, Auditor, p, "")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f, err := Fetch(ctx, srv.Client(), m, dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(f) != "cinc-auditor_7.2.1-1_amd64.deb" {
		t.Fatalf("file %s", f)
	}
	if _, err := Resolve(ctx, srv.Client(), srv.URL, Auditor, Platform{P: "el", PV: "9", M: "x86_64"}, ""); err == nil {
		t.Fatal("a missing platform must be an error")
	}

	// Tampered package: refused and deleted.
	sum = strings.Repeat("0", 64)
	m, err = Resolve(ctx, srv.Client(), srv.URL, Auditor, p, "")
	if err != nil {
		t.Fatal(err)
	}
	dir2 := t.TempDir()
	if _, err := Fetch(ctx, srv.Client(), m, dir2); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected a checksum mismatch, got %v", err)
	}
	if ents, _ := os.ReadDir(dir2); len(ents) != 0 {
		t.Fatal("a package that failed verification must not be left on disk")
	}

	// HTTPS base with a plain-HTTP package URL: refused.
	if _, err := Resolve(ctx, srv.Client(), "https://127.0.0.1:1", Auditor, p, ""); err == nil {
		t.Fatal("unreachable mirror must fail")
	}
}

func TestRefusesPlainHTTPPackageFromHTTPSBase(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "sha256\t%s\nurl\thttp://example.invalid/cinc-auditor.deb\n", strings.Repeat("a", 64))
	}))
	defer srv.Close()
	_, err := Resolve(context.Background(), srv.Client(), srv.URL, Auditor, Platform{P: "ubuntu", PV: "24.04", M: "x86_64"}, "")
	if err == nil || !strings.Contains(err.Error(), "non-HTTPS") {
		t.Fatalf("expected a refusal, got %v", err)
	}
}
