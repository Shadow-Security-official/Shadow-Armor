package selfupdate

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.3.0", "0.3.0", 0},
		{"v0.3.1", "0.3.0", 1},
		{"0.2.0", "0.10.0", -1},
		{"1.0.0", "0.99.99", 1},
		{"0.3.0-rc1", "0.3.0", -1},
		{"0.3.0-rc.2", "0.3.0-rc.10", -1},
		{"0.3.0+build5", "0.3.0", 0},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestIsRelease(t *testing.T) {
	for v, want := range map[string]bool{"0.3.0": true, "v1.2.3": true, "0.3.0-dev": false, "v0.3.0-4-g1a2b3c4-dirty": false, "1a2b3c4": false} {
		if IsRelease(v) != want {
			t.Errorf("IsRelease(%q) != %v", v, want)
		}
	}
}

func TestAssetNames(t *testing.T) {
	if got := BinaryName("linux", "arm64"); got != "sdw-armor-linux-arm64" {
		t.Error(got)
	}
	if got := PackageName("deb", "0.3.1", "amd64"); got != "sdw-armor_0.3.1-1_amd64.deb" {
		t.Error(got)
	}
	if got := PackageName("rpm", "0.3.1", "arm64"); got != "sdw-armor-0.3.1-1.aarch64.rpm" {
		t.Error(got)
	}
}

func TestParseSums(t *testing.T) {
	sums := ParseSums([]byte("0000000000000000000000000000000000000000000000000000000000000001  sdw-armor-linux-amd64\n" +
		"00000000000000000000000000000000000000000000000000000000000000AA *sdw-armor.cdx.json\nnot a line\n"))
	if sums["sdw-armor-linux-amd64"] == "" || sums["sdw-armor.cdx.json"] != "00000000000000000000000000000000000000000000000000000000000000aa" || len(sums) != 2 {
		t.Errorf("%v", sums)
	}
}

func TestLatestAndDownload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases/latest":
			_, _ = w.Write([]byte(`{"tag_name":"v0.4.0","html_url":"https://example.invalid/r","body":"### Added\n\n- One thing.\n- Another.\n","assets":[{"name":"f","browser_download_url":"` + "http://" + r.Host + `/f","size":5}]}`))
		case "/releases/tags/v0.1.0":
			http.NotFound(w, r)
		case "/f":
			_, _ = w.Write([]byte("hello"))
		}
	}))
	defer srv.Close()
	c := &Client{API: srv.URL, UserAgent: "test"}
	rel, err := c.Latest(context.Background())
	if err != nil || rel.Version() != "0.4.0" || len(rel.Notes(5)) != 2 {
		t.Fatalf("%+v %v", rel, err)
	}
	if _, err := c.ByTag(context.Background(), "0.1.0"); !errors.Is(err, ErrNoRelease) || !strings.Contains(err.Error(), "v0.1.0") {
		t.Errorf("missing tag: %v", err)
	}
	a, _ := rel.Asset("f")
	dest := filepath.Join(t.TempDir(), "f")
	sum, err := c.Download(context.Background(), a.URL, dest, nil)
	if err != nil || sum != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("%s %v", sum, err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "hello" {
		t.Error(string(b))
	}
}
