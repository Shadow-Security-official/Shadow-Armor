// Package cinc installs CINC Auditor (the scan engine) or CINC Client (the
// harden runtime) on a target, and only when explicitly asked to.
//
// No installer script is ever piped into a shell. The package for the
// target's platform is resolved with the omnitruck metadata endpoint (which
// publishes its URL and SHA-256), downloaded on the machine running
// sdw-armor, checked against that SHA-256, streamed to the target, checked
// again there, and installed with the system package tool (dpkg or rpm).
// The target itself needs no Internet access. A package file you provide
// (--cinc-package) replaces the download for air-gapped sites.
package cinc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/target"
)

// DefaultBase is the official CINC omnitruck service. $SDW_ARMOR_OMNITRUCK
// points sdw-armor at a mirror that serves the same API.
const DefaultBase = "https://omnitruck.cinc.sh"

// Omnitruck project names.
const (
	Auditor = "cinc-auditor"
	Client  = "cinc"
)

// Label names a project for humans.
func Label(project string) string {
	if project == Client {
		return "CINC Client (cinc-client)"
	}
	return "CINC Auditor (cinc-auditor)"
}

// Binary is the command a project installs.
func Binary(project string) string {
	if project == Client {
		return "cinc-client"
	}
	return "cinc-auditor"
}

// Platform is a target platform in omnitruck's terms.
type Platform struct {
	Pretty string `json:"pretty,omitempty"` // PRETTY_NAME, for messages
	P      string `json:"p"`                // omnitruck platform (ubuntu, debian, el, amazon, sles)
	PV     string `json:"pv"`               // omnitruck platform version
	M      string `json:"m"`                // machine (x86_64, aarch64)
	Pkg    string `json:"pkg"`              // deb or rpm
}

func (p Platform) String() string { return p.P + "/" + p.PV + "/" + p.M }

// Map translates /etc/os-release fields and `uname -m` into an omnitruck
// platform. AlmaLinux, Rocky, CentOS and Oracle Linux are "el", as upstream
// declares them.
func Map(id, idLike, versionID, arch string) (Platform, error) {
	var p Platform
	switch arch {
	case "x86_64", "amd64":
		p.M = "x86_64"
	case "aarch64", "arm64":
		p.M = "aarch64"
	default:
		return p, fmt.Errorf("no CINC package for the %q architecture", arch)
	}
	id = strings.ToLower(strings.TrimSpace(id))
	like := " " + strings.ToLower(idLike) + " "
	major := versionID
	if i := strings.IndexByte(versionID, '.'); i > 0 {
		major = versionID[:i]
	}
	switch {
	case id == "ubuntu":
		p.P, p.PV, p.Pkg = "ubuntu", versionID, "deb"
	case id == "debian":
		p.P, p.PV, p.Pkg = "debian", major, "deb"
	case id == "amzn":
		p.P, p.PV, p.Pkg = "amazon", major, "rpm"
	case id == "rhel" || id == "centos" || id == "rocky" || id == "almalinux" || id == "ol" ||
		(id != "fedora" && (strings.Contains(like, " rhel ") || strings.Contains(like, " centos "))):
		p.P, p.PV, p.Pkg = "el", major, "rpm"
	case id == "sles" || id == "sled" || id == "opensuse-leap":
		p.P, p.PV, p.Pkg = "sles", major, "rpm"
	default:
		return p, fmt.Errorf("sdw-armor does not know the CINC package platform for %q (ID_LIKE %q): install CINC yourself (https://cinc.sh/start/auditor/) or pass --cinc-package", id, strings.TrimSpace(idLike))
	}
	if p.PV == "" {
		return p, fmt.Errorf("%s has no VERSION_ID in /etc/os-release (rolling or testing release): install CINC yourself or pass --cinc-package", id)
	}
	return p, nil
}

// detectScript prints the os-release fields Map needs.
const detectScript = `. /etc/os-release 2>/dev/null
printf 'id=%s\nlike=%s\nver=%s\npretty=%s\narch=%s\n' "$ID" "$ID_LIKE" "$VERSION_ID" "$PRETTY_NAME" "$(uname -m)"`

// Detect reads the target platform.
func Detect(ctx context.Context, t *target.Target) (Platform, error) {
	out, err := t.Output(ctx, detectScript, false)
	if err != nil {
		return Platform{}, fmt.Errorf("detect the platform of %s: %w", t, err)
	}
	kv := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			kv[k] = strings.TrimSpace(v)
		}
	}
	p, err := Map(kv["id"], kv["like"], kv["ver"], kv["arch"])
	p.Pretty = kv["pretty"]
	return p, err
}

// Meta is one resolved package.
type Meta struct {
	Project string `json:"project"`
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

var hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Base returns the omnitruck base URL in use.
func Base() string {
	if b := strings.TrimSpace(os.Getenv("SDW_ARMOR_OMNITRUCK")); b != "" {
		return strings.TrimRight(b, "/")
	}
	return DefaultBase
}

// MetadataURL is the omnitruck metadata query for a project and platform.
// version is empty (latest stable), a major ("18") or an exact version.
func MetadataURL(base, project string, p Platform, version string) string {
	q := url.Values{"p": {p.P}, "pv": {p.PV}, "m": {p.M}}
	if version != "" {
		q.Set("v", version)
	}
	return strings.TrimRight(base, "/") + "/stable/" + url.PathEscape(project) + "/metadata?" + q.Encode()
}

// ParseMetadata reads an omnitruck metadata answer (tab-separated
// "key value" lines, or the JSON variant).
func ParseMetadata(body []byte) (Meta, error) {
	var m Meta
	body = bytes.TrimSpace(body)
	if bytes.HasPrefix(body, []byte("{")) {
		if err := json.Unmarshal(body, &m); err != nil {
			return m, fmt.Errorf("unreadable metadata: %v", err)
		}
	} else {
		for _, line := range strings.Split(string(body), "\n") {
			f := strings.Fields(line)
			if len(f) != 2 {
				continue
			}
			switch f[0] {
			case "url":
				m.URL = f[1]
			case "sha256":
				m.SHA256 = f[1]
			case "version":
				m.Version = f[1]
			}
		}
	}
	m.SHA256 = strings.ToLower(m.SHA256)
	if m.URL == "" || !hexRe.MatchString(m.SHA256) {
		return m, errors.New("the metadata has no package URL or no valid SHA-256")
	}
	return m, nil
}

// Resolve asks omnitruck which package fits the platform, and its checksum.
func Resolve(ctx context.Context, hc *http.Client, base, project string, p Platform, version string) (Meta, error) {
	u := MetadataURL(base, project, p, version)
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Meta{}, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return Meta{}, fmt.Errorf("query %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return Meta{}, fmt.Errorf("no %s package for %s (%s answered %s)", project, p, u, resp.Status)
	}
	m, err := ParseMetadata(body)
	if err != nil {
		return m, fmt.Errorf("%s: %w", u, err)
	}
	m.Project = project
	pu, err := url.Parse(m.URL)
	if err != nil || pu.Host == "" {
		return m, fmt.Errorf("%s: invalid package URL %q", u, m.URL)
	}
	// Plain HTTP only when the operator chose a plain-HTTP mirror.
	if pu.Scheme != "https" && !strings.HasPrefix(base, "http://") {
		return m, fmt.Errorf("%s: refusing non-HTTPS package URL %q", u, m.URL)
	}
	return m, nil
}

// Fetch downloads the package into dir and verifies its SHA-256; a file that
// does not match is deleted. progress, when set, receives the bytes done and
// the total (-1 when unknown).
func Fetch(ctx context.Context, hc *http.Client, m Meta, dir string, progress ...func(done, total int64)) (string, error) {
	pu, err := url.Parse(m.URL)
	if err != nil {
		return "", err
	}
	name := path.Base(pu.Path)
	if name == "" || name == "." || name == "/" || strings.ContainsAny(name, `\`) {
		name = m.Project + ".pkg"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.URL, nil)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", m.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: %s", m.URL, resp.Status)
	}
	dest := filepath.Join(dir, name)
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	var body io.Reader = resp.Body
	if len(progress) > 0 && progress[0] != nil {
		body = &countingReader{r: resp.Body, total: resp.ContentLength, fn: progress[0]}
	}
	_, err = io.Copy(io.MultiWriter(f, h), body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(dest)
		return "", fmt.Errorf("download %s: %w", m.URL, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != m.SHA256 {
		_ = os.Remove(dest)
		return "", fmt.Errorf("checksum mismatch for %s: published %s, downloaded %s. Nothing was installed", name, m.SHA256, got)
	}
	return dest, nil
}

// ProjectOf tells which project a package file holds, from its name
// (cinc-auditor_7.2.1-1_amd64.deb, cinc-18.8.11-1.el9.x86_64.rpm...).
func ProjectOf(file string) string {
	b := filepath.Base(file)
	switch {
	case strings.HasPrefix(b, "cinc-auditor"):
		return Auditor
	case len(b) > 5 && (strings.HasPrefix(b, "cinc_") || strings.HasPrefix(b, "cinc-")) && b[5] >= '0' && b[5] <= '9':
		return Client
	}
	return ""
}

// PkgType is deb or rpm from a file name.
func PkgType(file string) string {
	switch strings.ToLower(filepath.Ext(file)) {
	case ".deb":
		return "deb"
	case ".rpm":
		return "rpm"
	}
	return ""
}

// Local describes a package file given by the operator.
func Local(file string) (Meta, error) {
	f, err := os.Open(file)
	if err != nil {
		return Meta{}, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return Meta{}, err
	}
	return Meta{Project: ProjectOf(file), URL: "file://" + file, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// Options of an installation.
type Options struct {
	Version  string   // latest stable when empty
	Packages []string // operator-provided package files (air-gapped)
	Base     string   // omnitruck base URL (default: Base())
	Resolved *Meta    // package already resolved (and shown to the operator)
	HTTP     *http.Client
	Log      io.Writer
	Progress func(string)
	// OnDownload receives download progress (bytes done, total or -1).
	OnDownload func(done, total int64)
}

func (o *Options) progress(format string, a ...any) {
	if o.Progress != nil {
		o.Progress(fmt.Sprintf(format, a...))
	}
}

// PackageFor returns the operator-provided package for a project, if any.
func (o *Options) PackageFor(project string) string {
	for _, p := range o.Packages {
		if ProjectOf(p) == project {
			return p
		}
	}
	return ""
}

// Install puts project on the target: from the matching --cinc-package when
// given, otherwise from omnitruck with SHA-256 verification.
func Install(ctx context.Context, t *target.Target, project string, o Options) (Meta, error) {
	if o.Log == nil {
		o.Log = io.Discard
	}
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 30 * time.Minute}
	}
	if o.Base == "" {
		o.Base = Base()
	}
	if err := CanInstall(ctx, t); err != nil {
		return Meta{}, err
	}
	plat, err := Detect(ctx, t)
	file := o.PackageFor(project)
	var m Meta
	if file != "" {
		if m, err = Local(file); err != nil {
			return m, err
		}
		pt := PkgType(file)
		if pt == "" {
			return m, fmt.Errorf("%s: expected a .deb or .rpm package", file)
		}
		if plat.Pkg != "" && plat.Pkg != pt {
			return m, fmt.Errorf("%s is a .%s package but %s uses %s packages", file, pt, t, plat.Pkg)
		}
		plat.Pkg = pt
		o.progress("installing %s on %s from %s (sha256 %s)", Label(project), t, file, m.SHA256)
	} else {
		if err != nil {
			return Meta{}, err
		}
		if o.Resolved != nil {
			m = *o.Resolved
		} else if m, err = Resolve(ctx, o.HTTP, o.Base, project, plat, o.Version); err != nil {
			return m, err
		}
		o.progress("downloading %s %s for %s (%s)", Label(project), m.Version, plat, m.URL)
		dir, err := os.MkdirTemp("", "sdw-armor-cinc-")
		if err != nil {
			return m, err
		}
		defer os.RemoveAll(dir)
		if file, err = Fetch(ctx, o.HTTP, m, dir, o.OnDownload); err != nil {
			return m, err
		}
		o.progress("sha256 verified (%s), installing on %s", m.SHA256, t)
	}
	return m, installFile(ctx, t, file, m.SHA256, plat.Pkg, o.Log)
}

// CanInstall checks that installing is possible: root, or sudo.
func CanInstall(ctx context.Context, t *target.Target) error {
	uid, err := t.Output(ctx, "id -u", false)
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w", t, err)
	}
	if strings.TrimSpace(uid) != "0" && !t.Sudo {
		return fmt.Errorf("installing CINC on %s needs root: pass --sudo", t)
	}
	return nil
}

func installFile(ctx context.Context, t *target.Target, file, sum, pkg string, log io.Writer) error {
	dir, err := t.MkTemp(ctx, "sdw-armor-cinc", "/var/tmp")
	if err != nil {
		return err
	}
	defer t.Remove(ctx, dir, t.Sudo)
	remote := dir + "/" + filepath.Base(file)
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	err = t.WriteFileFrom(ctx, remote, f)
	_ = f.Close()
	if err != nil {
		return err
	}
	install := "dpkg -i \"$f\""
	if pkg == "rpm" {
		install = "rpm -U --replacepkgs \"$f\""
	}
	script := "set -e\nf=" + target.Quote(remote) + `
if command -v sha256sum >/dev/null 2>&1; then
  echo "` + sum + `  $f" | sha256sum -c - >/dev/null || { echo "checksum mismatch after the transfer: nothing installed" >&2; exit 1; }
fi
` + install
	var errb bytes.Buffer
	code, err := t.Run(ctx, script, true, nil, log, io.MultiWriter(log, &errb))
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("installing %s on %s failed (exit %d): %s", filepath.Base(file), t, code, strings.TrimSpace(lastLines(errb.String(), 3)))
	}
	return nil
}

// Recipe is the same procedure as shell commands, for operators who prefer
// to type them: resolve, download, verify, then install with the package tool.
func Recipe(base, project string, p Platform, version string) string {
	install := "sudo dpkg -i \"$PKG\""
	if p.Pkg == "rpm" {
		install = "sudo rpm -U \"$PKG\""
	}
	return fmt.Sprintf(`META=$(curl -fsS '%s')
URL=$(printf '%%s\n' "$META" | awk '$1=="url"{print $2}')
SUM=$(printf '%%s\n' "$META" | awk '$1=="sha256"{print $2}')
PKG=${URL##*/}
curl -fsSLO "$URL"
echo "$SUM  $PKG" | sha256sum --check   # integrity, before anything runs
%s
%s version
`, MetadataURL(base, project, p, version), install, Binary(project))
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

type countingReader struct {
	r     io.Reader
	done  int64
	total int64
	fn    func(done, total int64)
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.done += int64(n)
	c.fn(c.done, c.total)
	return n, err
}
