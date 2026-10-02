// Package selfupdate finds, downloads and verifies sdw-armor releases.
//
// Releases are read from the GitHub API of the project (or a mirror set in
// SDW_ARMOR_RELEASES). Every download is checked against the release's
// SHA256SUMS; when cosign or the GitHub CLI is installed, the signature of
// SHA256SUMS or the build provenance of the file is verified too.
package selfupdate

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
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	// Repo is the GitHub repository releases come from.
	Repo = "Shadow-Security-official/Shadow-Armor"
	// DefaultAPI is the GitHub API base of Repo.
	DefaultAPI = "https://api.github.com/repos/" + Repo
	// SigIssuer and SigIdentity are what the keyless signature of
	// SHA256SUMS must carry: the release workflow of Repo.
	SigIssuer   = "https://token.actions.githubusercontent.com"
	SigIdentity = `^https://github.com/Shadow-Security-official/Shadow-Armor/\.github/workflows/release\.yml@refs/(tags/v|heads/main)`
	// SumsFile and SigFile are published with every release.
	SumsFile = "SHA256SUMS"
	SigFile  = "SHA256SUMS.sigstore.json"
)

// API is the releases API base: SDW_ARMOR_RELEASES, or GitHub.
func API() string {
	if v := strings.TrimSpace(os.Getenv("SDW_ARMOR_RELEASES")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return DefaultAPI
}

// Asset is one file of a release.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// Release is a published release.
type Release struct {
	Tag        string    `json:"tag_name"`
	Name       string    `json:"name"`
	URL        string    `json:"html_url"`
	Published  time.Time `json:"published_at"`
	Draft      bool      `json:"draft"`
	Prerelease bool      `json:"prerelease"`
	Body       string    `json:"body"`
	Assets     []Asset   `json:"assets"`
}

// Version is the tag without its leading "v".
func (r Release) Version() string { return strings.TrimPrefix(r.Tag, "v") }

// Asset returns the release file with that name.
func (r Release) Asset(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

// Notes returns the first bullet points of the release notes.
func (r Release) Notes(max int) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(r.Body))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() && len(out) < max {
		l := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(l, "- ") {
			out = append(out, strings.NewReplacer("`", "", "**", "").Replace(strings.TrimPrefix(l, "- ")))
		}
	}
	return out
}

// Client talks to the releases API.
type Client struct {
	HTTP *http.Client
	API  string
	// UserAgent identifies the caller (GitHub requires one).
	UserAgent string
}

func (c *Client) get(ctx context.Context, url string, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" && strings.HasPrefix(url, "https://api.github.com/") {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	return hc.Do(req)
}

// Latest returns the newest published release (drafts and pre-releases
// excluded).
func (c *Client) Latest(ctx context.Context) (Release, error) {
	return c.release(ctx, c.API+"/releases/latest")
}

// ByTag returns the release of one tag (v0.3.1).
func (c *Client) ByTag(ctx context.Context, tag string) (Release, error) {
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	r, err := c.release(ctx, c.API+"/releases/tags/"+tag)
	if errors.Is(err, ErrNoRelease) {
		return r, fmt.Errorf("%s: %w", tag, err)
	}
	return r, err
}

func (c *Client) release(ctx context.Context, url string) (Release, error) {
	resp, err := c.get(ctx, url, "application/vnd.github+json")
	if err != nil {
		return Release{}, fmt.Errorf("cannot reach %s: %w", c.API, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return Release{}, err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return Release{}, ErrNoRelease
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
		return Release{}, fmt.Errorf("%s refused the request (%s): GitHub rate limit? Set GITHUB_TOKEN or retry later", c.API, resp.Status)
	case resp.StatusCode != http.StatusOK:
		return Release{}, fmt.Errorf("%s: %s", url, resp.Status)
	}
	var r Release
	if err := json.Unmarshal(body, &r); err != nil {
		return Release{}, fmt.Errorf("unreadable release from %s: %w", url, err)
	}
	if r.Tag == "" {
		return Release{}, fmt.Errorf("release without a tag at %s", url)
	}
	return r, nil
}

// ErrNoRelease: the repository has no such (or no) published release.
var ErrNoRelease = errors.New("no published release found")

// Download writes url to dest and returns its SHA-256 (hex).
func (c *Client) Download(ctx context.Context, url, dest string, progress func(done, total int64)) (string, error) {
	resp, err := c.get(ctx, url, "application/octet-stream")
	if err != nil {
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: %s", url, resp.Status)
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	var body io.Reader = resp.Body
	if progress != nil {
		body = &counting{r: resp.Body, total: resp.ContentLength, fn: progress}
	}
	_, err = io.Copy(io.MultiWriter(f, h), body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(dest)
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type counting struct {
	r           io.Reader
	done, total int64
	fn          func(done, total int64)
}

func (c *counting) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.done += int64(n)
	c.fn(c.done, c.total)
	return n, err
}

// ParseSums reads a sha256sum file: file name => hex digest.
func ParseSums(b []byte) map[string]string {
	out := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) != 2 || len(f[0]) != 64 {
			continue
		}
		out[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
	}
	return out
}

// BinaryName is the release file of the static binary for a platform.
func BinaryName(goos, goarch string) string { return "sdw-armor-" + goos + "-" + goarch }

// PackageName is the release file of the .deb or .rpm package.
func PackageName(kind, version, goarch string) string {
	if kind == "rpm" {
		arch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[goarch]
		return fmt.Sprintf("sdw-armor-%s-1.%s.rpm", version, arch)
	}
	return fmt.Sprintf("sdw-armor_%s-1_%s.deb", version, goarch)
}

// Compare orders two versions (a leading "v" is ignored): -1, 0 or 1.
// A pre-release (0.3.0-rc1) sorts before its release.
func Compare(a, b string) int {
	ca, pa := split(a)
	cb, pb := split(b)
	for i := 0; i < 3; i++ {
		if ca[i] != cb[i] {
			if ca[i] < cb[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case pa == pb:
		return 0
	case pa == "":
		return 1
	case pb == "":
		return -1
	}
	return comparePre(pa, pb)
}

func split(v string) ([3]int, string) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	core, pre, _ := strings.Cut(v, "-")
	var n [3]int
	for i, p := range strings.SplitN(core, ".", 3) {
		n[i], _ = strconv.Atoi(p)
	}
	return n, pre
}

func comparePre(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, xe := strconv.Atoi(as[i])
		y, ye := strconv.Atoi(bs[i])
		switch {
		case xe == nil && ye == nil && x != y:
			if x < y {
				return -1
			}
			return 1
		case xe == nil && ye != nil:
			return -1
		case xe != nil && ye == nil:
			return 1
		case as[i] != bs[i]:
			if as[i] < bs[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}

// IsRelease says whether v is a plain release version (0.3.1), as opposed
// to a development build (0.3.1-dev, v0.3.0-4-g1a2b3c4-dirty).
func IsRelease(v string) bool {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}

// Verification is the outcome of the signature check of a download.
type Verification struct {
	Tool   string // cosign, gh, or "" when neither could run
	Detail string
}

// VerifySignature checks who built the release, with the first available
// tool: cosign on the signed SHA256SUMS, or the GitHub CLI on the build
// provenance of the file. With neither, it returns an empty Verification and
// no error: the SHA-256 check still stands.
func VerifySignature(ctx context.Context, sums, bundle, file string) (Verification, error) {
	if path, err := exec.LookPath("cosign"); err == nil && bundle != "" {
		out, err := exec.CommandContext(ctx, path, "verify-blob", sums, "--bundle", bundle,
			"--certificate-oidc-issuer", SigIssuer, "--certificate-identity-regexp", SigIdentity).CombinedOutput()
		if err != nil {
			return Verification{Tool: "cosign"}, fmt.Errorf("cosign could not verify %s: %s", SumsFile, lastLine(out))
		}
		return Verification{Tool: "cosign", Detail: SumsFile + " signed by the release workflow of " + Repo}, nil
	}
	if path, err := exec.LookPath("gh"); err == nil && ghReady(ctx, path) {
		out, err := exec.CommandContext(ctx, path, "attestation", "verify", file, "--repo", Repo).CombinedOutput()
		if err != nil {
			return Verification{Tool: "gh"}, fmt.Errorf("gh could not verify the build provenance: %s", lastLine(out))
		}
		return Verification{Tool: "gh", Detail: "SLSA build provenance: built by the release workflow of " + Repo}, nil
	}
	return Verification{}, nil
}

// ghReady: a GitHub CLI with the attestation command, logged in.
func ghReady(ctx context.Context, gh string) bool {
	if exec.CommandContext(ctx, gh, "attestation", "verify", "--help").Run() != nil {
		return false
	}
	return exec.CommandContext(ctx, gh, "auth", "status").Run() == nil
}

func lastLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// Installer says how the running binary was installed: "deb" or "rpm" when
// a package owns it, "binary" otherwise.
func Installer(ctx context.Context, exe string) string {
	if p, err := exec.LookPath("dpkg-query"); err == nil {
		if out, err := exec.CommandContext(ctx, p, "-S", exe).Output(); err == nil && bytes.HasPrefix(out, []byte("sdw-armor:")) {
			return "deb"
		}
	}
	if p, err := exec.LookPath("rpm"); err == nil {
		if out, err := exec.CommandContext(ctx, p, "-qf", exe).Output(); err == nil && bytes.HasPrefix(out, []byte("sdw-armor-")) {
			return "rpm"
		}
	}
	return "binary"
}
