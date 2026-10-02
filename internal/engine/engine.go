// Package engine drives CINC Auditor (or Chef InSpec) natively: locally
// against local://, ssh:// and docker:// targets, or on the target itself.
package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/target"
)

// Candidates, in order of preference. CINC Auditor is the free distribution
// of InSpec; Chef InSpec works too (license acceptance is passed for you).
var Candidates = []string{"cinc-auditor", "/opt/cinc-auditor/bin/cinc-auditor", "inspec", "/opt/inspec/bin/inspec", "/opt/chef-workstation/bin/inspec"}

type Engine struct {
	Path    string
	Name    string
	Version string
}

// ErrNotFound means no engine binary was found.
var ErrNotFound = errors.New("no CINC Auditor (cinc-auditor) or InSpec (inspec) found")

// Find locates the local engine: explicit path, $SDW_ARMOR_ENGINE, then PATH.
func Find(ctx context.Context, override string) (*Engine, error) {
	if override == "" {
		override = os.Getenv("SDW_ARMOR_ENGINE")
	}
	cands := Candidates
	if override != "" {
		cands = []string{override}
	}
	for _, c := range cands {
		p, err := exec.LookPath(c)
		if err != nil {
			continue
		}
		e := &Engine{Path: p, Name: nameOf(p)}
		v, err := e.version(ctx)
		if err != nil {
			if override != "" {
				return nil, fmt.Errorf("engine %s: %w", p, err)
			}
			continue
		}
		e.Version = v
		return e, nil
	}
	if override != "" {
		return nil, fmt.Errorf("engine %q not found or not executable", override)
	}
	return nil, ErrNotFound
}

func nameOf(p string) string {
	if strings.Contains(filepath.Base(p), "inspec") {
		return "inspec"
	}
	return "cinc-auditor"
}

var versionRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

func (e *Engine) version(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	args := []string{"version"}
	if e.Name == "inspec" {
		args = append(args, "--chef-license=accept-silent")
	}
	out, err := exec.CommandContext(ctx, e.Path, args...).Output()
	if err != nil {
		return "", err
	}
	v := versionRe.FindString(string(out))
	if v == "" {
		return "", fmt.Errorf("unexpected version output %q", strings.TrimSpace(string(out)))
	}
	return v, nil
}

// Major version number.
func (e *Engine) Major() int {
	var m int
	if _, err := fmt.Sscanf(e.Version, "%d", &m); err != nil {
		return 0
	}
	return m
}

// ExecOptions describes one audit run.
type ExecOptions struct {
	ProfileDir string
	TargetURI  string // engine transport URI (local://, ssh://..., docker://...)
	Controls   []string
	InputFile  string
	WaiverFile string
	ConfigFile string // InSpec --config JSON (sudo password, key files)
	Sudo       bool
	Identity   string
	ReportPath string
	// SSH, when set, replaces the target URI with explicit connection
	// settings (resolved from ~/.ssh/config by `ssh -G`): the Docker engine
	// cannot read the operator's ssh configuration itself.
	SSH *SSHSettings
	// Progress receives live events (progress-bar reporter on stdout).
	Progress func(Event)
}

// SSHSettings are explicit ssh transport settings for the engine.
type SSHSettings struct {
	Host, User   string
	Port         int
	KeyFiles     []string
	BastionHost  string
	BastionUser  string
	BastionPort  int
	ProxyCommand string
}

// ExecArgs builds the `exec` command line (shared by local and on-target runs).
func ExecArgs(name string, o ExecOptions) []string {
	args := []string{"exec", o.ProfileDir, "--reporter"}
	if o.Progress != nil {
		args = append(args, "progress-bar")
	}
	args = append(args, "json:"+o.ReportPath, "--no-color", "--no-create-lockfile", "--no-distinct-exit")
	if name == "inspec" {
		args = append(args, "--chef-license=accept-silent")
	}
	switch {
	case o.SSH != nil:
		u := "ssh://"
		if o.SSH.User != "" {
			u += o.SSH.User + "@"
		}
		u += o.SSH.Host
		if o.SSH.Port != 0 {
			u += fmt.Sprintf(":%d", o.SSH.Port)
		}
		args = append(args, "-t", u)
		for _, k := range o.SSH.KeyFiles {
			args = append(args, "-i", k)
		}
		if o.SSH.BastionHost != "" {
			args = append(args, "--bastion-host", o.SSH.BastionHost)
			if o.SSH.BastionUser != "" {
				args = append(args, "--bastion-user", o.SSH.BastionUser)
			}
			if o.SSH.BastionPort != 0 {
				args = append(args, "--bastion-port", fmt.Sprint(o.SSH.BastionPort))
			}
		}
		if o.SSH.ProxyCommand != "" {
			args = append(args, "--proxy-command", o.SSH.ProxyCommand)
		}
	case o.TargetURI != "" && o.TargetURI != "local://":
		args = append(args, "-t", o.TargetURI)
	}
	if o.Sudo {
		args = append(args, "--sudo")
	}
	if o.Identity != "" {
		args = append(args, "-i", o.Identity)
	}
	if o.InputFile != "" {
		args = append(args, "--input-file", o.InputFile)
	}
	if o.WaiverFile != "" {
		args = append(args, "--waiver-file", o.WaiverFile)
	}
	if o.ConfigFile != "" {
		args = append(args, "--config", o.ConfigFile)
	}
	if len(o.Controls) > 0 {
		args = append(args, "--controls")
		args = append(args, o.Controls...)
	}
	return args
}

// Exec runs the engine locally and returns the raw JSON report.
func (e *Engine) Exec(ctx context.Context, o ExecOptions, stderr io.Writer) ([]byte, error) {
	cmd := exec.CommandContext(ctx, e.Path, ExecArgs(e.Name, o)...)
	var errb bytes.Buffer
	var w io.Writer = &errb
	if stderr != nil {
		w = io.MultiWriter(&errb, stderr)
	}
	cmd.Stdout = io.Discard
	var pw *ProgressWriter
	if o.Progress != nil {
		// The progress-bar reporter writes to stderr; other lines go on.
		pw = NewProgressWriter(o.Progress, w)
		w = pw
	}
	cmd.Stderr = w
	cmd.Env = append(os.Environ(), "CHEF_LICENSE=accept-silent")
	runErr := cmd.Run()
	if pw != nil {
		pw.Flush()
	}
	raw, readErr := os.ReadFile(o.ReportPath)
	if readErr != nil || len(bytes.TrimSpace(raw)) == 0 {
		if runErr != nil {
			return nil, fmt.Errorf("%s exec failed: %v\n%s", e.Name, runErr, tail(errb.String(), 15))
		}
		return nil, fmt.Errorf("%s produced no report: %s", e.Name, tail(errb.String(), 15))
	}
	return raw, nil
}

// OnTarget runs the engine installed on the target itself: the profile is
// uploaded to a private temp dir, executed with local://, and the JSON report
// is read back. Nothing is left behind.
func OnTarget(ctx context.Context, t *target.Target, enginePath string, profile func(dir string) error, o ExecOptions, files map[string][]byte, stderr io.Writer) ([]byte, error) {
	dir, err := t.MkTemp(ctx, "sdw-armor", "/tmp")
	if err != nil {
		return nil, err
	}
	defer t.Remove(ctx, dir, t.Sudo)
	if err := profile(dir + "/profile"); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := t.WriteFile(ctx, dir+"/"+n, files[n]); err != nil {
			return nil, err
		}
	}
	o.ProfileDir = dir + "/profile"
	o.ReportPath = dir + "/report.json"
	o.TargetURI = ""
	o.Sudo = false // the whole run is privileged instead
	name := nameOf(enginePath)
	parts := []string{target.Quote(enginePath)}
	for _, a := range ExecArgs(name, o) {
		parts = append(parts, target.Quote(a))
	}
	script := "cd " + target.Quote(dir) + " && CHEF_LICENSE=accept-silent " + strings.Join(parts, " ") + " >/dev/null; rc=$?; chmod 0644 " + target.Quote(o.ReportPath) + " 2>/dev/null; exit $rc"
	var errb bytes.Buffer
	var w io.Writer = &errb
	if stderr != nil {
		w = io.MultiWriter(&errb, stderr)
	}
	var pw *ProgressWriter
	if o.Progress != nil {
		pw = NewProgressWriter(o.Progress, w)
		w = pw
	}
	_, err = t.Run(ctx, script, true, nil, io.Discard, w)
	if pw != nil {
		pw.Flush()
	}
	if err != nil {
		return nil, err
	}
	raw, err := t.ReadFile(ctx, o.ReportPath, t.Sudo)
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("%s on %s produced no report: %s", name, t, tail(errb.String(), 15))
	}
	return raw, nil
}

// InputsYAML renders inputs as a YAML document. Values are emitted as JSON,
// which is valid YAML flow syntax, so no YAML library is needed.
func InputsYAML(inputs map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(inputs))
	for k := range inputs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	b.WriteString("# Generated by sdw-armor\n")
	for _, k := range keys {
		v, err := json.Marshal(inputs[k])
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "%s: %s\n", k, v)
	}
	return b.Bytes(), nil
}

// tail keeps the last n meaningful lines of engine output (Ruby backtrace
// frames are dropped: the message is what helps).
func tail(s string, n int) string {
	var lines []string
	for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "from /") || t == "" {
			continue
		}
		lines = append(lines, l)
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
