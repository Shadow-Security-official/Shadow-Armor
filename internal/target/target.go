// Package target reaches the audited host without installing anything on it:
// the local shell, the system `ssh` client (so ~/.ssh/config, ProxyJump,
// agents and ControlMaster all apply), or `docker exec`.
package target

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
)

type Kind string

const (
	Local  Kind = "local"
	SSH    Kind = "ssh"
	Docker Kind = "docker"
)

type Target struct {
	Kind      Kind
	User      string
	Host      string
	Port      int
	Container string
	// Identity is an optional private key for ssh (-i).
	Identity string
	// Sudo runs privileged commands through `sudo -n` (or `sudo -S` when a
	// password is provided through SudoPassword).
	Sudo         bool
	SudoPassword string
}

// Parse accepts local, local://, ssh://[user@]host[:port] and docker://name.
func Parse(s string) (*Target, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "" || s == "local" || s == "local://":
		return &Target{Kind: Local}, nil
	case strings.HasPrefix(s, "docker://"):
		name := strings.TrimPrefix(s, "docker://")
		if name == "" || strings.ContainsAny(name, "/ ") {
			return nil, fmt.Errorf("invalid docker target %q: use docker://<container name or id>", s)
		}
		return &Target{Kind: Docker, Container: name}, nil
	case strings.HasPrefix(s, "ssh://"):
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return nil, fmt.Errorf("invalid ssh target %q: use ssh://[user@]host[:port]", s)
		}
		t := &Target{Kind: SSH, Host: u.Hostname()}
		if u.User != nil {
			t.User = u.User.Username()
			if _, has := u.User.Password(); has {
				return nil, errors.New("passwords in target URIs are not supported: use keys or ssh-agent")
			}
		}
		if p := u.Port(); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n <= 0 || n > 65535 {
				return nil, fmt.Errorf("invalid ssh port %q", p)
			}
			t.Port = n
		}
		return t, nil
	}
	return nil, fmt.Errorf("unsupported target %q: use local, ssh://[user@]host[:port] or docker://<container>", s)
}

// String is the canonical URI of the target.
func (t *Target) String() string {
	switch t.Kind {
	case SSH:
		s := "ssh://"
		if t.User != "" {
			s += t.User + "@"
		}
		if strings.Contains(t.Host, ":") {
			s += "[" + t.Host + "]"
		} else {
			s += t.Host
		}
		if t.Port != 0 {
			s += ":" + strconv.Itoa(t.Port)
		}
		return s
	case Docker:
		return "docker://" + t.Container
	}
	return "local://"
}

// Shell quoting for POSIX sh.
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	safe := func(r rune) bool {
		return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:=@%+,", r)
	}
	if strings.IndexFunc(s, func(r rune) bool { return !safe(r) }) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// SSHArgs are the ssh client options for this target (before the command).
func (t *Target) SSHArgs() []string {
	args := []string{"-o", "BatchMode=yes"}
	if t.Port != 0 {
		args = append(args, "-p", strconv.Itoa(t.Port))
	}
	if t.Identity != "" {
		args = append(args, "-i", t.Identity)
	}
	dest := t.Host
	if t.User != "" {
		dest = t.User + "@" + t.Host
	}
	return append(args, "--", dest)
}

// Command builds the local process that runs script on the target.
func (t *Target) Command(ctx context.Context, script string, privileged bool) *exec.Cmd {
	if privileged && t.Sudo && t.Kind != Docker {
		// Already root (a root login, or sdw-armor run as root): no sudo
		// needed, and it may not even be installed.
		elevate := "sudo -n sh -c"
		if t.SudoPassword != "" {
			elevate = "sudo -S -p '' sh -c"
		}
		script = `if [ "$(id -u)" = 0 ]; then set -- sh -c; else set -- ` + elevate + `; fi; exec "$@" ` + Quote(script)
	}
	switch t.Kind {
	case SSH:
		return exec.CommandContext(ctx, "ssh", append(t.SSHArgs(), "sh -c "+Quote(script))...)
	case Docker:
		return exec.CommandContext(ctx, "docker", "exec", "-i", t.Container, "sh", "-c", script)
	}
	return exec.CommandContext(ctx, "sh", "-c", script)
}

// Run executes script on the target and streams its output.
func (t *Target) Run(ctx context.Context, script string, privileged bool, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	cmd := t.Command(ctx, script, privileged)
	if privileged && t.Sudo && t.SudoPassword != "" && t.Kind != Docker {
		if stdin != nil {
			return -1, errors.New("internal: stdin is reserved for the sudo password")
		}
		stdin = strings.NewReader(t.SudoPassword + "\n")
	}
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}

// Output runs script and returns trimmed stdout; a non-zero exit is an error
// carrying stderr.
func (t *Target) Output(ctx context.Context, script string, privileged bool) (string, error) {
	var out, errb bytes.Buffer
	code, err := t.Run(ctx, script, privileged, nil, &out, &errb)
	if err != nil {
		return "", err
	}
	if code != 0 {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = strings.TrimSpace(out.String())
		}
		return strings.TrimSpace(out.String()), fmt.Errorf("exit %d: %s", code, firstLines(msg, 3))
	}
	return strings.TrimSpace(out.String()), nil
}

// Probe checks the target is reachable and returns `id -un`.
func (t *Target) Probe(ctx context.Context) (string, error) {
	out, err := t.Output(ctx, "id -un", false)
	if err != nil {
		return "", fmt.Errorf("cannot reach %s: %w", t, err)
	}
	return out, nil
}

// Has reports whether a command exists on the target (PATH plus the usual
// omnibus locations).
func (t *Target) Has(ctx context.Context, bin string) (string, bool) {
	script := fmt.Sprintf("command -v %s 2>/dev/null && exit 0; for d in /opt/cinc-auditor/bin /opt/cinc/bin /opt/inspec/bin /opt/chef/bin /usr/local/bin; do [ -x \"$d/%s\" ] && echo \"$d/%s\" && exit 0; done; exit 1", Quote(bin), bin, bin)
	out, err := t.Output(ctx, script, false)
	if err != nil || out == "" {
		return "", false
	}
	return strings.TrimSpace(strings.Split(out, "\n")[0]), true
}

// MkTemp creates a private temporary directory on the target, under $TMPDIR
// or base (e.g. /var/tmp when /tmp itself may be remounted by the run).
func (t *Target) MkTemp(ctx context.Context, prefix, base string) (string, error) {
	if base == "" {
		base = "/tmp"
	}
	dir, err := t.Output(ctx, "umask 077 && mktemp -d \"${TMPDIR:-"+base+"}/"+prefix+".XXXXXXXX\"", false)
	if err != nil {
		return "", fmt.Errorf("create temporary directory on %s: %w", t, err)
	}
	return dir, nil
}

// Upload copies a directory tree of fsys (rooted at root) into dest on the
// target as a gzip tar stream: no scp/sftp/rsync needed, only tar.
func (t *Target) Upload(ctx context.Context, fsys fs.FS, root, dest string) error {
	var buf bytes.Buffer
	if err := TarGz(&buf, fsys, root); err != nil {
		return err
	}
	var errb bytes.Buffer
	code, err := t.Run(ctx, "mkdir -p "+Quote(dest)+" && tar -xzf - -C "+Quote(dest), false, &buf, io.Discard, &errb)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("upload to %s:%s failed: %s", t, dest, firstLines(errb.String(), 3))
	}
	return nil
}

// WriteFile writes data to a file on the target (mode 0600).
func (t *Target) WriteFile(ctx context.Context, p string, data []byte) error {
	return t.WriteFileFrom(ctx, p, bytes.NewReader(data))
}

// WriteFileFrom streams r into a file on the target (mode 0600).
func (t *Target) WriteFileFrom(ctx context.Context, p string, r io.Reader) error {
	var errb bytes.Buffer
	code, err := t.Run(ctx, "umask 077 && cat > "+Quote(p), false, r, io.Discard, &errb)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("write %s on %s: %s", p, t, firstLines(errb.String(), 3))
	}
	return nil
}

// ReadFile reads a file from the target (privileged when needed).
func (t *Target) ReadFile(ctx context.Context, p string, privileged bool) ([]byte, error) {
	var out, errb bytes.Buffer
	code, err := t.Run(ctx, "cat "+Quote(p), privileged, nil, &out, &errb)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("read %s on %s: %s", p, t, firstLines(errb.String(), 3))
	}
	return out.Bytes(), nil
}

// Remove deletes a path on the target (best effort).
func (t *Target) Remove(ctx context.Context, p string, privileged bool) {
	if p == "" || p == "/" || !strings.Contains(p, "sdw-armor") {
		return
	}
	_, _ = t.Run(ctx, "rm -rf "+Quote(p), privileged, nil, io.Discard, io.Discard)
}

// TarGz writes the tree under root of fsys as a gzip-compressed tar stream,
// with paths relative to root.
func TarGz(w io.Writer, fsys fs.FS, root string) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(p, root), "/")
		if rel == "" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr := &tar.Header{Name: rel, ModTime: info.ModTime(), Uid: 0, Gid: 0}
		if d.IsDir() {
			hdr.Typeflag = tar.TypeDir
			hdr.Name += "/"
			hdr.Mode = 0o755
			return tw.WriteHeader(hdr)
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		hdr.Typeflag = tar.TypeReg
		hdr.Mode = 0o644
		hdr.Size = int64(len(data))
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
	if err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// ExtractTo materialises an fs.FS subtree into a local directory.
func ExtractTo(fsys fs.FS, root, dest string) error {
	return fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(p, root), "/")
		out := path.Join(dest, rel)
		if d.IsDir() {
			return os.MkdirAll(out, 0o700)
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		return os.WriteFile(out, data, 0o600)
	})
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, " | ")
}

// SSHConfig is what the system ssh client would use to reach the target.
type SSHConfig struct {
	HostName     string
	User         string
	Port         int
	IdentityFile []string // existing files only, ~ expanded
	ProxyJump    string
	ProxyCommand string
}

// ResolveSSH asks the local ssh client (`ssh -G`) how it would connect:
// aliases, users, ports and keys from ~/.ssh/config, resolved exactly as
// OpenSSH does. Nothing connects.
func (t *Target) ResolveSSH(ctx context.Context) (*SSHConfig, error) {
	if t.Kind != SSH {
		return nil, errors.New("not an ssh target")
	}
	args := t.SSHArgs()
	// ssh -G takes the same options and destination, without "--".
	var opts []string
	for _, a := range args {
		if a != "--" {
			opts = append(opts, a)
		}
	}
	out, err := exec.CommandContext(ctx, "ssh", append([]string{"-G"}, opts...)...).Output()
	if err != nil {
		return nil, fmt.Errorf("ssh -G %s: %w", t.Host, err)
	}
	return parseSSHG(string(out), os.Getenv("HOME")), nil
}

func parseSSHG(out, home string) *SSHConfig {
	c := &SSHConfig{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(k) {
		case "hostname":
			c.HostName = v
		case "user":
			c.User = v
		case "port":
			c.Port, _ = strconv.Atoi(v)
		case "identityfile":
			if strings.HasPrefix(v, "~/") && home != "" {
				v = home + v[1:]
			}
			if st, err := os.Stat(v); err == nil && !st.IsDir() {
				c.IdentityFile = append(c.IdentityFile, v)
			}
		case "proxyjump":
			if v != "none" {
				c.ProxyJump = v
			}
		case "proxycommand":
			if v != "none" {
				c.ProxyCommand = v
			}
		}
	}
	return c
}
