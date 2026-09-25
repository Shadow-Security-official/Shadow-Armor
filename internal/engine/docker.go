package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// DefaultImage is the CINC Auditor image the Docker engine runs, pinned to
// the version Shadow-Armor is tested with. Override it with --engine-image
// or $SDW_ARMOR_ENGINE_IMAGE (a digest reference pins it completely).
const DefaultImage = "docker.io/cincproject/auditor:7.2.1"

// ImageRef returns the image to use: explicit, $SDW_ARMOR_ENGINE_IMAGE, or
// DefaultImage.
func ImageRef(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if e := strings.TrimSpace(os.Getenv("SDW_ARMOR_ENGINE_IMAGE")); e != "" {
		return e
	}
	return DefaultImage
}

// Docker runs CINC Auditor from its container image: nothing to install on
// this machine but Docker. It audits ssh:// and docker:// targets; it cannot
// audit the machine it runs on (a container sees its own filesystem).
type Docker struct {
	Image   string // reference as given
	Digest  string // repo digest of the local image (image@sha256:...)
	Version string // engine version inside the image
}

// ErrDockerUnavailable means the docker CLI or daemon is not usable.
var ErrDockerUnavailable = errors.New("docker is not available")

// DockerReady checks the docker CLI and daemon.
func DockerReady(ctx context.Context) error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("%w: no docker CLI in PATH", ErrDockerUnavailable)
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", ErrDockerUnavailable, firstLine(string(out), err))
	}
	return nil
}

// ImageDigest returns the repo digest of a local image, and whether the
// image is present at all.
func ImageDigest(ctx context.Context, image string) (string, bool) {
	out, err := exec.CommandContext(ctx, "docker", "image", "inspect", "--format", "{{join .RepoDigests \" \"}}", image).Output()
	if err != nil {
		return "", false
	}
	for _, d := range strings.Fields(string(out)) {
		return d, true
	}
	return "", true
}

// PrepareDocker makes sure the image is present (pulling it when pull is
// true) and reads the engine version inside it.
func PrepareDocker(ctx context.Context, image string, pull bool, log io.Writer) (*Docker, error) {
	if err := DockerReady(ctx); err != nil {
		return nil, err
	}
	d := &Docker{Image: image}
	digest, ok := ImageDigest(ctx, image)
	if !ok {
		if !pull {
			return nil, fmt.Errorf("the engine image %s is not present locally", image)
		}
		if log == nil {
			log = io.Discard
		}
		var errb bytes.Buffer
		cmd := exec.CommandContext(ctx, "docker", "pull", image)
		cmd.Stdout, cmd.Stderr = log, io.MultiWriter(log, &errb)
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("docker pull %s: %s", image, firstLine(errb.String(), err))
		}
		digest, _ = ImageDigest(ctx, image)
	}
	d.Digest = digest
	vctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(vctx, "docker", "run", "--rm", "--entrypoint", "cinc-auditor", image, "version").Output()
	if err != nil {
		return nil, fmt.Errorf("%s does not run cinc-auditor: %v", image, err)
	}
	if d.Version = versionRe.FindString(string(out)); d.Version == "" {
		return nil, fmt.Errorf("%s: unexpected cinc-auditor version output %q", image, strings.TrimSpace(string(out)))
	}
	return d, nil
}

// Ref is the most precise reference of the image that ran.
func (d *Docker) Ref() string {
	if d.Digest != "" {
		return d.Digest
	}
	return d.Image
}

// DockerRun describes the mounts a run needs.
type DockerRun struct {
	WorkDir string // host directory holding the profile, inputs and the report
	// DockerTarget: the target is a container, so the engine needs the
	// Docker API socket of this machine.
	DockerTarget bool
	// Files the engine must read at their host path (ssh keys).
	ReadOnly []string
}

const containerWork = "/sdw"

// Exec runs the audit in a throwaway container and returns the JSON report.
// Paths of o are host paths inside r.WorkDir; they are mapped into the
// container.
func (d *Docker) Exec(ctx context.Context, r DockerRun, o ExecOptions, stderr io.Writer) ([]byte, error) {
	name := "sdw-armor-engine-" + randomSuffix()
	args, err := d.runArgs(name, r, o)
	if err != nil {
		return nil, err
	}
	hostReport := o.ReportPath
	cmd := exec.Command("docker", args...) //nolint:gosec // arguments are built, not interpolated into a shell
	var errb bytes.Buffer
	var w io.Writer = &errb
	if stderr != nil {
		w = io.MultiWriter(&errb, stderr)
	}
	cmd.Stdout = io.Discard
	var pw *ProgressWriter
	if o.Progress != nil {
		pw = NewProgressWriter(o.Progress, w)
		w = pw
	}
	cmd.Stderr = w
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var runErr error
	select {
	case runErr = <-done:
	case <-ctx.Done():
		// Killing the docker CLI does not stop the container: remove it.
		rm := exec.Command("docker", "rm", "-f", name)
		_ = rm.Run()
		<-done
		return nil, ctx.Err()
	}
	if pw != nil {
		pw.Flush()
	}
	raw, readErr := os.ReadFile(hostReport)
	if readErr != nil || len(bytes.TrimSpace(raw)) == 0 {
		if runErr != nil {
			return nil, fmt.Errorf("cinc-auditor (docker %s) failed: %v\n%s", d.Image, runErr, tail(errb.String(), 15))
		}
		return nil, fmt.Errorf("cinc-auditor (docker %s) produced no report: %s", d.Image, tail(errb.String(), 15))
	}
	return raw, nil
}

// dockerSocket returns the local Docker API socket to mount, or a non-unix
// DOCKER_HOST to pass through.
func dockerSocket() (sock, host string) {
	if h := os.Getenv("DOCKER_HOST"); h != "" {
		if u, err := url.Parse(h); err == nil && u.Scheme == "unix" {
			return u.Path, ""
		}
		return "", h
	}
	for _, s := range []string{"/var/run/docker.sock", "/run/docker.sock"} {
		if st, err := os.Stat(s); err == nil && st.Mode()&os.ModeSocket != 0 {
			return s, ""
		}
	}
	return "", ""
}

func randomSuffix() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func firstLine(s string, err error) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return err.Error()
	}
	return strings.SplitN(s, "\n", 2)[0]
}

// runArgs builds the `docker run` command line: the work directory mounted
// at /sdw with every path of o mapped into it, the Docker socket for a
// docker:// target, ssh keys read-only at their own path, the ssh agent.
func (d *Docker) runArgs(name string, r DockerRun, o ExecOptions) ([]string, error) {
	abs, err := filepath.Abs(r.WorkDir)
	if err != nil {
		return nil, err
	}
	inside := func(p string) string {
		if p == "" {
			return ""
		}
		rel, err := filepath.Rel(abs, p)
		if err != nil || strings.HasPrefix(rel, "..") {
			return p
		}
		return containerWork + "/" + filepath.ToSlash(rel)
	}
	co := o
	co.ProfileDir, co.ReportPath = inside(o.ProfileDir), inside(o.ReportPath)
	co.InputFile, co.WaiverFile, co.ConfigFile = inside(o.InputFile), inside(o.WaiverFile), inside(o.ConfigFile)
	co.Identity = "" // keys are passed through co.SSH

	args := []string{"run", "--rm", "--name", name, "--label", "org.opencontainers.image.title=sdw-armor-engine",
		"-v", abs + ":" + containerWork, "-e", "CHEF_LICENSE=accept-no-persist"}
	if runtime.GOOS == "linux" {
		// Reach the same hosts, names and ports as this machine.
		args = append(args, "--network", "host")
	}
	if r.DockerTarget {
		sock, envHost := dockerSocket()
		switch {
		case sock != "":
			args = append(args, "-v", sock+":/var/run/docker.sock")
		case envHost != "":
			args = append(args, "-e", "DOCKER_HOST="+envHost)
		}
	}
	seen := map[string]bool{}
	for _, f := range r.ReadOnly {
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		args = append(args, "-v", f+":"+f+":ro")
	}
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" && o.SSH != nil && runtime.GOOS == "linux" {
		if st, err := os.Stat(sock); err == nil && st.Mode()&os.ModeSocket != 0 {
			args = append(args, "-v", sock+":/run/sdw-ssh-agent.sock", "-e", "SSH_AUTH_SOCK=/run/sdw-ssh-agent.sock")
		}
	}
	// The report is written as root inside the container: hand the work
	// directory back to the caller before exiting.
	owner := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	script := `cinc-auditor "$@"; rc=$?; chown -R ` + owner + ` ` + containerWork + ` 2>/dev/null; exit $rc`
	args = append(args, "--entrypoint", "sh", d.Image, "-c", script, "sh")
	return append(args, ExecArgs("cinc-auditor", co)...), nil

}
