package engine

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerRunArgs(t *testing.T) {
	dir := t.TempDir()
	d := &Docker{Image: "docker.io/cincproject/auditor:7.2.1"}
	o := ExecOptions{
		ProfileDir: filepath.Join(dir, "profile"),
		InputFile:  filepath.Join(dir, "inputs.yml"),
		ReportPath: filepath.Join(dir, "report.json"),
		Controls:   []string{"SA-06.01"},
		Sudo:       true,
		Identity:   "/home/me/.ssh/id_ed25519",
		SSH:        &SSHSettings{Host: "10.0.0.7", User: "admin", Port: 2222, KeyFiles: []string{"/home/me/.ssh/id_ed25519"}, BastionHost: "jump", BastionUser: "ops"},
		Progress:   func(Event) {},
	}
	args, err := d.runArgs("sdw-armor-engine-test", DockerRun{WorkDir: dir, ReadOnly: []string{"/home/me/.ssh/id_ed25519"}}, o)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Join(args, " ")
	for _, want := range []string{
		"run --rm --name sdw-armor-engine-test",
		"-v " + dir + ":/sdw ",
		"-v /home/me/.ssh/id_ed25519:/home/me/.ssh/id_ed25519:ro",
		"--entrypoint sh docker.io/cincproject/auditor:7.2.1",
		"exec /sdw/profile --reporter progress-bar json:/sdw/report.json",
		"-t ssh://admin@10.0.0.7:2222 -i /home/me/.ssh/id_ed25519 --bastion-host jump --bastion-user ops",
		"--sudo --input-file /sdw/inputs.yml --controls SA-06.01",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("missing %q in:\n%s", want, line)
		}
	}
	if strings.Contains(line, "docker.sock") {
		t.Error("an ssh target must not get the Docker socket")
	}
	if strings.Count(line, "-i /home/me/.ssh/id_ed25519") != 1 {
		t.Error("the key must be passed once")
	}
}
