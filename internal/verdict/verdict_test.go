package verdict

import (
	"testing"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/engine"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
)

func res(status, desc, msg string) engine.InspecResult {
	return engine.InspecResult{Status: status, CodeDesc: desc, Message: msg}
}

func TestKind(t *testing.T) {
	cases := map[string]string{
		"sysctl kernel.randomize_va_space [boot value: not persisted] runtime is expected to cmp == 2":         KindRuntime,
		"sysctl kernel.randomize_va_space [boot value: /etc/sysctl.conf:3] persistent is expected to cmp == 2": KindPersistent,
		"mount /tmp runtime_options is expected to include \"nodev\"":                                          KindRuntime,
		"systemd unit x persistent_enabled is expected to cmp == false":                                        KindPersistent,
		"sshd -T PermitRootLogin (set in /etc/ssh/sshd_config:12) value is expected to be in \"no\"":           KindEffective,
		"audit rule: watch /etc/persistent-data (-p wa) value is expected to cmp == true":                      KindEffective,
		"listening sockets exposes only the allowed ports (22)":                                                KindEffective,
	}
	for desc, want := range cases {
		if got := Kind(desc); got != want {
			t.Errorf("Kind(%q) = %s, want %s", desc, got, want)
		}
	}
}

func TestClassify(t *testing.T) {
	const rt = "sysctl k runtime is expected to cmp == 2"
	const ps = "sysctl k persistent is expected to cmp == 2"
	const eff = "sshd -T x value is expected to be in \"no\""
	cases := []struct {
		name    string
		results []engine.InspecResult
		waiver  map[string]any
		status  model.Status
		qual    model.Qualifier
		proof   string // now/on_disk/reboot, checked when set
		decl    string // declared evidence type of unprefixed assertions
	}{
		{"durable", []engine.InspecResult{res("passed", rt, ""), res("passed", ps, "")}, nil, model.Pass, model.Durable, "proven/proven/expected", ""},
		{"runtime only: persistence contradicted", []engine.InspecResult{res("passed", rt, ""), res("failed", ps, "expected: 2 got:")}, nil, model.Pass, model.RuntimeOnly, "proven/failed/failed", ""},
		{"runtime only: persistence not measured", []engine.InspecResult{res("passed", rt, "")}, nil, model.Pass, model.RuntimeOnly, "proven/not_measured/not_measured", ""},
		{"live-only check declared runtime", []engine.InspecResult{res("passed", "listening sockets exposes only the allowed ports (22)", "")}, nil, model.Pass, model.RuntimeOnly, "proven/not_measured/not_measured", KindRuntime},
		{"transient state: reboot not applicable", []engine.InspecResult{res("passed", "updates (apt) processes_with_deleted_libs is expected to be empty", "")}, nil, model.Pass, model.Durable, "proven/not_measured/n/a", KindTransient},
		{"runtime paired with durable config", []engine.InspecResult{res("passed", "systemd unit ctrl-alt-del.target runtime_active is expected to cmp == false", ""), res("passed", "systemd unit ctrl-alt-del.target is masked", "")}, nil, model.Pass, model.Durable, "proven/proven/expected", KindConfig},
		{"persistent only (no systemd)", []engine.InspecResult{res("passed", ps, "")}, nil, model.Pass, model.Durable, "not_measured/proven/expected", ""},
		{"pending", []engine.InspecResult{res("failed", rt, "expected: 2 got: 0"), res("passed", ps, "")}, nil, model.Fail, model.Pending, "failed/proven/expected", ""},
		{"a config failure is never pending", []engine.InspecResult{res("failed", rt, "expected: 2 got: 0"), res("passed", ps, ""), res("failed", eff, "x")}, nil, model.Fail, "", "failed/failed/failed", ""},
		{"absent live value is not pending", []engine.InspecResult{res("failed", rt, "expected: 1 got:"), res("passed", ps, "")}, nil, model.Fail, "", "", ""},
		{"both wrong", []engine.InspecResult{res("failed", rt, "x"), res("failed", ps, "y")}, nil, model.Fail, "", "", ""},
		{"persistent-only check failing is a failure", []engine.InspecResult{res("failed", ps, "x")}, nil, model.Fail, "", "", ""},
		{"effective failure", []engine.InspecResult{res("failed", eff, "x")}, nil, model.Fail, "", "", ""},
		{"effective pass", []engine.InspecResult{res("passed", eff, "")}, nil, model.Pass, model.Durable, "", ""},
		{"skipped", []engine.InspecResult{{Status: "skipped", CodeDesc: "No-op", SkipMessage: "Skipped control due to only_if condition: sshd is not installed"}}, nil, model.Skip, "", "", ""},
		{"exception is an error", []engine.InspecResult{{Status: "failed", CodeDesc: "x", Exception: "RuntimeError", Message: "boom"}}, nil, model.Error, "", "", ""},
		{"resource skipped exception is a skip", []engine.InspecResult{{Status: "failed", CodeDesc: "x", Exception: "Inspec::Exceptions::ResourceSkipped", Message: "n/a"}}, nil, model.Skip, "", "", ""},
		{"no results", nil, nil, model.Skip, "", "", ""},
		{"waived", []engine.InspecResult{{Status: "skipped"}}, map[string]any{"justification": "accepted", "run": false, "skipped_due_to_waiver": true}, model.Waived, "", "", ""},
		{"expired waiver runs normally", []engine.InspecResult{res("failed", eff, "x")}, map[string]any{"justification": "old", "message": "Waiver expired on 2020-01-01, evaluating control normally", "skipped_due_to_waiver": false}, model.Fail, "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Classify(engine.InspecControl{ID: "SA-00.00", Results: c.results, WaiverData: c.waiver}, c.decl)
			if r.Status != c.status || r.Qualifier != c.qual {
				t.Fatalf("got %s/%s, want %s/%s", r.Status, r.Qualifier, c.status, c.qual)
			}
			if c.proof != "" {
				if r.Proof == nil {
					t.Fatalf("no proof, want %s", c.proof)
				}
				if got := r.Proof.Now + "/" + r.Proof.OnDisk + "/" + r.Proof.Reboot; got != c.proof {
					t.Fatalf("proof %s, want %s", got, c.proof)
				}
			}
		})
	}
}

func TestCleanMessage(t *testing.T) {
	cases := map[string]string{
		"\nexpected: 2\n     got: 1\n\n(compared using `cmp` matcher)\n": "found 1 · expected 2",
		"\nexpected: 2\n     got: \n\n(compared using `cmp` matcher)\n":  "found (unset) · expected 2",
		"expected `[\"a\", \"b\"].empty?` to be truthy, got false":       `found: "a", "b"`,
		"expected `[].empty?` to be falsey, got true":                    "found: none",
		// The two messages that read backwards before.
		"expected `prohibit-password` to be in the list: `[\"no\"]`":                                                                    "found prohibit-password · expected no",
		"expected `yes` to be in the list: `[\"no\"]`":                                                                                  "found yes · expected no",
		"expected `SYSLOG` to be in the list: `[\"email\", \"exec\", \"single\", \"halt\", \"EMAIL\", \"EXEC\", \"SINGLE\", \"HALT\"]`": "found SYSLOG · expected one of email, exec, single, halt",
		"expected `none` not to be in the list: `[\"none\", \"\"]`":                                                                     "found none · expected anything but none, (empty)",
		"expected it to be >= 14 got: (unset)":                                                                                          "found (unset) · expected >= 14",
		"expected it to be <= 4 got: 6":                                                                                                 "found 6 · expected <= 4",
		"expected it not to be == \"none\" got: none":                                                                                   "found none · expected anything but none",
		"expected: not nil got: nil":                                                                                                    "found none",
		"expected: [] got: [\"tcp 0.0.0.0:2025\"]":                                                                                      `found: "tcp 0.0.0.0:2025"`,
		"expected 120 to be between 1 and 60 (inclusive)":                                                                               "found 120 · expected between 1 and 60",
		"expected \"022\" to mask at least 027":                                                                                         "found umask 022 · expected 027 or stricter",
		"expected [\"pam_rootok.so\", \"pam_unix.so\"] to include \"pam_wheel.so\"":                                                     "missing pam_wheel.so · found pam_rootok.so, pam_unix.so",
		"expected [\"rw\", \"nosuid\"] to include \"nodev\", \"nosuid\", and \"noexec\"":                                                "missing nodev, noexec · found rw, nosuid",
		"expected File /etc/cron.allow to exist":                                                                                        "/etc/cron.allow does not exist",
		"expected -1 to be between 0 and 45 (inclusive)":                                                                                "found -1 · expected between 0 and 45",
		"no usable local dnf metadata cache":                                                                                            "no usable local dnf metadata cache",
	}
	for in, want := range cases {
		if got := CleanMessage(in); got != want {
			t.Errorf("CleanMessage(%q) = %q, want %q", in, got, want)
		}
	}
}
