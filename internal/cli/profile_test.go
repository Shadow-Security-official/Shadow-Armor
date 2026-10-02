package cli

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	shadowarmor "github.com/Shadow-Security-official/Shadow-Armor"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/catalog"
)

func testApp(t *testing.T) *app {
	t.Helper()
	cat, err := catalog.Load(shadowarmor.Profile)
	if err != nil {
		t.Fatal(err)
	}
	return &app{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, cat: cat}
}

// Without a terminal a full scan cannot guess the profile: exit 2, with the
// profiles and their example servers in the message.
func TestScanWithoutProfileOffTerminal(t *testing.T) {
	_, errOut, code := run(t, "scan", "--no-color")
	if code != 2 || !strings.Contains(errOut, "choose a scan profile with --profile") || !strings.Contains(errOut, "e.g. a production server") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
}

func TestPickProfile(t *testing.T) {
	a := testApp(t)
	cases := []struct {
		input, want string
	}{
		{"3\n", catalog.Complete},
		{"intensive\n\n1\n", catalog.Basic},
		{"Avancé\n", catalog.Advanced},
		{"advanced\n", catalog.Advanced},
	}
	for _, c := range cases {
		var w bytes.Buffer
		got, err := a.pickProfile(bufio.NewReader(strings.NewReader(c.input)), &w, catalog.Filter{Pillars: []int{6}})
		if err != nil || got != c.want {
			t.Errorf("%q: got %q, %v", c.input, got, err)
		}
		if !strings.Contains(w.String(), "e.g. a private, temporary development server") {
			t.Errorf("%q: the question must show the example servers", c.input)
		}
	}
	var w bytes.Buffer
	if _, err := a.pickProfile(bufio.NewReader(strings.NewReader("")), &w, catalog.Filter{}); err == nil {
		t.Error("end of input must not pick a profile")
	}
}

func TestProfileFromFlags(t *testing.T) {
	a := testApp(t)
	cases := []struct {
		sf   scanFlags
		want string
		bad  bool
	}{
		{scanFlags{}, "", false},
		{scanFlags{level: 1}, catalog.Advanced, false},
		{scanFlags{level: 2}, catalog.Complete, false},
		{scanFlags{profile: "Basique"}, catalog.Basic, false},
		{scanFlags{profile: "complete", level: 2}, catalog.Complete, false},
		{scanFlags{profile: "basic", level: 1}, "", true},
		{scanFlags{level: 3}, "", true},
	}
	for _, c := range cases {
		got, err := a.profileFromFlags(&c.sf)
		if (err != nil) != c.bad || got != c.want {
			t.Errorf("%+v: got %q, %v", c.sf, got, err)
		}
	}
}
