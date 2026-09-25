package catalog_test

import (
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"

	shadowarmor "github.com/Shadow-Security-official/Shadow-Armor"
	"github.com/Shadow-Security-official/Shadow-Armor/internal/catalog"
)

func load(t *testing.T) *catalog.Catalog {
	t.Helper()
	c, err := catalog.Load(shadowarmor.Profile)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var (
	idRe      = regexp.MustCompile(`^SA-(0[1-9]|1[0-2])\.\d{2}$`)
	nistRe    = regexp.MustCompile(`^[A-Z]{2}-\d{1,2}(\(\d{1,2}\))*(\([a-z]\))?$`)
	nist171Re = regexp.MustCompile(`^3\.\d{1,2}\.\d{1,2}$`)
	pciRe     = regexp.MustCompile(`^\d{1,2}(\.\d{1,2}){1,3}$`)
	stigRe    = regexp.MustCompile(`^SRG-OS-\d{6}-GPOS-\d{5}$`)
	anssiRe   = regexp.MustCompile(`^R\d{1,2}$`)
	cisRe     = regexp.MustCompile(`^\d{1,2}\.\d{1,2}$`)
)

// Every control: well-formed id, pillar 1-12, known severity, level 1-2,
// at least one mapping, a rationale, a probe description, a remediation.
func TestCatalogIntegrity(t *testing.T) {
	c := load(t)
	if len(c.Pillars) != 12 {
		t.Fatalf("want 12 pillars, got %d", len(c.Pillars))
	}
	perPillar := map[int]int{}
	for _, ctl := range c.Controls {
		perPillar[ctl.Pillar]++
		if !idRe.MatchString(ctl.ID) {
			t.Errorf("%s: malformed id", ctl.ID)
		}
		if want := ctl.ID[3:5]; want != twoDigits(ctl.Pillar) {
			t.Errorf("%s: id says pillar %s but pillar is %d", ctl.ID, want, ctl.Pillar)
		}
		if _, ok := c.SeverityWeights[ctl.Severity]; !ok {
			t.Errorf("%s: unknown severity %q", ctl.ID, ctl.Severity)
		}
		if ctl.Level != 1 && ctl.Level != 2 {
			t.Errorf("%s: level %d", ctl.ID, ctl.Level)
		}
		if len(ctl.Evidence) == 0 {
			t.Errorf("%s: no evidence kinds", ctl.ID)
		}
		for _, k := range ctl.Evidence {
			if !contains(catalog.EvidenceKinds, k) {
				t.Errorf("%s: unknown evidence kind %q (%s)", ctl.ID, k, strings.Join(catalog.EvidenceKinds, ", "))
			}
		}
		if ctl.Scope != "host" && ctl.Scope != "any" {
			t.Errorf("%s: scope %q", ctl.ID, ctl.Scope)
		}
		if ctl.Rationale == "" || ctl.Check == "" || ctl.Remediation.Summary == "" {
			t.Errorf("%s: missing rationale, check or remediation summary", ctl.ID)
		}
		if ctl.Remediation.Auto && len(ctl.Remediation.Actions) == 0 {
			t.Errorf("%s: automatic remediation without actions", ctl.ID)
		}
		if !ctl.Remediation.Auto && ctl.Remediation.Manual == "" {
			t.Errorf("%s: manual remediation without guidance", ctl.ID)
		}
		n := 0
		for _, k := range catalog.StandardKeys {
			n += len(ctl.Map.Refs(k))
		}
		if n == 0 {
			t.Errorf("%s: no standard mapping", ctl.ID)
		}
		check := func(std string, re *regexp.Regexp, refs []string) {
			for _, r := range refs {
				if !re.MatchString(r) {
					t.Errorf("%s: malformed %s reference %q", ctl.ID, std, r)
				}
			}
		}
		check("NIST 800-53", nistRe, ctl.Map.NIST)
		check("NIST 800-171", nist171Re, ctl.Map.NIST171)
		check("PCI DSS", pciRe, ctl.Map.PCI)
		check("STIG SRG", stigRe, ctl.Map.STIG)
		check("ANSSI", anssiRe, ctl.Map.ANSSI)
		check("CIS Controls", cisRe, ctl.Map.CIS)
	}
	for id := 1; id <= 12; id++ {
		if perPillar[id] == 0 {
			t.Errorf("pillar %d has no control", id)
		}
	}
}

func twoDigits(n int) string {
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	return "1" + string(rune('0'+n-10))
}

// The catalog and the InSpec controls must describe exactly the same set.
func TestEveryCatalogControlHasAProbe(t *testing.T) {
	c := load(t)
	ctlRe := regexp.MustCompile(`control '(SA-\d{2}\.\d{2})'|%w\[([^\]]+)\]\.each do \|id\|`)
	found := map[string]bool{}
	err := fs.WalkDir(shadowarmor.Profile, "profile/controls", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, _ := fs.ReadFile(shadowarmor.Profile, p)
		for _, m := range ctlRe.FindAllStringSubmatch(string(raw), -1) {
			if m[1] != "" {
				found[m[1]] = true
			}
			for _, id := range strings.Fields(m[2]) {
				found[id] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ctl := range c.Controls {
		if !found[ctl.ID] {
			t.Errorf("%s is in the catalog but no control implements it", ctl.ID)
		}
		delete(found, ctl.ID)
	}
	for id := range found {
		if strings.HasPrefix(id, "SA-") {
			t.Errorf("%s is implemented but missing from the catalog", id)
		}
	}
}

// Every remediation kind used by the catalog is interpreted by the cookbook.
func TestEveryRemediationKindIsImplemented(t *testing.T) {
	c := load(t)
	recipe, err := fs.ReadFile(shadowarmor.Cookbook, "cookbook/shadow_armor/recipes/default.rb")
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string][]string{}
	for _, ctl := range c.Controls {
		for _, a := range ctl.Remediation.Actions {
			k, _ := a["kind"].(string)
			kinds[k] = append(kinds[k], ctl.ID)
		}
	}
	var names []string
	for k := range kinds {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if !strings.Contains(string(recipe), "by_kind['"+k+"']") {
			t.Errorf("remediation kind %q (used by %v) is not handled by recipes/default.rb", k, kinds[k])
		}
	}
}

// Placeholders in remediations must name declared inputs.
func TestPlaceholdersReferenceInputs(t *testing.T) {
	c := load(t)
	inputs := c.InputDefaults()
	ph := regexp.MustCompile(`\{\{\s*([a-z0-9_]+)\s*\}\}`)
	raw, _ := fs.ReadFile(shadowarmor.Profile, catalog.Path)
	for _, m := range ph.FindAllStringSubmatch(string(raw), -1) {
		if _, ok := inputs[m[1]]; !ok {
			t.Errorf("placeholder {{%s}} does not name an input", m[1])
		}
	}
}

func TestSelect(t *testing.T) {
	c := load(t)
	l1 := c.Select(catalog.Filter{Level: 1})
	all := c.Select(catalog.Filter{Level: 2})
	if len(l1) == 0 || len(l1) >= len(all) {
		t.Fatalf("level 1 = %d, level 2 = %d", len(l1), len(all))
	}
	ssh := c.Select(catalog.Filter{Pillars: []int{6}})
	for _, ctl := range ssh {
		if ctl.Pillar != 6 {
			t.Fatalf("pillar filter leaked %s", ctl.ID)
		}
	}
	stig := c.Select(catalog.Filter{Standard: "stig"})
	for _, ctl := range stig {
		if len(ctl.Map.STIG) == 0 {
			t.Fatalf("standard filter leaked %s", ctl.ID)
		}
	}
	one := c.Select(catalog.Filter{IDs: []string{"sa-06.01"}})
	if len(one) != 1 || one[0].ID != "SA-06.01" {
		t.Fatalf("id selection: %+v", one)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// The evidence kinds a control declares must match what its code asserts:
// runtime* properties <=> "runtime", persistent* <=> "persistent", and
// unprefixed assertions need a declared type (listed first). This keeps the
// proof columns of every verdict honest when a control changes.
func TestEvidenceMatchesControlCode(t *testing.T) {
	c := load(t)
	lambdaRe := regexp.MustCompile(`(?ms)^(\w+) = lambda do.*?^end$`)
	controlRe := regexp.MustCompile(`(?ms)^control '(SA-\d\d\.\d\d)' do(.*?)^end$`)
	refRe := regexp.MustCompile(`&(\w+)`)
	itsRe := regexp.MustCompile(`its\('([a-z_]+)'\)`)
	itRe := regexp.MustCompile(`\bit[\s(]['"]`)
	type kinds struct{ runtime, persistent, plain bool }
	got := map[string]kinds{}
	files, _ := fs.Glob(shadowarmor.Profile, "profile/controls/*.rb")
	for _, f := range files {
		raw, _ := fs.ReadFile(shadowarmor.Profile, f)
		src := string(raw)
		lambdas := map[string]string{}
		for _, m := range lambdaRe.FindAllStringSubmatch(src, -1) {
			lambdas[m[1]] = m[0]
		}
		for _, m := range controlRe.FindAllStringSubmatch(src, -1) {
			body := m[2]
			for _, r := range refRe.FindAllStringSubmatch(m[2], -1) {
				body += lambdas[r[1]]
			}
			var k kinds
			for _, p := range itsRe.FindAllStringSubmatch(body, -1) {
				switch {
				case strings.HasPrefix(p[1], "runtime"):
					k.runtime = true
				case strings.HasPrefix(p[1], "persistent"):
					k.persistent = true
				default:
					k.plain = true
				}
			}
			if itRe.MatchString(body) {
				k.plain = true
			}
			got[m[1]] = k
		}
	}
	for _, ctl := range c.Controls {
		k, ok := got[ctl.ID]
		if !ok {
			t.Errorf("%s: control not found in profile/controls", ctl.ID)
			continue
		}
		hasRuntime, hasPersistent := contains(ctl.Evidence, "runtime"), contains(ctl.Evidence, "persistent")
		declared := ctl.DeclaredType()
		durable := declared != "runtime" && contains(ctl.Evidence, declared)
		switch {
		case k.persistent != hasPersistent:
			t.Errorf("%s: persistent* assertions %v, evidence %v", ctl.ID, k.persistent, ctl.Evidence)
		case k.runtime && !hasRuntime:
			t.Errorf("%s: runtime* assertions but evidence %v", ctl.ID, ctl.Evidence)
		case hasRuntime && !k.runtime && (declared != "runtime" || !k.plain):
			t.Errorf("%s: evidence lists runtime but the control asserts nothing live", ctl.ID)
		case k.plain && !durable && declared != "runtime":
			t.Errorf("%s: unprefixed assertions need a declared type first in evidence %v", ctl.ID, ctl.Evidence)
		case !k.plain && durable:
			t.Errorf("%s: evidence declares %q but the control has no unprefixed assertion", ctl.ID, declared)
		}
	}
}
