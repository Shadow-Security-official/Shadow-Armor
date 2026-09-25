// Command sbom writes the CycloneDX SBOM of a Shadow-Armor release.
//
//	go run ./tools/sbom -version 0.3.0 -o dist/sdw-armor.cdx.json dist/sdw-armor-linux-* dist/sdw-armor-darwin-*
//
// It reads the Go build information of every binary (toolchain, module
// dependencies, build settings) and adds what the binary embeds: the InSpec
// profile and the Chef cookbook, each with a hash of its file tree. The
// release workflow attests the SBOM against the binaries. Standard library
// only, like sdw-armor itself.
package main

import (
	"crypto/sha1" //nolint:gosec // RFC 4122 name-based UUID (version 5) is defined with SHA-1
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	shadowarmor "github.com/Shadow-Security-official/Shadow-Armor"
)

const repo = "https://github.com/Shadow-Security-official/Shadow-Armor"

type hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type license struct {
	License struct {
		ID string `json:"id"`
	} `json:"license"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type extRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type component struct {
	BOMRef       string     `json:"bom-ref"`
	Type         string     `json:"type"`
	Name         string     `json:"name"`
	Version      string     `json:"version,omitempty"`
	Description  string     `json:"description,omitempty"`
	Licenses     []license  `json:"licenses,omitempty"`
	PURL         string     `json:"purl,omitempty"`
	Hashes       []hash     `json:"hashes,omitempty"`
	ExternalRefs []extRef   `json:"externalReferences,omitempty"`
	Properties   []property `json:"properties,omitempty"`
}

type dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type bom struct {
	BOMFormat    string `json:"bomFormat"`
	SpecVersion  string `json:"specVersion"`
	SerialNumber string `json:"serialNumber"`
	Version      int    `json:"version"`
	Metadata     struct {
		Timestamp string `json:"timestamp"`
		Tools     struct {
			Components []component `json:"components"`
		} `json:"tools"`
		Component component `json:"component"`
	} `json:"metadata"`
	Components   []component  `json:"components"`
	Dependencies []dependency `json:"dependencies"`
}

func lic(id string) []license {
	var l license
	l.License.ID = id
	return []license{l}
}

// treeHash hashes a file tree like Go's dirhash.Hash1: SHA-256 over the
// sorted lines "<sha256 of file>  <path>\n".
func treeHash(fsys fs.FS, root string) (string, int, error) {
	var lines []string
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		s := sha256.Sum256(b)
		lines = append(lines, fmt.Sprintf("%x  %s\n", s, p))
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		_, _ = io.WriteString(h, l)
	}
	return hex.EncodeToString(h.Sum(nil)), len(lines), nil
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// uuid5 is an RFC 4122 name-based UUID: the same release always gets the
// same serial number.
func uuid5(name string) string {
	ns := []byte{0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8} // URL namespace
	h := sha1.New()                                                                                              //nolint:gosec
	h.Write(ns)
	h.Write([]byte(name))
	u := h.Sum(nil)[:16]
	u[6] = (u[6] & 0x0f) | 0x50
	u[8] = (u[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

func versionOf(fsys fs.FS, file string, re *regexp.Regexp) string {
	b, err := fs.ReadFile(fsys, file)
	if err != nil {
		return ""
	}
	if m := re.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}

func main() {
	version := flag.String("version", "", "release version (without the leading v)")
	out := flag.String("o", "", "output file (default: stdout)")
	date := flag.String("date", "", "timestamp, RFC 3339 (default: $SOURCE_DATE_EPOCH or now)")
	flag.Parse()
	bins := flag.Args()
	if *version == "" || len(bins) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sbom -version X.Y.Z [-o file] binary...")
		os.Exit(2)
	}
	v := strings.TrimPrefix(*version, "v")
	ts := *date
	if ts == "" {
		t := time.Now().UTC()
		if e := os.Getenv("SOURCE_DATE_EPOCH"); e != "" {
			var sec int64
			if _, err := fmt.Sscanf(e, "%d", &sec); err == nil {
				t = time.Unix(sec, 0).UTC()
			}
		}
		ts = t.Format(time.RFC3339)
	}

	var b bom
	b.BOMFormat, b.SpecVersion, b.Version = "CycloneDX", "1.6", 1
	b.Metadata.Timestamp = ts
	b.Metadata.Tools.Components = []component{{BOMRef: "tool:shadow-armor-sbom", Type: "application", Name: "shadow-armor tools/sbom", Version: v}}
	mainRef := "pkg:golang/github.com/Shadow-Security-official/Shadow-Armor@v" + v
	b.Metadata.Component = component{
		BOMRef: mainRef, Type: "application", Name: "sdw-armor", Version: v,
		Description:  "Effective Linux compliance & hardening over CINC Auditor: a static binary embedding its InSpec profile and Chef cookbook.",
		Licenses:     lic("Apache-2.0"),
		PURL:         mainRef,
		ExternalRefs: []extRef{{Type: "vcs", URL: repo}, {Type: "website", URL: repo}},
	}

	var deps []string
	seen := map[string]bool{}
	add := func(c component) {
		if seen[c.BOMRef] {
			return
		}
		seen[c.BOMRef] = true
		b.Components = append(b.Components, c)
		deps = append(deps, c.BOMRef)
	}
	var serial []string
	for _, p := range bins {
		info, err := buildinfo.ReadFile(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sbom: %s: %v\n", p, err)
			os.Exit(1)
		}
		sum, err := fileSHA256(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sbom: %v\n", err)
			os.Exit(1)
		}
		serial = append(serial, sum)
		props := []property{{Name: "go.version", Value: info.GoVersion}}
		for _, s := range info.Settings {
			switch s.Key {
			case "GOOS", "GOARCH", "CGO_ENABLED", "-trimpath", "vcs.revision", "vcs.time", "vcs.modified":
				props = append(props, property{Name: "go.build." + s.Key, Value: s.Value})
			}
		}
		name := filepath.Base(p)
		add(component{BOMRef: "file:" + name, Type: "file", Name: name, Version: v, Hashes: []hash{{"SHA-256", sum}}, Properties: props})
		gv := strings.TrimPrefix(info.GoVersion, "go")
		add(component{BOMRef: "pkg:golang/stdlib@" + gv, Type: "library", Name: "stdlib", Version: info.GoVersion,
			Description: "Go standard library, compiled into the binary", Licenses: lic("BSD-3-Clause"), PURL: "pkg:golang/stdlib@" + gv})
		for _, d := range info.Deps {
			m := d
			if d.Replace != nil {
				m = d.Replace
			}
			ref := "pkg:golang/" + m.Path + "@" + m.Version
			c := component{BOMRef: ref, Type: "library", Name: m.Path, Version: m.Version, PURL: ref}
			if m.Sum != "" {
				c.Properties = []property{{Name: "go.sum", Value: m.Sum}}
			}
			add(c)
		}
	}
	for _, e := range []struct {
		fsys             fs.FS
		root, name, desc string
		ver              string
	}{
		{shadowarmor.Profile, "profile", "shadow-armor InSpec profile", "CINC Auditor / InSpec profile embedded in the binary: 162 controls, effective-state resources and the catalog of mappings",
			versionOf(shadowarmor.Profile, "profile/inspec.yml", regexp.MustCompile(`(?m)^version:\s*['"]?([^'"\s]+)`))},
		{shadowarmor.Cookbook, "cookbook", "shadow_armor Chef cookbook", "Chef cookbook embedded in the binary: converges the declarative remediations of sdw-armor harden",
			versionOf(shadowarmor.Cookbook, "cookbook/shadow_armor/metadata.rb", regexp.MustCompile(`(?m)^version\s+['"]([^'"]+)`))},
	} {
		sum, n, err := treeHash(e.fsys, e.root)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sbom: %v\n", err)
			os.Exit(1)
		}
		add(component{BOMRef: "embedded:" + e.root, Type: "library", Name: e.name, Version: e.ver, Description: e.desc,
			Licenses: lic("Apache-2.0"), Hashes: []hash{{"SHA-256", sum}},
			Properties: []property{{Name: "shadow-armor:tree-hash", Value: "SHA-256 over the sorted lines \"<sha256>  <path>\" of its " + fmt.Sprint(n) + " files (Go dirhash Hash1 layout)"}}})
		serial = append(serial, sum)
	}
	b.SerialNumber = "urn:uuid:" + uuid5(repo+"@v"+v+"#"+strings.Join(serial, ","))
	b.Dependencies = []dependency{{Ref: mainRef, DependsOn: deps}}
	for _, r := range deps {
		b.Dependencies = append(b.Dependencies, dependency{Ref: r, DependsOn: []string{}})
	}

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "sbom:", err)
		os.Exit(1)
	}
	data = append(data, '\n')
	if *out == "" {
		_, _ = os.Stdout.Write(data)
		return
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil { //nolint:gosec // a public release artifact
		fmt.Fprintln(os.Stderr, "sbom:", err)
		os.Exit(1)
	}
}
