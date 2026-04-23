package translator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getreeldev/oval-to-vex/oval"
)

func TestFromDebianOVAL_Fixture(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "testdata", "debian-bookworm-sample.oval.xml"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	stmts, err := FromDebianOVAL(f)
	if err != nil {
		t.Fatalf("FromDebianOVAL: %v", err)
	}

	// Fixture has 4 definitions:
	//   1. CVE-2021-44228 on apache-log4j2 (vulnerability + fix) → 1 statement
	//   2. DSA-5000-1 / CVE-2022-0778 on openssl (patch + fix)    → 1 statement
	//   3. CVE-2026-0001 unfixed (no dpkginfo test resolvable)    → skipped
	//   4. CVE-2026-0002 unrecognized platform                    → skipped
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d: %+v", len(stmts), stmts)
	}

	for i, s := range stmts {
		if !strings.HasPrefix(s.CVE, "CVE-") {
			t.Errorf("stmt %d: CVE %q does not start with CVE-", i, s.CVE)
		}
		if s.IDType != "purl" {
			t.Errorf("stmt %d: IDType %q, want purl", i, s.IDType)
		}
		if s.Vendor != "debian" {
			t.Errorf("stmt %d: Vendor %q, want debian", i, s.Vendor)
		}
		if s.Status != "fixed" {
			t.Errorf("stmt %d: Status %q, want fixed", i, s.Status)
		}
		if !strings.Contains(s.ProductID, "?distro=debian-12") {
			t.Errorf("stmt %d: ProductID %q must carry distro=debian-12", i, s.ProductID)
		}
		if s.BaseID != s.ProductID {
			t.Errorf("stmt %d: BaseID (%q) must equal ProductID (%q)", i, s.BaseID, s.ProductID)
		}
	}

	// Both expected packages must be present with their fix versions.
	wantByPackage := map[string]string{
		"pkg:deb/debian/apache-log4j2?distro=debian-12": "0:2.15.0-1",
		"pkg:deb/debian/openssl?distro=debian-12":       "0:3.0.2-2",
	}
	got := make(map[string]string, len(stmts))
	for _, s := range stmts {
		got[s.ProductID] = s.Version
	}
	for pkg, wantVer := range wantByPackage {
		gotVer, ok := got[pkg]
		if !ok {
			t.Errorf("missing statement for %q", pkg)
			continue
		}
		if gotVer != wantVer {
			t.Errorf("%q: got version %q, want %q", pkg, gotVer, wantVer)
		}
	}
}

func TestFromDebianOVAL_SkipsUnknownPlatform(t *testing.T) {
	doc := &oval.DebianDocument{
		Definitions: oval.DebianDefinitions{
			Definitions: []oval.DebianDefinition{
				{
					ID:    "oval:org.debian:def:1",
					Class: "vulnerability",
					Metadata: oval.DebianMetadata{
						Affected:   oval.Affected{Platforms: []string{"Debian SomethingElse"}},
						References: []oval.Reference{{RefID: "CVE-2024-1", Source: "CVE"}},
					},
				},
			},
		},
	}
	if got := fromDebianDocument(doc); len(got) != 0 {
		t.Errorf("expected 0 statements for unknown platform, got %d", len(got))
	}
}

func TestFromDebianOVAL_SkipsInventoryClass(t *testing.T) {
	doc := &oval.DebianDocument{
		Definitions: oval.DebianDefinitions{
			Definitions: []oval.DebianDefinition{
				{
					ID:    "oval:org.debian:def:1",
					Class: "inventory",
					Metadata: oval.DebianMetadata{
						Affected:   oval.Affected{Platforms: []string{"Debian GNU/Linux 12"}},
						References: []oval.Reference{{RefID: "CVE-2024-1", Source: "CVE"}},
					},
				},
			},
		},
	}
	if got := fromDebianDocument(doc); len(got) != 0 {
		t.Errorf("expected 0 statements for inventory class, got %d", len(got))
	}
}

func TestExtractDebianVersion(t *testing.T) {
	cases := []struct {
		platforms []string
		want      string
	}{
		{[]string{"Debian GNU/Linux 12"}, "12"},
		{[]string{"Debian GNU/Linux 11"}, "11"},
		{[]string{"Debian GNU/Linux 13"}, "13"},
		{[]string{"Ubuntu 24.04"}, ""},
		{[]string{}, ""},
		{[]string{"Debian SomethingElse", "Debian GNU/Linux 12"}, "12"},
	}
	for _, tc := range cases {
		if got := extractDebianVersion(tc.platforms); got != tc.want {
			t.Errorf("extractDebianVersion(%v) = %q, want %q", tc.platforms, got, tc.want)
		}
	}
}

func TestCollectDebianCVEs_Dedupes(t *testing.T) {
	def := &oval.DebianDefinition{
		Metadata: oval.DebianMetadata{
			References: []oval.Reference{
				{RefID: "CVE-2024-1", Source: "CVE"},
				{RefID: "DSA-5000", Source: "DSA"},
				{RefID: "CVE-2024-2", Source: "CVE"},
				{RefID: "CVE-2024-1", Source: "CVE"}, // dup
			},
		},
	}
	got := collectDebianCVEs(def)
	want := []string{"CVE-2024-1", "CVE-2024-2"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: got %q, want %q", i, got[i], want[i])
		}
	}
}
