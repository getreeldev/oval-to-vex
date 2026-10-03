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
	//   1. CVE-2021-44228 on apache-log4j2 (vulnerability + fix) → 1 fixed statement
	//   2. DSA-5000-1 / CVE-2022-0778 on openssl (patch + fix)    → 1 fixed statement
	//   3. CVE-2026-0001 on curl (vulnerability + no test)        → 1 affected statement
	//   4. CVE-2026-0002 unrecognized platform                    → skipped
	if len(stmts) != 3 {
		t.Fatalf("expected 3 statements, got %d: %+v", len(stmts), stmts)
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
		if s.Status != "fixed" && s.Status != "affected" {
			t.Errorf("stmt %d: Status %q, want fixed or affected", i, s.Status)
		}
		if !strings.Contains(s.ProductID, "?distro=debian-12") {
			t.Errorf("stmt %d: ProductID %q must carry distro=debian-12", i, s.ProductID)
		}
		if s.BaseID != s.ProductID {
			t.Errorf("stmt %d: BaseID (%q) must equal ProductID (%q)", i, s.BaseID, s.ProductID)
		}
	}

	// Expected: two fixed statements (with versions) and one affected (no version).
	wantFixed := map[string]string{
		"pkg:deb/debian/apache-log4j2?distro=debian-12": "0:2.15.0-1",
		"pkg:deb/debian/openssl?distro=debian-12":       "0:3.0.2-2",
	}
	wantAffected := "pkg:deb/debian/curl?distro=debian-12"
	var sawAffected bool
	for _, s := range stmts {
		switch s.Status {
		case "fixed":
			wantVer, ok := wantFixed[s.ProductID]
			if !ok {
				t.Errorf("unexpected fixed statement for %q", s.ProductID)
				continue
			}
			if s.Version != wantVer {
				t.Errorf("%q: got version %q, want %q", s.ProductID, s.Version, wantVer)
			}
			delete(wantFixed, s.ProductID)
		case "affected":
			if s.ProductID != wantAffected {
				t.Errorf("affected: got %q, want %q", s.ProductID, wantAffected)
			}
			if s.Version != "" {
				t.Errorf("affected statements must have empty version, got %q", s.Version)
			}
			if s.CVE != "CVE-2026-0001" {
				t.Errorf("affected CVE: got %q, want CVE-2026-0001", s.CVE)
			}
			sawAffected = true
		}
	}
	for missing := range wantFixed {
		t.Errorf("missing fixed statement for %q", missing)
	}
	if !sawAffected {
		t.Errorf("missing affected statement for unpatched-CVE definition")
	}
}

// TestFromDebianOVAL_OpenBoundIsAffected uses the live bookworm record for
// CVE-2016-5416 in 389-ds-base, open per the Debian tracker. Debian encodes
// "no fix yet" as a bound of 0:0; that is an affected package, not one fixed
// at version 0:0.
func TestFromDebianOVAL_OpenBoundIsAffected(t *testing.T) {
	const doc = `<?xml version='1.0' encoding='UTF-8'?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <definitions>
    <definition id="oval:org.debian:def:308370225544215691963860905694509241784" version="1" class="vulnerability">
      <metadata>
        <title>CVE-2016-5416 389-ds-base</title>
        <affected family="unix">
          <platform>Debian GNU/Linux 12</platform>
          <product>389-ds-base</product>
        </affected>
        <reference source="CVE" ref_id="CVE-2016-5416" ref_url="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5416"/>
      </metadata>
      <criteria comment="Release section" operator="AND">
        <criterion test_ref="oval:org.debian.oval:tst:1" comment="Debian 12 is installed"/>
        <criteria comment="Architecture section" operator="OR">
          <criteria comment="Architecture independent section" operator="AND">
            <criterion test_ref="oval:org.debian.oval:tst:2" comment="all architecture"/>
            <criterion test_ref="oval:org.debian.oval:tst:9326" comment="389-ds-base DPKG is earlier than 0"/>
          </criteria>
        </criteria>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <dpkginfo_test id="oval:org.debian.oval:tst:9326" version="1" check="all" check_existence="at_least_one_exists" comment="389-ds-base is earlier than 0" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <object object_ref="oval:org.debian.oval:obj:1062"/>
      <state state_ref="oval:org.debian.oval:ste:7151"/>
    </dpkginfo_test>
  </tests>
  <objects>
    <dpkginfo_object id="oval:org.debian.oval:obj:1062" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <name>389-ds-base</name>
    </dpkginfo_object>
  </objects>
  <states>
    <dpkginfo_state id="oval:org.debian.oval:ste:7151" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <evr datatype="debian_evr_string" operation="less than">0:0</evr>
    </dpkginfo_state>
  </states>
</oval_definitions>`

	stmts, err := FromDebianOVAL(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("FromDebianOVAL: %v", err)
	}
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d: %+v", len(stmts), stmts)
	}
	s := stmts[0]
	if s.CVE != "CVE-2016-5416" || s.ProductID != "pkg:deb/debian/389-ds-base?distro=debian-12" {
		t.Errorf("got (%s, %s), want (CVE-2016-5416, pkg:deb/debian/389-ds-base?distro=debian-12)", s.CVE, s.ProductID)
	}
	if s.Status != "affected" {
		t.Errorf("status %q, want affected (a 0:0 bound means no fix exists)", s.Status)
	}
	if s.Version != "" {
		t.Errorf("version %q, want empty (0:0 is not a fix version)", s.Version)
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
