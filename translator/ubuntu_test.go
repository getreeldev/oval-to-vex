package translator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getreeldev/oval-to-vex/oval"
)

func TestFromUbuntuOVAL_Fixture(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "testdata", "ubuntu-noble-sample.oval.xml"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	stmts, err := FromUbuntuOVAL(f)
	if err != nil {
		t.Fatalf("FromUbuntuOVAL: %v", err)
	}

	// Fixture has three definitions: inventory (skipped), USN-6663-3 (skipped:
	// no CVE refs), USN-6673-3 (1 CVE × 2 packages → 2 statements).
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements (USN-6673-3: 1 CVE × 2 packages), got %d", len(stmts))
	}

	// Every statement must have the expected invariants.
	for i, s := range stmts {
		if s.CVE != "CVE-2024-26130" {
			t.Errorf("stmt %d: CVE %q, want CVE-2024-26130", i, s.CVE)
		}
		if s.IDType != "purl" {
			t.Errorf("stmt %d: IDType %q, want purl", i, s.IDType)
		}
		if s.Vendor != "ubuntu" {
			t.Errorf("stmt %d: Vendor %q, want ubuntu", i, s.Vendor)
		}
		if s.Status != "fixed" {
			t.Errorf("stmt %d: Status %q, want fixed", i, s.Status)
		}
		if s.Version != "0:41.0.7-4ubuntu0.1" {
			t.Errorf("stmt %d: Version %q, want 0:41.0.7-4ubuntu0.1", i, s.Version)
		}
		if !strings.HasPrefix(s.ProductID, "pkg:deb/ubuntu/") {
			t.Errorf("stmt %d: ProductID %q must start with pkg:deb/ubuntu/", i, s.ProductID)
		}
		if !strings.Contains(s.ProductID, "?distro=ubuntu-24.04") {
			t.Errorf("stmt %d: ProductID %q must carry distro=ubuntu-24.04", i, s.ProductID)
		}
		if s.BaseID != s.ProductID {
			t.Errorf("stmt %d: BaseID (%q) must equal ProductID (%q) — distro is part of identity", i, s.BaseID, s.ProductID)
		}
	}

	// Both expected packages must be present.
	wantPkgs := map[string]bool{
		"pkg:deb/ubuntu/python3-cryptography?distro=ubuntu-24.04":    false,
		"pkg:deb/ubuntu/python-cryptography-doc?distro=ubuntu-24.04": false,
	}
	for _, s := range stmts {
		if _, ok := wantPkgs[s.ProductID]; ok {
			wantPkgs[s.ProductID] = true
		}
	}
	for pkg, found := range wantPkgs {
		if !found {
			t.Errorf("missing statement for package %q", pkg)
		}
	}
}

func TestFromUbuntuOVAL_SkipsClassNotPatch(t *testing.T) {
	doc := &oval.UbuntuDocument{
		Definitions: oval.UbuntuDefinitions{
			Definitions: []oval.UbuntuDefinition{
				{
					ID:    "oval:com.ubuntu.noble:def:1",
					Class: "inventory",
					Metadata: oval.UbuntuMetadata{
						References: []oval.Reference{{RefID: "CVE-2024-1", Source: "CVE"}},
					},
				},
			},
		},
	}
	if got := fromUbuntuDocument(doc); len(got) != 0 {
		t.Errorf("expected 0 statements for non-patch class, got %d", len(got))
	}
}

func TestFromUbuntuOVAL_SkipsUnknownCodename(t *testing.T) {
	doc := &oval.UbuntuDocument{
		Definitions: oval.UbuntuDefinitions{
			Definitions: []oval.UbuntuDefinition{
				{
					ID:    "oval:com.ubuntu.zesty:def:1",
					Class: "patch",
					Metadata: oval.UbuntuMetadata{
						References: []oval.Reference{{RefID: "CVE-2024-1", Source: "CVE"}},
					},
				},
			},
		},
	}
	if got := fromUbuntuDocument(doc); len(got) != 0 {
		t.Errorf("expected 0 statements for unknown codename, got %d", len(got))
	}
}

func TestExtractUbuntuCodename(t *testing.T) {
	cases := []struct {
		id   string
		want string
	}{
		{"oval:com.ubuntu.noble:def:66633000000", "noble"},
		{"oval:com.ubuntu.jammy:tst:1", "jammy"},
		{"oval:com.ubuntu.focal:obj:1", "focal"},
		{"oval:redhat:def:1", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := extractUbuntuCodename(tc.id); got != tc.want {
			t.Errorf("extractUbuntuCodename(%q) = %q, want %q", tc.id, got, tc.want)
		}
	}
}

func TestCollectTestRefs_NestedCriteria(t *testing.T) {
	c := &oval.UbuntuCriteria{
		Criterions: []oval.UbuntuCriterion{{TestRef: "tst:1"}},
		Criteria: []oval.UbuntuCriteria{
			{
				Criterions: []oval.UbuntuCriterion{{TestRef: "tst:2"}, {TestRef: "tst:3"}},
				Criteria: []oval.UbuntuCriteria{
					{Criterions: []oval.UbuntuCriterion{{TestRef: "tst:4"}}},
				},
			},
		},
	}
	got := collectTestRefs(c)
	want := []string{"tst:1", "tst:2", "tst:3", "tst:4"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCollectUbuntuCVEs_Dedupes(t *testing.T) {
	def := &oval.UbuntuDefinition{
		Metadata: oval.UbuntuMetadata{
			References: []oval.Reference{
				{RefID: "CVE-2024-1", Source: "CVE"},
				{RefID: "USN-1234-1", Source: "USN"},
				{RefID: "CVE-2024-2", Source: "CVE"},
			},
			Advisory: oval.UbuntuAdvisory{
				CVEs: []oval.UbuntuCVE{
					{ID: "CVE-2024-1"}, // dup
					{ID: "CVE-2024-3"},
				},
			},
		},
	}
	got := collectUbuntuCVEs(def)
	want := []string{"CVE-2024-1", "CVE-2024-2", "CVE-2024-3"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: got %q, want %q", i, got[i], want[i])
		}
	}
}
