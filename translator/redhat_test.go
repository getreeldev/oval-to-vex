package translator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getreeldev/oval-to-vex/oval"
)

func TestFromRedHatOVAL_Fixture(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "testdata", "rhel-9.6-eus-sample.oval.xml"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	stmts, err := FromRedHatOVAL(f)
	if err != nil {
		t.Fatalf("FromRedHatOVAL: %v", err)
	}
	if len(stmts) == 0 {
		t.Fatal("expected statements from fixture, got none")
	}

	// Every statement keeps invariants.
	for i, s := range stmts {
		if !strings.HasPrefix(s.CVE, "CVE-") {
			t.Errorf("stmt %d: CVE %q does not start with CVE-", i, s.CVE)
		}
		if s.IDType != "cpe" {
			t.Errorf("stmt %d: IDType %q, want cpe", i, s.IDType)
		}
		if s.Vendor != "redhat" {
			t.Errorf("stmt %d: Vendor %q, want redhat", i, s.Vendor)
		}
		if s.Status != "fixed" && s.Status != "affected" {
			t.Errorf("stmt %d: Status %q, want fixed or affected", i, s.Status)
		}
	}

	// SECDATA-1181 check: the EUS CPEs CSAF omits must be present here.
	// The fixture is rhel-9.6-eus; it should produce at least these two
	// stream-suffix CPEs that CSAF does not.
	required := []string{
		"cpe:/a:redhat:rhel_eus:9.6::appstream",
		"cpe:/a:redhat:rhel_eus:9.6::sap_hana",
	}
	for _, want := range required {
		var found bool
		for _, s := range stmts {
			if s.ProductID == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected statement for %q from EUS fixture; absence breaks the SECDATA-1181 use case", want)
		}
	}
}

func TestStatusForClass(t *testing.T) {
	cases := []struct {
		class string
		want  string
		ok    bool
	}{
		{"patch", "fixed", true},
		{"vulnerability", "affected", true},
		{"compliance", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := statusForClass(tc.class)
		if got != tc.want || ok != tc.ok {
			t.Errorf("statusForClass(%q) = (%q, %v), want (%q, %v)", tc.class, got, ok, tc.want, tc.ok)
		}
	}
}

func TestCollectRedHatCVEs_Dedupes(t *testing.T) {
	def := &oval.RedHatDefinition{
		Metadata: oval.RedHatMetadata{
			References: []oval.Reference{
				{RefID: "CVE-2024-1", Source: "CVE"},
				{RefID: "RHSA-2024:1234", Source: "RHSA"},
				{RefID: "CVE-2024-2", Source: "CVE"},
			},
			Advisory: oval.RedHatAdvisory{
				CVEs: []oval.RedHatCVE{
					{ID: "CVE-2024-1"}, // dup
					{ID: "CVE-2024-3"},
				},
			},
		},
	}
	got := collectRedHatCVEs(def)
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

func TestFromRedHatDocument_EmptyAdvisorySkipped(t *testing.T) {
	doc := &oval.RedHatDocument{
		Definitions: oval.RedHatDefinitions{
			Definitions: []oval.RedHatDefinition{
				{
					ID:       "oval:x:def:1",
					Class:    "patch",
					Metadata: oval.RedHatMetadata{
						// No CVE references, no CPEs.
					},
				},
			},
		},
	}
	stmts := fromRedHatDocument(doc)
	if len(stmts) != 0 {
		t.Errorf("expected 0 statements for advisory with no CVEs/CPEs, got %d", len(stmts))
	}
}
