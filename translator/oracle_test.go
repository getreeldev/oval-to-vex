package translator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getreeldev/oval-to-vex/oval"
)

func TestFromOracleOVAL_Fixture(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "testdata", "oracle-ol9-sample.oval.xml"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	stmts, err := FromOracleOVAL(f)
	if err != nil {
		t.Fatalf("FromOracleOVAL: %v", err)
	}

	// Fixture:
	//   def 1 (ELSA multi-platform OL8+OL9): bpftool + kernel-uek, 2 CVEs,
	//     emitted per platform = 2 pkgs × 2 CVEs × 2 platforms = 8. Each
	//     package version test is referenced under BOTH an aarch64 and an
	//     x86_64 branch (as in real Oracle data); the walk must dedupe on
	//     (name, evr) so this stays 8, not 16.
	//   def 2 (glibc, OL9 only): stock glibc survives, ksplice variant
	//     filtered, 1 CVE = 1.
	//   Signature + arch + "ksplice-based" tests must not emit. Total = 9.
	if len(stmts) != 9 {
		t.Fatalf("expected 9 statements, got %d: %+v", len(stmts), stmts)
	}

	// No duplicate (CVE, ProductID): the per-arch criteria-tree repetition
	// must be collapsed.
	seenPair := make(map[[2]string]struct{})
	for _, s := range stmts {
		key := [2]string{s.CVE, s.ProductID}
		if _, dup := seenPair[key]; dup {
			t.Errorf("duplicate statement (CVE=%s, ProductID=%s) — per-arch refs not deduped", s.CVE, s.ProductID)
		}
		seenPair[key] = struct{}{}
	}

	for i, s := range stmts {
		if !strings.HasPrefix(s.CVE, "CVE-") {
			t.Errorf("stmt %d: CVE %q does not start with CVE-", i, s.CVE)
		}
		if s.IDType != "purl" {
			t.Errorf("stmt %d: IDType %q, want purl", i, s.IDType)
		}
		if s.Vendor != "oracle" {
			t.Errorf("stmt %d: Vendor %q, want oracle", i, s.Vendor)
		}
		if s.Status != "fixed" {
			t.Errorf("stmt %d: Status %q, want fixed", i, s.Status)
		}
		if s.BaseID != s.ProductID {
			t.Errorf("stmt %d: BaseID (%q) must equal ProductID (%q)", i, s.BaseID, s.ProductID)
		}
		if !strings.HasPrefix(s.ProductID, "pkg:rpm/oracle/") {
			t.Errorf("stmt %d: ProductID %q is not a pkg:rpm/oracle PURL", i, s.ProductID)
		}
	}

	// A multi-platform ELSA must emit per platform: the OL9 distro qualifier
	// must be present.
	var sawOL9, sawOL8 bool
	for _, s := range stmts {
		if strings.Contains(s.ProductID, "?distro=oracle-9") {
			sawOL9 = true
		}
		if strings.Contains(s.ProductID, "?distro=oracle-8") {
			sawOL8 = true
		}
	}
	if !sawOL9 {
		t.Error("no statement carrying distro=oracle-9")
	}
	if !sawOL8 {
		t.Error("multi-platform ELSA did not emit the OL8 rows (distro=oracle-8)")
	}

	// Known (CVE, package, evr) tuple with epoch preserved. kernel-uek was
	// gated by a signature test — its presence proves the signature filter
	// works on evr, not the object.
	const wantEVR = "0:5.15.0-321.202.5.el8uek"
	wantID := "pkg:rpm/oracle/kernel-uek?distro=oracle-9"
	var foundKernel bool
	for _, s := range stmts {
		if s.CVE == "CVE-2025-54518" && s.ProductID == wantID {
			foundKernel = true
			if s.Version != wantEVR {
				t.Errorf("%q: version %q, want %q (epoch must be preserved)", wantID, s.Version, wantEVR)
			}
		}
	}
	if !foundKernel {
		t.Errorf("missing expected statement for CVE-2025-54518 / %q", wantID)
	}

	// Stock glibc must survive; its ksplice sibling must be skipped. No
	// statement may carry a ksplice evr.
	var foundStockGlibc bool
	for _, s := range stmts {
		if strings.HasPrefix(s.ProductID, "pkg:rpm/oracle/glibc?") {
			foundStockGlibc = true
			if s.Version != "2:2.34-231.0.1.el9_7.10" {
				t.Errorf("glibc statement got version %q, want the stock (non-ksplice) evr", s.Version)
			}
		}
		if strings.Contains(s.Version, "ksplice") {
			t.Errorf("statement %+v carries a ksplice evr — ksplice variant not filtered", s)
		}
	}
	if !foundStockGlibc {
		t.Error("missing stock glibc statement (only the ksplice variant survived?)")
	}
}

func TestExtractOracleVersions(t *testing.T) {
	cases := []struct {
		platforms []string
		want      []string
	}{
		{[]string{"Oracle Linux 9"}, []string{"9"}},
		{[]string{"Oracle Linux 8", "Oracle Linux 9"}, []string{"8", "9"}},
		{[]string{"Oracle Linux 7"}, []string{"7"}},
		{[]string{"Debian GNU/Linux 12"}, nil},
		{[]string{}, nil},
		// Dedupe identical platforms.
		{[]string{"Oracle Linux 9", "Oracle Linux 9"}, []string{"9"}},
	}
	for _, tc := range cases {
		got := extractOracleVersions(tc.platforms)
		if len(got) != len(tc.want) {
			t.Errorf("extractOracleVersions(%v) = %v, want %v", tc.platforms, got, tc.want)
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("extractOracleVersions(%v)[%d] = %q, want %q", tc.platforms, i, got[i], tc.want[i])
			}
		}
	}
}

func TestFromOracleDocument_SkipsUnknownPlatform(t *testing.T) {
	doc := &oval.RpminfoDocument{
		Definitions: oval.RpminfoDefinitions{
			Definitions: []oval.RpminfoDefinition{
				{
					ID:    "oval:com.oracle.elsa:def:1",
					Class: "patch",
					Metadata: oval.RpminfoMetadata{
						Affected:   oval.Affected{Platforms: []string{"Something Else 9"}},
						References: []oval.Reference{{RefID: "CVE-2024-1", Source: "CVE"}},
					},
				},
			},
		},
	}
	if got := fromOracleDocument(doc); len(got) != 0 {
		t.Errorf("expected 0 statements for unknown platform, got %d", len(got))
	}
}

func TestCollectRpminfoCVEs_Dedupes(t *testing.T) {
	def := &oval.RpminfoDefinition{
		Metadata: oval.RpminfoMetadata{
			References: []oval.Reference{
				{RefID: "CVE-2024-1", Source: "CVE"},
				{RefID: "ELSA-2024-1", Source: "elsa"},
				{RefID: "CVE-2024-2", Source: "CVE"},
			},
			Advisory: oval.RpminfoAdvisory{
				CVEs: []oval.RpminfoCVE{
					{ID: "CVE-2024-1"}, // dup of the reference
					{ID: "CVE-2024-3"},
				},
			},
		},
	}
	got := collectRpminfoCVEs(def)
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
