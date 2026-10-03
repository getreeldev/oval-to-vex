package translator

import (
	"os"
	"path/filepath"
	"strconv"
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
	//     one branch per release with its own versions = 2 pkgs × 2 CVEs ×
	//     2 releases = 8. Each package version test is referenced under BOTH
	//     an aarch64 and an x86_64 branch (as in real Oracle data); the walk
	//     must dedupe on (release, name, evr) so this stays 8, not 16.
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

	// A multi-release ELSA must emit per release: both distro qualifiers
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

	// Each release carries its own branch's evr, epoch preserved: OL9's
	// kernel-uek is fixed at the el9uek build, OL8's at the el8uek one.
	// kernel-uek was gated by a signature test — its presence proves the
	// signature filter works on evr, not the object.
	wantKernel := map[string]string{
		"pkg:rpm/oracle/kernel-uek?distro=oracle-9": "0:5.15.0-321.202.5.el9uek",
		"pkg:rpm/oracle/kernel-uek?distro=oracle-8": "0:5.15.0-321.202.5.el8uek",
	}
	for wantID, wantEVR := range wantKernel {
		var found bool
		for _, s := range stmts {
			if s.CVE == "CVE-2025-54518" && s.ProductID == wantID {
				found = true
				if s.Version != wantEVR {
					t.Errorf("%q: version %q, want %q (epoch must be preserved)", wantID, s.Version, wantEVR)
				}
			}
		}
		if !found {
			t.Errorf("missing expected statement for CVE-2025-54518 / %q", wantID)
		}
	}

	// No release may carry another release's build.
	for _, s := range stmts {
		release := s.ProductID[strings.Index(s.ProductID, "?distro=oracle-")+len("?distro=oracle-"):]
		if !strings.Contains(s.Version, ".el"+release) {
			t.Errorf("%s carries %q, not an el%s build", s.ProductID, s.Version, release)
		}
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

// oracleBranch is one release branch of a synthetic ELSA: the release its
// gate names ("" for a branch with no gate) and the (name, evr) version
// tests under it. A state may also carry a stream pattern (stream), as live
// version states do ("5.15.0", `^1\.26\.`).
type oracleBranch struct {
	release string
	tests   []oracleVersionTest
}

type oracleVersionTest struct {
	name, evr, stream string
}

// oracleDoc builds one ELSA definition naming every platform in platforms,
// with one AND branch per oracleBranch: the release gate (when set) beside
// an arch gate and an OR over the version tests, the shape of the live
// feed.
func oracleDoc(platforms []string, branches ...oracleBranch) *oval.RpminfoDocument {
	doc := &oval.RpminfoDocument{}
	doc.Objects.Objects = append(doc.Objects.Objects, oval.RpminfoObject{ID: "obj:release", Name: "oraclelinux-release"})
	doc.States.States = append(doc.States.States, oval.RpminfoState{ID: "ste:arch"})
	doc.Tests.Tests = append(doc.Tests.Tests, oval.RpminfoTest{ID: "tst:arch", Object: oval.RpminfoObjectRef{Ref: "obj:release"}, State: oval.RpminfoStateRef{Ref: "ste:arch"}})

	def := oval.RpminfoDefinition{
		ID:    "oval:com.oracle.elsa:def:1",
		Class: "patch",
		Metadata: oval.RpminfoMetadata{
			Affected:   oval.Affected{Platforms: platforms},
			References: []oval.Reference{{RefID: "CVE-2024-1", Source: "CVE"}},
		},
		Criteria: oval.RpminfoCriteria{Operator: "OR"},
	}
	n := 0
	id := func(kind string) string { n++; return kind + ":" + strconv.Itoa(n) }
	for _, b := range branches {
		branch := oval.RpminfoCriteria{Operator: "AND"}
		if b.release != "" {
			ste, tst := id("ste"), id("tst")
			doc.States.States = append(doc.States.States, oval.RpminfoState{ID: ste, Version: oval.RpminfoVersion{Operation: "pattern match", Value: "^" + b.release}})
			doc.Tests.Tests = append(doc.Tests.Tests, oval.RpminfoTest{ID: tst, Object: oval.RpminfoObjectRef{Ref: "obj:release"}, State: oval.RpminfoStateRef{Ref: ste}})
			branch.Criterions = append(branch.Criterions, oval.RpminfoCriterion{TestRef: tst})
		}
		arch := oval.RpminfoCriteria{Operator: "AND", Criterions: []oval.RpminfoCriterion{{TestRef: "tst:arch"}}}
		pkgs := oval.RpminfoCriteria{Operator: "OR"}
		for _, vt := range b.tests {
			obj, ste, tst := id("obj"), id("ste"), id("tst")
			doc.Objects.Objects = append(doc.Objects.Objects, oval.RpminfoObject{ID: obj, Name: vt.name})
			state := oval.RpminfoState{ID: ste, EVR: oval.RpminfoEVR{Datatype: "evr_string", Operation: "less than", Value: vt.evr}}
			if vt.stream != "" {
				state.Version = oval.RpminfoVersion{Operation: "pattern match", Value: vt.stream}
			}
			doc.States.States = append(doc.States.States, state)
			doc.Tests.Tests = append(doc.Tests.Tests, oval.RpminfoTest{ID: tst, Object: oval.RpminfoObjectRef{Ref: obj}, State: oval.RpminfoStateRef{Ref: ste}})
			pkgs.Criteria = append(pkgs.Criteria, oval.RpminfoCriteria{Operator: "AND", Criterions: []oval.RpminfoCriterion{{TestRef: tst}}})
		}
		arch.Criteria = []oval.RpminfoCriteria{pkgs}
		branch.Criteria = []oval.RpminfoCriteria{{Operator: "OR", Criteria: []oval.RpminfoCriteria{arch}}}
		def.Criteria.Criteria = append(def.Criteria.Criteria, branch)
	}
	doc.Definitions.Definitions = []oval.RpminfoDefinition{def}
	return doc
}

// TestFromOracleDocument_EachReleaseGetsItsOwnVersions: an ELSA naming OL8,
// OL9 and OL10 fixes each release at its own .elN evr. Every statement must
// carry the evr of the branch its release gate heads, and no other.
func TestFromOracleDocument_EachReleaseGetsItsOwnVersions(t *testing.T) {
	doc := oracleDoc([]string{"Oracle Linux 8", "Oracle Linux 9", "Oracle Linux 10"},
		oracleBranch{"8", []oracleVersionTest{
			{"kernel-uek", "0:5.15.0-321.202.5.el8uek", "5.15.0"},
			{"cri-o", "0:1.26.4-2.el8", `^1\.26\.`},
		}},
		oracleBranch{"9", []oracleVersionTest{
			{"kernel-uek", "0:5.15.0-321.202.5.el9uek", "5.15.0"},
			{"cri-o", "0:1.26.4-2.el9", `^1\.26\.`},
		}},
		oracleBranch{"10", []oracleVersionTest{
			{"kernel-uek", "0:6.12.0-206.104.4.el10uek", ""},
		}},
	)
	got := make(map[string]string)
	for _, s := range fromOracleDocument(doc) {
		if prev, dup := got[s.ProductID]; dup {
			t.Errorf("%s emitted twice (%s and %s)", s.ProductID, prev, s.Version)
		}
		got[s.ProductID] = s.Version
	}
	want := map[string]string{
		"pkg:rpm/oracle/kernel-uek?distro=oracle-8":  "0:5.15.0-321.202.5.el8uek",
		"pkg:rpm/oracle/cri-o?distro=oracle-8":       "0:1.26.4-2.el8",
		"pkg:rpm/oracle/kernel-uek?distro=oracle-9":  "0:5.15.0-321.202.5.el9uek",
		"pkg:rpm/oracle/cri-o?distro=oracle-9":       "0:1.26.4-2.el9",
		"pkg:rpm/oracle/kernel-uek?distro=oracle-10": "0:6.12.0-206.104.4.el10uek",
	}
	if len(got) != len(want) {
		t.Errorf("got %d products %v, want %d %v", len(got), got, len(want), want)
	}
	for id, evr := range want {
		if got[id] != evr {
			t.Errorf("%s: version %q, want %q", id, got[id], evr)
		}
	}
}

// TestFromOracleDocument_DropsUngatedTests: a version test under no release
// gate has no release, so it is dropped, even though the definition's
// <platform> names a release. The gated branch beside it still emits.
func TestFromOracleDocument_DropsUngatedTests(t *testing.T) {
	doc := oracleDoc([]string{"Oracle Linux 9"},
		oracleBranch{"", []oracleVersionTest{{"glibc", "2:2.34-231.0.1.el9_7.10", ""}}},
		oracleBranch{"9", []oracleVersionTest{{"bpftool", "0:5.15.0-321.202.5.el9uek", ""}}},
	)
	stmts := fromOracleDocument(doc)
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement (the gated bpftool), got %d: %+v", len(stmts), stmts)
	}
	if stmts[0].ProductID != "pkg:rpm/oracle/bpftool?distro=oracle-9" {
		t.Errorf("got %s, want pkg:rpm/oracle/bpftool?distro=oracle-9", stmts[0].ProductID)
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
