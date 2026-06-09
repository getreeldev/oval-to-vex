package translator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getreeldev/oval-to-vex/oval"
)

func TestFromAlmaLinuxOVAL_Fixture(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "testdata", "almalinux-9-sample.oval.xml"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	stmts, err := FromAlmaLinuxOVAL(f, "9")
	if err != nil {
		t.Fatalf("FromAlmaLinuxOVAL: %v", err)
	}

	// Fixture: one ALSA patch def with 2 packages (perf, kernel) × 2 CVEs,
	// each emitted under 2 namespaces (almalinux, alma) = 8 statements. The
	// no-CVE def is skipped; the two signature tests (same objects as the
	// version tests, evr-less states) must not produce statements.
	if len(stmts) != 8 {
		t.Fatalf("expected 8 statements, got %d: %+v", len(stmts), stmts)
	}

	// Invariants on every statement.
	for i, s := range stmts {
		if !strings.HasPrefix(s.CVE, "CVE-") {
			t.Errorf("stmt %d: CVE %q does not start with CVE-", i, s.CVE)
		}
		if s.IDType != "purl" {
			t.Errorf("stmt %d: IDType %q, want purl", i, s.IDType)
		}
		if s.Vendor != "almalinux" {
			t.Errorf("stmt %d: Vendor %q, want almalinux", i, s.Vendor)
		}
		if s.Status != "fixed" {
			t.Errorf("stmt %d: Status %q, want fixed", i, s.Status)
		}
		if s.BaseID != s.ProductID {
			t.Errorf("stmt %d: BaseID (%q) must equal ProductID (%q)", i, s.BaseID, s.ProductID)
		}
		if !strings.HasPrefix(s.ProductID, "pkg:rpm/") {
			t.Errorf("stmt %d: ProductID %q is not a pkg:rpm PURL", i, s.ProductID)
		}
	}

	// Both namespaces must be emitted (Trivy uses "alma"; purl-spec uses
	// "almalinux") — this is the namespace-drift insurance.
	var sawAlma, sawAlmalinux bool
	for _, s := range stmts {
		if strings.HasPrefix(s.ProductID, "pkg:rpm/alma/") {
			sawAlma = true
		}
		if strings.HasPrefix(s.ProductID, "pkg:rpm/almalinux/") {
			sawAlmalinux = true
		}
	}
	if !sawAlma {
		t.Error("no statement under the pkg:rpm/alma/ namespace (Trivy convention)")
	}
	if !sawAlmalinux {
		t.Error("no statement under the pkg:rpm/almalinux/ namespace (purl-spec convention)")
	}

	// A known (CVE, package, evr) tuple must be present under both
	// namespaces, with the epoch (0:) preserved verbatim. kernel was gated
	// by a signature test in the fixture — its presence proves the signature
	// test was filtered on evr, not on the object.
	const wantEVR = "0:5.14.0-570.30.1.el9_6"
	for _, ns := range []string{"almalinux", "alma"} {
		wantID := "pkg:rpm/" + ns + "/kernel?distro=almalinux-9"
		var found bool
		for _, s := range stmts {
			if s.CVE == "CVE-2024-57980" && s.ProductID == wantID {
				found = true
				if s.Version != wantEVR {
					t.Errorf("%q: version %q, want %q (epoch must be preserved)", wantID, s.Version, wantEVR)
				}
			}
		}
		if !found {
			t.Errorf("missing expected statement for CVE-2024-57980 / %q", wantID)
		}
	}

	// The signature-only package state must never leak a fixed version. No
	// statement should carry the signature_keyid value as its version.
	for _, s := range stmts {
		if s.Version == "" || strings.Contains(s.Version, "d36cb86c") {
			t.Errorf("statement %+v carries an empty or signature-keyid version — signature test not filtered", s)
		}
	}
}

func TestFromAlmaLinuxOVAL_EmptyReleaseProducesNothing(t *testing.T) {
	doc := &oval.RpminfoDocument{
		Definitions: oval.RpminfoDefinitions{
			Definitions: []oval.RpminfoDefinition{
				{
					ID:    "oval:org.almalinux.alsa:def:1",
					Class: "patch",
					Metadata: oval.RpminfoMetadata{
						References: []oval.Reference{{RefID: "CVE-2024-1", Source: "CVE"}},
					},
				},
			},
		},
	}
	if got := fromAlmaLinuxDocument(doc, ""); len(got) != 0 {
		t.Errorf("expected 0 statements with empty release, got %d", len(got))
	}
	if got := fromAlmaLinuxDocument(doc, "  "); len(got) != 0 {
		t.Errorf("expected 0 statements with blank release, got %d", len(got))
	}
}

func TestFromAlmaLinuxDocument_SkipsNonPatchClass(t *testing.T) {
	doc := &oval.RpminfoDocument{
		Definitions: oval.RpminfoDefinitions{
			Definitions: []oval.RpminfoDefinition{
				{
					ID:    "oval:org.almalinux.alsa:def:1",
					Class: "vulnerability",
					Metadata: oval.RpminfoMetadata{
						References: []oval.Reference{{RefID: "CVE-2024-1", Source: "CVE"}},
					},
				},
			},
		},
	}
	if got := fromAlmaLinuxDocument(doc, "9"); len(got) != 0 {
		t.Errorf("expected 0 statements for non-patch class, got %d", len(got))
	}
}
