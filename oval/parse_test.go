package oval

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDecode_CommonFields checks that the vendor-agnostic Decode parses
// the OVAL document and populates only the OVAL-spec-standardised fields
// (title, references, affected). Vendor extensions like Red Hat's
// <advisory> are not part of this decode path and therefore not checked.
func TestDecode_CommonFields(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "testdata", "rhel-9.6-eus-sample.oval.xml"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	doc, err := Decode(f)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if doc.Generator.ProductName == "" {
		t.Error("expected non-empty generator.product_name")
	}
	if len(doc.Definitions.Definitions) == 0 {
		t.Fatal("expected at least one definition in the fixture")
	}

	def := doc.Definitions.Definitions[0]
	if def.ID == "" {
		t.Error("expected definition.id")
	}
	if def.Class == "" {
		t.Error("expected definition.class")
	}
	if def.Metadata.Title == "" {
		t.Error("expected metadata.title")
	}
	var cveRefs int
	for _, ref := range def.Metadata.References {
		if ref.Source == "CVE" {
			cveRefs++
		}
	}
	if cveRefs == 0 {
		t.Error("expected at least one CVE reference (shared OVAL field)")
	}
}

// TestDecodeRedHat_Fixture exercises the Red Hat-specific decode path,
// which adds the <advisory> extension (severity, CVEs with CVSS, affected
// CPE list, etc.) on top of the shared fields.
func TestDecodeRedHat_Fixture(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "testdata", "rhel-9.6-eus-sample.oval.xml"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	doc, err := DecodeRedHat(f)
	if err != nil {
		t.Fatalf("DecodeRedHat: %v", err)
	}
	if len(doc.Definitions.Definitions) == 0 {
		t.Fatal("expected at least one definition in the fixture")
	}

	def := doc.Definitions.Definitions[0]
	adv := def.Metadata.Advisory
	if adv.Severity == "" {
		t.Error("expected advisory.severity populated via Red Hat decode")
	}
	if len(adv.AffectedCPEList.CPEs) == 0 {
		t.Error("expected at least one CPE in affected_cpe_list — the whole point of DecodeRedHat")
	}
	if len(adv.CVEs) == 0 {
		t.Error("expected at least one CVE in advisory")
	}
}
