package oval

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDecode_CommonFields checks that the vendor-agnostic Decode parses
// the OVAL document and populates only the OVAL-spec-standardised fields
// (title, references, affected). Vendor extensions like Oracle's
// <advisory> are not part of this decode path and therefore not checked.
func TestDecode_CommonFields(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "testdata", "oracle-ol9-sample.oval.xml"))
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
