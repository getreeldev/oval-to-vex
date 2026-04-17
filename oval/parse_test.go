package oval

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDecode_RHELEUSFixture(t *testing.T) {
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

	// Spot-check the first definition.
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
	if len(def.Metadata.Advisory.AffectedCPEList.CPEs) == 0 {
		t.Error("expected at least one CPE in affected_cpe_list")
	}
}
