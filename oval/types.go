// Package oval decodes OVAL 5.10/5.11 definition documents into Go values.
// The type set is intentionally narrow: only what the translator package
// needs to emit Statements. Test objects, state definitions, and criteria
// trees are parsed but not evaluated — OVAL applicability evaluation is
// out of scope for a VEX-emitter.
//
// Only genuinely shared OVAL-spec types live here. Vendor extensions
// (Red Hat's <advisory>, Ubuntu's notification blocks, SUSE patch
// descriptions, etc.) each have their own vendor file — e.g. redhat.go —
// with their own Decode entrypoint. See DecodeRedHat for that path.
package oval

import "encoding/xml"

// Document is the root <oval_definitions> element with only the fields
// guaranteed by the OVAL spec. For vendor-extension access (Red Hat
// <advisory>, etc.), use the vendor-specific document type — e.g.
// RedHatDocument — and its corresponding Decode function.
type Document struct {
	XMLName     xml.Name    `xml:"oval_definitions"`
	Generator   Generator   `xml:"generator"`
	Definitions Definitions `xml:"definitions"`
}

// Generator holds the metadata/<generator> block.
type Generator struct {
	ProductName    string `xml:"product_name"`
	ProductVersion string `xml:"product_version"`
	SchemaVersion  string `xml:"schema_version"`
	Timestamp      string `xml:"timestamp"`
	ContentVersion string `xml:"content_version"`
}

// Definitions wraps the list of definitions.
type Definitions struct {
	Definitions []Definition `xml:"definition"`
}

// Definition is one advisory (class="patch") or vulnerability
// (class="vulnerability") record, at the shared OVAL level.
type Definition struct {
	ID       string   `xml:"id,attr"`
	Class    string   `xml:"class,attr"`
	Version  string   `xml:"version,attr"`
	Metadata Metadata `xml:"metadata"`
}

// Metadata holds only the OVAL-spec-standardised children of <metadata>:
// title, affected, references, and description. Vendor-extension payload
// (Red Hat <advisory>, etc.) is NOT on this struct — it lives on the
// vendor-specific Metadata type.
type Metadata struct {
	Title       string      `xml:"title"`
	Affected    Affected    `xml:"affected"`
	References  []Reference `xml:"reference"`
	Description string      `xml:"description"`
}

// Affected declares the product family and list of platforms.
type Affected struct {
	Family    string   `xml:"family,attr"`
	Platforms []string `xml:"platform"`
}

// Reference is one external link. Red Hat uses source="RHSA" for errata
// and source="CVE" for CVE IDs.
type Reference struct {
	RefID  string `xml:"ref_id,attr"`
	RefURL string `xml:"ref_url,attr"`
	Source string `xml:"source,attr"`
}
