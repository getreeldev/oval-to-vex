// Package oval decodes OVAL 5.10/5.11 definition documents into Go values.
// The type set is intentionally narrow: only what the translator package
// needs to emit Statements. Test objects, state definitions, and criteria
// trees are parsed but not evaluated — OVAL applicability evaluation is
// out of scope for a VEX-emitter.
package oval

import "encoding/xml"

// Document is the root <oval_definitions> element.
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
// (class="vulnerability") record.
type Definition struct {
	ID       string   `xml:"id,attr"`
	Class    string   `xml:"class,attr"`
	Version  string   `xml:"version,attr"`
	Metadata Metadata `xml:"metadata"`
}

// Metadata holds the per-definition title, affected platforms, references,
// and advisory/CVE details.
type Metadata struct {
	Title       string      `xml:"title"`
	Affected    Affected    `xml:"affected"`
	References  []Reference `xml:"reference"`
	Description string      `xml:"description"`
	Advisory    Advisory    `xml:"advisory"`
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

// Advisory is the per-definition Red Hat advisory metadata.
type Advisory struct {
	From            string       `xml:"from,attr"`
	Severity        string       `xml:"severity"`
	Rights          string       `xml:"rights"`
	Issued          DateAttr     `xml:"issued"`
	Updated         DateAttr     `xml:"updated"`
	CVEs            []CVE        `xml:"cve"`
	Bugzilla        []Bugzilla   `xml:"bugzilla"`
	AffectedCPEList AffectedCPEs `xml:"affected_cpe_list"`
}

// DateAttr covers elements like <issued date="2022-05-17"/>.
type DateAttr struct {
	Date string `xml:"date,attr"`
}

// CVE is one <cve> element in the advisory. CVSS and CWE details are
// parsed for completeness but not currently emitted in Statements.
type CVE struct {
	ID     string `xml:",chardata"`
	CVSS3  string `xml:"cvss3,attr"`
	CWE    string `xml:"cwe,attr"`
	Href   string `xml:"href,attr"`
	Impact string `xml:"impact,attr"`
	Public string `xml:"public,attr"`
}

// Bugzilla is one <bugzilla> link.
type Bugzilla struct {
	ID   string `xml:"id,attr"`
	Href string `xml:"href,attr"`
	Text string `xml:",chardata"`
}

// AffectedCPEs wraps <affected_cpe_list>. Each <cpe> child is one CPE 2.2
// URI applicable to this advisory. Red Hat EUS/AUS/E4S variants only
// appear here — not in their CSAF VEX feed — which is the core reason
// this library exists.
type AffectedCPEs struct {
	CPEs []string `xml:"cpe"`
}
