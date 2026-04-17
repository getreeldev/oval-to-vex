package oval

import (
	"encoding/xml"
	"fmt"
	"io"
)

// RedHatDocument is the Red Hat-specific OVAL document shape. It mirrors
// the shared Document but chains through RedHatDefinitions →
// RedHatDefinition → RedHatMetadata so that Red Hat's <advisory> extension
// (with severity, CVEs carrying CVSS + CWE attrs, affected_cpe_list, etc.)
// is populated during XML decode.
//
// Use DecodeRedHat to populate. Ubuntu, Debian, SUSE each get their own
// Document shape and Decode entrypoint in their own file.
type RedHatDocument struct {
	XMLName     xml.Name          `xml:"oval_definitions"`
	Generator   Generator         `xml:"generator"`
	Definitions RedHatDefinitions `xml:"definitions"`
}

// RedHatDefinitions wraps the list of Red Hat definitions.
type RedHatDefinitions struct {
	Definitions []RedHatDefinition `xml:"definition"`
}

// RedHatDefinition is one Red Hat advisory or vulnerability record,
// carrying the Red Hat-specific advisory block on its metadata.
type RedHatDefinition struct {
	ID       string         `xml:"id,attr"`
	Class    string         `xml:"class,attr"`
	Version  string         `xml:"version,attr"`
	Metadata RedHatMetadata `xml:"metadata"`
}

// RedHatMetadata carries the shared <metadata> children plus Red Hat's
// own <advisory> extension block.
type RedHatMetadata struct {
	Title       string         `xml:"title"`
	Affected    Affected       `xml:"affected"`
	References  []Reference    `xml:"reference"`
	Description string         `xml:"description"`
	Advisory    RedHatAdvisory `xml:"advisory"`
}

// RedHatAdvisory is the Red Hat-specific <advisory> block: severity,
// per-CVE CVSS + CWE metadata, affected CPE list, bugzilla links.
type RedHatAdvisory struct {
	From            string             `xml:"from,attr"`
	Severity        string             `xml:"severity"`
	Rights          string             `xml:"rights"`
	Issued          RedHatDateAttr     `xml:"issued"`
	Updated         RedHatDateAttr     `xml:"updated"`
	CVEs            []RedHatCVE        `xml:"cve"`
	Bugzilla        []RedHatBugzilla   `xml:"bugzilla"`
	AffectedCPEList RedHatAffectedCPEs `xml:"affected_cpe_list"`
}

// RedHatDateAttr covers Red Hat's <issued date="..."/> and <updated
// date="..."/> elements.
type RedHatDateAttr struct {
	Date string `xml:"date,attr"`
}

// RedHatCVE is one <cve> child of Red Hat's <advisory>. CVSS and CWE
// attributes are preserved for callers that want risk metadata, but the
// translator currently only uses the ID.
type RedHatCVE struct {
	ID     string `xml:",chardata"`
	CVSS3  string `xml:"cvss3,attr"`
	CWE    string `xml:"cwe,attr"`
	Href   string `xml:"href,attr"`
	Impact string `xml:"impact,attr"`
	Public string `xml:"public,attr"`
}

// RedHatBugzilla is one <bugzilla> link in a Red Hat advisory.
type RedHatBugzilla struct {
	ID   string `xml:"id,attr"`
	Href string `xml:"href,attr"`
	Text string `xml:",chardata"`
}

// RedHatAffectedCPEs wraps Red Hat's <affected_cpe_list>. Each child <cpe>
// is one CPE 2.2 URI the advisory applies to. Red Hat's EUS, AUS, E4S,
// SAP, HA, NFV stream variants only appear here — not in their CSAF VEX
// feed — which is the core reason this library exists. See SECDATA-1181.
type RedHatAffectedCPEs struct {
	CPEs []string `xml:"cpe"`
}

// DecodeRedHat reads a Red Hat OVAL document from r. Callers that only
// need shared OVAL fields can use Decode instead; callers that need the
// Red Hat <advisory> block (CVEs with CVSS, affected_cpe_list, severity,
// etc.) should use this.
func DecodeRedHat(r io.Reader) (*RedHatDocument, error) {
	var doc RedHatDocument
	if err := xml.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode Red Hat OVAL: %w", err)
	}
	return &doc, nil
}
