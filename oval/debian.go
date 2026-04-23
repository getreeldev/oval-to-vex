package oval

import (
	"encoding/xml"
	"fmt"
	"io"
)

// DebianDocument is the Debian-specific OVAL document shape.
//
// Debian OVAL differs structurally from Ubuntu: each definition targets
// exactly one (CVE, package) pair. The dpkginfo_object embeds the
// package name directly in a <name> child — there is no constant_variable
// indirection like Ubuntu's main feed. The release (Debian 11/12/13) is
// not encoded in the definition ID namespace (all defs share
// oval:org.debian:def:...); it is recovered from the <platform> text in
// metadata ("Debian GNU/Linux 12").
//
// Use DecodeDebian to populate.
type DebianDocument struct {
	XMLName     xml.Name          `xml:"oval_definitions"`
	Generator   Generator         `xml:"generator"`
	Definitions DebianDefinitions `xml:"definitions"`
	Tests       DebianTests       `xml:"tests"`
	Objects     DebianObjects     `xml:"objects"`
	States      DebianStates      `xml:"states"`
}

// DebianDefinitions wraps the list.
type DebianDefinitions struct {
	Definitions []DebianDefinition `xml:"definition"`
}

// DebianDefinition is one Debian security advisory record. Class is
// typically "vulnerability" (per-CVE record) or "patch" (DSA record);
// both map to a dpkginfo version-bound via the criteria tree.
type DebianDefinition struct {
	ID       string         `xml:"id,attr"`
	Class    string         `xml:"class,attr"`
	Version  string         `xml:"version,attr"`
	Metadata DebianMetadata `xml:"metadata"`
	Criteria DebianCriteria `xml:"criteria"`
}

// DebianMetadata — the <platform> child is where Debian encodes the
// release ("Debian GNU/Linux 12"). <product> names the affected package
// for convenience; the criteria tree is the authoritative source.
type DebianMetadata struct {
	Title       string      `xml:"title"`
	Affected    Affected    `xml:"affected"`
	References  []Reference `xml:"reference"`
	Description string      `xml:"description"`
}

// DebianCriteria is a (possibly nested) criteria block. Structurally
// identical to Ubuntu's — top-level AND with a "Debian N is installed"
// criterion, then nested architecture OR groupings containing the
// package-version criterion.
type DebianCriteria struct {
	Operator   string             `xml:"operator,attr"`
	Criteria   []DebianCriteria   `xml:"criteria"`
	Criterions []DebianCriterion  `xml:"criterion"`
}

// DebianCriterion references a test by ID.
type DebianCriterion struct {
	TestRef string `xml:"test_ref,attr"`
	Comment string `xml:"comment,attr"`
}

// DebianTests — only dpkginfo_test is relevant for VEX emission. The
// release-check (textfilecontent54_test) and architecture-check
// (uname_test) are used by OVAL applicability evaluation, not by us.
type DebianTests struct {
	DpkginfoTests []DebianDpkginfoTest `xml:"dpkginfo_test"`
}

// DebianDpkginfoTest — a dpkginfo_test pairs one object_ref (a package)
// with one state_ref (a fixed-version bound).
type DebianDpkginfoTest struct {
	ID     string                  `xml:"id,attr"`
	Object DebianDpkginfoObjectRef `xml:"object"`
	State  DebianDpkginfoStateRef  `xml:"state"`
}

// DebianDpkginfoObjectRef is a pointer to an object by ID.
type DebianDpkginfoObjectRef struct {
	Ref string `xml:"object_ref,attr"`
}

// DebianDpkginfoStateRef is a pointer to a state by ID.
type DebianDpkginfoStateRef struct {
	Ref string `xml:"state_ref,attr"`
}

// DebianObjects wraps the <objects> section.
type DebianObjects struct {
	DpkginfoObjects []DebianDpkginfoObject `xml:"dpkginfo_object"`
}

// DebianDpkginfoObject carries the binary package name directly — no
// variable indirection, unlike Ubuntu's constant_variable pattern.
type DebianDpkginfoObject struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name"`
}

// DebianStates wraps the <states> section.
type DebianStates struct {
	DpkginfoStates []DebianDpkginfoState `xml:"dpkginfo_state"`
}

// DebianDpkginfoState carries the version-bound the criterion compares
// against. Operation is typically "less than" — i.e. the package is
// vulnerable when its installed evr is less than the state's evr,
// equivalently fixed at this evr.
type DebianDpkginfoState struct {
	ID  string    `xml:"id,attr"`
	EVR DebianEVR `xml:"evr"`
}

// DebianEVR is the epoch:version-release string in debian_evr_string
// datatype. Same shape as Ubuntu.
type DebianEVR struct {
	Datatype  string `xml:"datatype,attr"`
	Operation string `xml:"operation,attr"`
	Value     string `xml:",chardata"`
}

// DecodeDebian reads a Debian OVAL document from r.
func DecodeDebian(r io.Reader) (*DebianDocument, error) {
	var doc DebianDocument
	if err := xml.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode Debian OVAL: %w", err)
	}
	return &doc, nil
}
