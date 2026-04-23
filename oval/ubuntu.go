package oval

import (
	"encoding/xml"
	"fmt"
	"io"
)

// UbuntuDocument is the Ubuntu-specific OVAL document shape.
//
// Ubuntu OVAL differs structurally from Red Hat: package identity does not
// live in the definition metadata. It must be resolved by walking
// criteria → dpkginfo_test → dpkginfo_object → constant_variable to find
// binary package names, and dpkginfo_test → dpkginfo_state to find the
// fixed evr (epoch:version-release) string. So this Document type carries
// the full Tests/Objects/States/Variables sections, unlike RedHatDocument
// which only needs metadata.
//
// Use DecodeUbuntu to populate.
type UbuntuDocument struct {
	XMLName     xml.Name          `xml:"oval_definitions"`
	Generator   Generator         `xml:"generator"`
	Definitions UbuntuDefinitions `xml:"definitions"`
	Tests       UbuntuTests       `xml:"tests"`
	Objects     UbuntuObjects     `xml:"objects"`
	States      UbuntuStates      `xml:"states"`
	Variables   UbuntuVariables   `xml:"variables"`
}

// UbuntuDefinitions wraps the list of Ubuntu definitions.
type UbuntuDefinitions struct {
	Definitions []UbuntuDefinition `xml:"definition"`
}

// UbuntuDefinition is one Ubuntu USN advisory record. Carries Ubuntu's
// own <advisory> extension on its metadata plus a criteria tree that
// references package tests by ID.
type UbuntuDefinition struct {
	ID       string         `xml:"id,attr"`
	Class    string         `xml:"class,attr"`
	Version  string         `xml:"version,attr"`
	Metadata UbuntuMetadata `xml:"metadata"`
	Criteria UbuntuCriteria `xml:"criteria"`
}

// UbuntuMetadata carries the shared <metadata> children plus Ubuntu's
// <advisory> extension.
type UbuntuMetadata struct {
	Title       string         `xml:"title"`
	Affected    Affected       `xml:"affected"`
	References  []Reference    `xml:"reference"`
	Description string         `xml:"description"`
	Advisory    UbuntuAdvisory `xml:"advisory"`
}

// UbuntuAdvisory is Ubuntu's <advisory> block: severity, issue date, CVE
// list with CVSS attrs, launchpad bug links.
type UbuntuAdvisory struct {
	From     string         `xml:"from,attr"`
	Severity string         `xml:"severity"`
	Issued   UbuntuDateAttr `xml:"issued"`
	CVEs     []UbuntuCVE    `xml:"cve"`
	Bugs     []string       `xml:"bug"`
}

// UbuntuDateAttr covers Ubuntu's <issued date="..."/> element.
type UbuntuDateAttr struct {
	Date string `xml:"date,attr"`
}

// UbuntuCVE is one <cve> child of Ubuntu's <advisory>. CVSS attributes
// are preserved for callers that want risk metadata, but the translator
// currently only uses the ID.
type UbuntuCVE struct {
	ID           string `xml:",chardata"`
	Href         string `xml:"href,attr"`
	Priority     string `xml:"priority,attr"`
	Public       string `xml:"public,attr"`
	CVSSScore    string `xml:"cvss_score,attr"`
	CVSSVector   string `xml:"cvss_vector,attr"`
	CVSSSeverity string `xml:"cvss_severity,attr"`
	USNs         string `xml:"usns,attr"`
}

// UbuntuCriteria is a (possibly nested) criteria block. Ubuntu's USN
// definitions wrap a top-level criteria around an extend_definition
// (the OS-installed applicability check) plus inner criteria containing
// criterion test_refs to dpkginfo_test entries.
type UbuntuCriteria struct {
	Operator          string                  `xml:"operator,attr"`
	Criteria          []UbuntuCriteria        `xml:"criteria"`
	Criterions        []UbuntuCriterion       `xml:"criterion"`
	ExtendDefinitions []UbuntuExtendDefinition `xml:"extend_definition"`
}

// UbuntuCriterion is a leaf reference to a test.
type UbuntuCriterion struct {
	TestRef string `xml:"test_ref,attr"`
	Comment string `xml:"comment,attr"`
}

// UbuntuExtendDefinition is the OS-installed applicability check that
// most USN definitions reference at the top of their criteria tree.
// Resolved against an inventory definition; not used for VEX statement
// emission.
type UbuntuExtendDefinition struct {
	DefinitionRef      string `xml:"definition_ref,attr"`
	ApplicabilityCheck string `xml:"applicability_check,attr"`
}

// UbuntuTests wraps the <tests> section. Ubuntu mixes element types:
// dpkginfo_test for package checks, family_test and textfilecontent54_test
// for OS-detection. Only dpkginfo_test produces VEX statements.
type UbuntuTests struct {
	DpkginfoTests []UbuntuDpkginfoTest `xml:"dpkginfo_test"`
}

// UbuntuDpkginfoTest is a single package check: a test_id paired with one
// object_ref (which dereferences to a package name set) and one state_ref
// (which dereferences to a fixed evr).
type UbuntuDpkginfoTest struct {
	ID     string             `xml:"id,attr"`
	Object UbuntuDpkginfoObjectRef `xml:"object"`
	State  UbuntuDpkginfoStateRef  `xml:"state"`
}

// UbuntuDpkginfoObjectRef is a reference to an object by ID.
type UbuntuDpkginfoObjectRef struct {
	Ref string `xml:"object_ref,attr"`
}

// UbuntuDpkginfoStateRef is a reference to a state by ID.
type UbuntuDpkginfoStateRef struct {
	Ref string `xml:"state_ref,attr"`
}

// UbuntuObjects wraps the <objects> section.
type UbuntuObjects struct {
	DpkginfoObjects []UbuntuDpkginfoObject `xml:"dpkginfo_object"`
}

// UbuntuDpkginfoObject points at a constant_variable that holds the
// affected binary package names.
type UbuntuDpkginfoObject struct {
	ID   string                   `xml:"id,attr"`
	Name UbuntuDpkginfoObjectName `xml:"name"`
}

// UbuntuDpkginfoObjectName carries the variable reference.
type UbuntuDpkginfoObjectName struct {
	VarRef string `xml:"var_ref,attr"`
}

// UbuntuStates wraps the <states> section.
type UbuntuStates struct {
	DpkginfoStates []UbuntuDpkginfoState `xml:"dpkginfo_state"`
}

// UbuntuDpkginfoState carries the fixed-version (evr) the test compares
// against. Operation is typically "less than" — i.e. the package is
// vulnerable when its installed evr is less than this state's evr.
type UbuntuDpkginfoState struct {
	ID  string    `xml:"id,attr"`
	EVR UbuntuEVR `xml:"evr"`
}

// UbuntuEVR is the epoch:version-release string in Ubuntu's debian_evr_string
// datatype.
type UbuntuEVR struct {
	Datatype  string `xml:"datatype,attr"`
	Operation string `xml:"operation,attr"`
	Value     string `xml:",chardata"`
}

// UbuntuVariables wraps the <variables> section.
type UbuntuVariables struct {
	ConstantVariables []UbuntuConstantVariable `xml:"constant_variable"`
}

// UbuntuConstantVariable holds the binary package names that share a
// single test+state pair (typically because they all ship from one source
// package and were patched together).
type UbuntuConstantVariable struct {
	ID     string   `xml:"id,attr"`
	Values []string `xml:"value"`
}

// DecodeUbuntu reads an Ubuntu OVAL document from r. Returns the parsed
// document with all sections (definitions + tests + objects + states +
// variables) populated, ready for the translator to walk.
func DecodeUbuntu(r io.Reader) (*UbuntuDocument, error) {
	var doc UbuntuDocument
	if err := xml.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode Ubuntu OVAL: %w", err)
	}
	return &doc, nil
}
