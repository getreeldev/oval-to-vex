package oval

import (
	"encoding/xml"
	"fmt"
	"io"
)

// RpminfoDocument is the OVAL document shape shared by RPM-distro feeds that
// encode fix versions at the package level via rpminfo_test / rpminfo_object /
// rpminfo_state — currently AlmaLinux (OVAL 5.10) and Oracle Linux (OVAL 5.11).
//
// Unlike RedHatDocument (which is CPE-only, reading just
// <metadata>/<advisory>/<affected_cpe_list>), this carries the full
// Tests/Objects/States sections so the translator can recover
// (package name, fixed evr) pairs by walking the criteria tree:
//
//	criterion → rpminfo_test → (object → name) + (state → evr)
//
// Both vendors put the binary package name literally in
// <rpminfo_object><name>, like Debian's dpkginfo_object — there is no
// var_ref indirection (Ubuntu's model) to resolve.
//
// Go's encoding/xml matches on local element name and ignores namespaces,
// so the red-def:/#linux-namespaced rpminfo_* elements decode against plain
// "rpminfo_test" / "rpminfo_object" / "rpminfo_state" tags. Other element
// types in the same sections (rpmverifyfile_test, textfilecontent54_test,
// uname_test, …) simply do not bind to these slices and are ignored — which
// is exactly the desired behaviour, since only rpminfo carries package
// versions.
//
// Use DecodeRpminfo to populate.
type RpminfoDocument struct {
	XMLName     xml.Name           `xml:"oval_definitions"`
	Generator   Generator          `xml:"generator"`
	Definitions RpminfoDefinitions `xml:"definitions"`
	Tests       RpminfoTests       `xml:"tests"`
	Objects     RpminfoObjects     `xml:"objects"`
	States      RpminfoStates      `xml:"states"`
}

// RpminfoDefinitions wraps the list.
type RpminfoDefinitions struct {
	Definitions []RpminfoDefinition `xml:"definition"`
}

// RpminfoDefinition is one errata record. Class is "patch" for both
// AlmaLinux (ALSA) and Oracle (ELSA) errata; the criteria tree binds the
// listed packages to their fixed evr.
type RpminfoDefinition struct {
	ID       string          `xml:"id,attr"`
	Class    string          `xml:"class,attr"`
	Version  string          `xml:"version,attr"`
	Metadata RpminfoMetadata `xml:"metadata"`
	Criteria RpminfoCriteria `xml:"criteria"`
}

// RpminfoMetadata carries the shared <metadata> children plus the vendor
// <advisory> block. CVEs appear in two places that can overlap:
// <reference source="CVE"> and <advisory>/<cve> — collectRpminfoCVEs reads
// both and dedupes. The <platform> children of <affected> name the distro
// release(s) (Oracle: "Oracle Linux 9"; AlmaLinux omits these — its release
// comes from the caller).
type RpminfoMetadata struct {
	Title       string          `xml:"title"`
	Affected    Affected        `xml:"affected"`
	References  []Reference     `xml:"reference"`
	Description string          `xml:"description"`
	Advisory    RpminfoAdvisory `xml:"advisory"`
}

// RpminfoAdvisory is the vendor <advisory> block. Only the CVE list is read
// by the translator; severity/dates/bugzilla are decoded loosely (ignored)
// to keep the type minimal.
type RpminfoAdvisory struct {
	Severity string       `xml:"severity"`
	CVEs     []RpminfoCVE `xml:"cve"`
}

// RpminfoCVE is one <cve> child of the <advisory>. The translator uses only
// the ID (chardata); CVSS/CWE attributes are carried for callers that want
// risk metadata.
type RpminfoCVE struct {
	ID    string `xml:",chardata"`
	CVSS3 string `xml:"cvss3,attr"`
	CWE   string `xml:"cwe,attr"`
	Href  string `xml:"href,attr"`
}

// RpminfoCriteria is a (possibly deeply nested) criteria block. RPM errata
// nest several levels: an outer OR over "<distro> N is installed" gates,
// then per-arch OR groupings, each leaf an AND of a "<pkg> is earlier than
// <evr>" criterion and a "<pkg> is signed with the <distro> key" criterion.
// We flatten the whole tree and resolve every test_ref; non-version tests
// (signature, arch, "is installed", ksplice gate) fall away when their
// resolved state has no <evr>.
type RpminfoCriteria struct {
	Operator   string             `xml:"operator,attr"`
	Criteria   []RpminfoCriteria  `xml:"criteria"`
	Criterions []RpminfoCriterion `xml:"criterion"`
}

// RpminfoCriterion references a test by ID. The Comment is human-readable
// ("kernel is earlier than 0:5.14.0-570.30.1.el9_6") and is not parsed for
// data — package name and evr come from the resolved object/state.
type RpminfoCriterion struct {
	TestRef string `xml:"test_ref,attr"`
	Comment string `xml:"comment,attr"`
}

// RpminfoTests wraps the <tests> section. Only rpminfo_test binds here;
// other element types in the same section (rpmverifyfile_test, etc.) are
// ignored by the decoder.
type RpminfoTests struct {
	Tests []RpminfoTest `xml:"rpminfo_test"`
}

// RpminfoTest pairs one object_ref (a package) with one state_ref (a
// version / signature / arch bound). A package's version test and its
// signature test reference the same object but different states — which is
// why the version-vs-signature distinction must be made on the state's
// <evr>, not the object.
type RpminfoTest struct {
	ID      string           `xml:"id,attr"`
	Comment string           `xml:"comment,attr"`
	Object  RpminfoObjectRef `xml:"object"`
	State   RpminfoStateRef  `xml:"state"`
}

// RpminfoObjectRef is a pointer to an object by ID.
type RpminfoObjectRef struct {
	Ref string `xml:"object_ref,attr"`
}

// RpminfoStateRef is a pointer to a state by ID.
type RpminfoStateRef struct {
	Ref string `xml:"state_ref,attr"`
}

// RpminfoObjects wraps the <objects> section.
type RpminfoObjects struct {
	Objects []RpminfoObject `xml:"rpminfo_object"`
}

// RpminfoObject carries the binary package name directly in a <name> child
// — no variable indirection (unlike Ubuntu's constant_variable pattern).
type RpminfoObject struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name"`
}

// RpminfoStates wraps the <states> section.
type RpminfoStates struct {
	States []RpminfoState `xml:"rpminfo_state"`
}

// RpminfoState carries whichever bound the referencing test compares
// against. A version test's state has <evr> (epoch:version-release,
// operation "less than" → fixed at this evr). Signature tests'
// states have <signature_keyid>; "is installed"/arch gate states have
// <version> or <arch>. Only EVR is read; an empty EVR marks a non-version
// state, which the translator drops.
type RpminfoState struct {
	ID  string     `xml:"id,attr"`
	EVR RpminfoEVR `xml:"evr"`
}

// RpminfoEVR is the epoch:version-release string. Datatype is "evr_string"
// for both AlmaLinux and Oracle.
type RpminfoEVR struct {
	Datatype  string `xml:"datatype,attr"`
	Operation string `xml:"operation,attr"`
	Value     string `xml:",chardata"`
}

// DecodeRpminfo reads an RPM-level OVAL document (AlmaLinux or Oracle) from
// r, populating all sections (definitions + tests + objects + states) ready
// for the translator to walk.
func DecodeRpminfo(r io.Reader) (*RpminfoDocument, error) {
	var doc RpminfoDocument
	if err := xml.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode rpminfo OVAL: %w", err)
	}
	return &doc, nil
}
