package translator

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/getreeldev/oval-to-vex/oval"
)

// codenameRe extracts the Ubuntu release codename from an OVAL ID like
// "oval:com.ubuntu.noble:def:66633000000".
var codenameRe = regexp.MustCompile(`oval:com\.ubuntu\.([a-z]+):`)

// codenameToVersion maps an Ubuntu LTS codename to its numeric version.
// Definitions whose codename is not in this map are skipped — we can't
// build a stable PURL without knowing the distro version. Add new
// entries here when Canonical ships a new release.
var codenameToVersion = map[string]string{
	"focal": "20.04",
	"jammy": "22.04",
	"noble": "24.04",
}

// FromUbuntuOVAL parses an Ubuntu USN OVAL document from r and returns
// the statements implied by its definitions.
//
// Ubuntu OVAL differs from Red Hat OVAL: package identity is not in the
// definition metadata. It is resolved by walking
// criteria → dpkginfo_test → (object → constant_variable) for the binary
// package names and (state → evr) for the fixed version.
//
// Output: one Statement per (CVE × binary package) drawn from each
// class="patch" definition. Status is always "fixed" — Ubuntu's USN feed
// is patches only; "affected unpatched" data lives in a different
// upstream feed (the CVE OVAL feed) which is out of scope for v0.2.0.
//
// Definitions are skipped when:
//   - class is not "patch" (e.g. "inventory" OS-detection definitions)
//   - the metadata contains no CVE references (USN-only patches without
//     a public CVE — rare; emitting USN-keyed statements is future work)
//   - the codename embedded in the OVAL ID is not in codenameToVersion
//     (we can't build a deterministic PURL without it)
func FromUbuntuOVAL(r io.Reader) ([]Statement, error) {
	doc, err := oval.DecodeUbuntu(r)
	if err != nil {
		return nil, err
	}
	return fromUbuntuDocument(doc), nil
}

// fromUbuntuDocument walks the parsed Ubuntu document and emits
// Statements. Split from FromUbuntuOVAL so tests can construct documents
// directly without going through XML decode.
func fromUbuntuDocument(doc *oval.UbuntuDocument) []Statement {
	testObj := make(map[string]string, len(doc.Tests.DpkginfoTests))
	testState := make(map[string]string, len(doc.Tests.DpkginfoTests))
	for _, t := range doc.Tests.DpkginfoTests {
		testObj[t.ID] = t.Object.Ref
		testState[t.ID] = t.State.Ref
	}
	objVar := make(map[string]string, len(doc.Objects.DpkginfoObjects))
	for _, o := range doc.Objects.DpkginfoObjects {
		objVar[o.ID] = o.Name.VarRef
	}
	varPkgs := make(map[string][]string, len(doc.Variables.ConstantVariables))
	for _, v := range doc.Variables.ConstantVariables {
		varPkgs[v.ID] = v.Values
	}
	stateEVR := make(map[string]string, len(doc.States.DpkginfoStates))
	for _, s := range doc.States.DpkginfoStates {
		stateEVR[s.ID] = s.EVR.Value
	}

	var out []Statement
	for i := range doc.Definitions.Definitions {
		def := &doc.Definitions.Definitions[i]
		if def.Class != "patch" {
			continue
		}
		cves := collectUbuntuCVEs(def)
		if len(cves) == 0 {
			continue
		}
		codename := extractUbuntuCodename(def.ID)
		distroVersion, ok := codenameToVersion[codename]
		if !ok {
			continue
		}
		for _, testRef := range collectTestRefs(&def.Criteria) {
			objID, hasObj := testObj[testRef]
			if !hasObj {
				continue
			}
			varID, hasVar := objVar[objID]
			if !hasVar {
				continue
			}
			packages := varPkgs[varID]
			fixedVersion := stateEVR[testState[testRef]]
			for _, pkg := range packages {
				id := fmt.Sprintf("pkg:deb/ubuntu/%s?distro=ubuntu-%s", pkg, distroVersion)
				for _, cve := range cves {
					out = append(out, Statement{
						CVE:       cve,
						ProductID: id,
						BaseID:    id,
						Version:   fixedVersion,
						IDType:    "purl",
						Status:    "fixed",
						Vendor:    "ubuntu",
					})
				}
			}
		}
	}
	return out
}

// collectTestRefs walks a (possibly nested) criteria tree and returns
// every criterion test_ref it contains. extend_definition refs are not
// included — those resolve to OS-detection inventory definitions, not
// package tests.
func collectTestRefs(c *oval.UbuntuCriteria) []string {
	var refs []string
	var walk func(*oval.UbuntuCriteria)
	walk = func(node *oval.UbuntuCriteria) {
		for _, crit := range node.Criterions {
			if crit.TestRef != "" {
				refs = append(refs, crit.TestRef)
			}
		}
		for i := range node.Criteria {
			walk(&node.Criteria[i])
		}
	}
	walk(c)
	return refs
}

// extractUbuntuCodename returns the codename embedded in an OVAL ID like
// "oval:com.ubuntu.noble:def:66633000000". Returns "" on no match.
func extractUbuntuCodename(id string) string {
	m := codenameRe.FindStringSubmatch(id)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// collectUbuntuCVEs gathers unique CVE IDs from an Ubuntu definition.
// Ubuntu, like Red Hat, can put CVEs in two places that overlap:
//
//   - <metadata>/<reference source="CVE">
//   - <metadata>/<advisory>/<cve>
//
// We read both and dedupe by CVE ID.
func collectUbuntuCVEs(def *oval.UbuntuDefinition) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		if _, dup := seen[id]; dup {
			return
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	for _, ref := range def.Metadata.References {
		if ref.Source == "CVE" {
			add(ref.RefID)
		}
	}
	for _, cve := range def.Metadata.Advisory.CVEs {
		add(cve.ID)
	}
	return out
}
