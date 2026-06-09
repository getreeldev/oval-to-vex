package translator

import (
	"strings"

	"github.com/getreeldev/oval-to-vex/oval"
)

// rpminfoPackage is one resolved (name, fixed-evr) pair drawn from a
// definition's criteria tree. The shared walk produces these; each vendor's
// translator turns them into PURL-keyed Statements with its own namespace
// and distro qualifier.
type rpminfoPackage struct {
	Name string
	EVR  string
}

// rpminfoResolver indexes a parsed RPM-level OVAL document so test_refs can
// be resolved to (package name, fixed evr) in O(1). Built once per document
// and shared across all definitions in it.
type rpminfoResolver struct {
	testObj   map[string]string // test ID → object ID
	testState map[string]string // test ID → state ID
	objName   map[string]string // object ID → package name
	stateEVR  map[string]string // state ID → evr (empty for non-version states)
}

// newRpminfoResolver builds the lookup maps from a decoded document.
func newRpminfoResolver(doc *oval.RpminfoDocument) *rpminfoResolver {
	r := &rpminfoResolver{
		testObj:   make(map[string]string, len(doc.Tests.Tests)),
		testState: make(map[string]string, len(doc.Tests.Tests)),
		objName:   make(map[string]string, len(doc.Objects.Objects)),
		stateEVR:  make(map[string]string, len(doc.States.States)),
	}
	for _, t := range doc.Tests.Tests {
		r.testObj[t.ID] = t.Object.Ref
		r.testState[t.ID] = t.State.Ref
	}
	for _, o := range doc.Objects.Objects {
		r.objName[o.ID] = o.Name
	}
	for _, s := range doc.States.States {
		r.stateEVR[s.ID] = strings.TrimSpace(s.EVR.Value)
	}
	return r
}

// packagesFor walks a definition's criteria tree and returns the resolved
// (name, evr) pairs for every version test it references.
//
// A test contributes a package only when it resolves to BOTH a named object
// AND a state carrying a non-empty <evr>. This single rule drops, with no
// per-element special-casing:
//
//   - signature tests   — same object as the version test, but a state
//     holding <signature_keyid> (no evr)
//   - arch / "is installed" gate tests — states holding <arch> or <version>
//   - rpmverifyfile / textfilecontent54 gate tests — not rpminfo_test at all,
//     so absent from the resolver maps entirely
//
// skipKsplice, when true, additionally drops packages whose fixed evr
// contains "ksplice" (Oracle ships Ksplice userspace variants in the same
// errata; v1 keys/serves only the stock package versions). AlmaLinux passes
// false.
//
// The result is deduped on (name, evr) WITHIN a definition: both vendors
// reference the same package version test once per architecture branch in
// their criteria tree (an aarch64 OR-group and an x86_64 OR-group, etc.), so
// a naive flatten would yield one identical pair per arch. Architecture is
// not part of the statement identity here — the fixed evr is
// arch-independent — so the duplicates are collapsed.
//
// Dedup is intentionally NOT done across definitions. A single CVE is
// commonly fixed by a succession of errata (kernel-uek -312, -316, -321, …),
// each a legitimate, distinct fix boundary; the same (CVE, package) then
// recurs with a different evr. Those are kept — consumers want every fix
// boundary, and reel-vex's statements PK excludes the evr so they collapse to
// the latest there anyway.
func (r *rpminfoResolver) packagesFor(def *oval.RpminfoDefinition, skipKsplice bool) []rpminfoPackage {
	var out []rpminfoPackage
	seen := make(map[rpminfoPackage]struct{})
	for _, ref := range collectRpminfoTestRefs(&def.Criteria) {
		objID, ok := r.testObj[ref]
		if !ok {
			continue
		}
		name := r.objName[objID]
		if name == "" {
			continue
		}
		evr := r.stateEVR[r.testState[ref]]
		if evr == "" {
			continue // signature / arch / "is installed" gate — no fix version
		}
		if skipKsplice && strings.Contains(evr, "ksplice") {
			continue
		}
		pkg := rpminfoPackage{Name: name, EVR: evr}
		if _, dup := seen[pkg]; dup {
			continue
		}
		seen[pkg] = struct{}{}
		out = append(out, pkg)
	}
	return out
}

// collectRpminfoTestRefs flattens a (deeply nested) criteria tree to the
// list of every criterion test_ref it contains, in document order. The
// caller resolves these against the rpminfo maps and drops the ones that
// aren't version tests.
func collectRpminfoTestRefs(c *oval.RpminfoCriteria) []string {
	var refs []string
	var walk func(*oval.RpminfoCriteria)
	walk = func(node *oval.RpminfoCriteria) {
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

// collectRpminfoCVEs gathers unique CVE IDs from an RPM-level definition,
// reading both <metadata>/<reference source="CVE"> and
// <metadata>/<advisory>/<cve> (which overlap) and deduping by ID. Mirrors
// collectRedHatCVEs — AlmaLinux and Oracle inherit Red Hat's advisory shape.
func collectRpminfoCVEs(def *oval.RpminfoDefinition) []string {
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
