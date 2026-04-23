package translator

import (
	"io"
	"regexp"
	"strings"

	"github.com/getreeldev/oval-to-vex/oval"
)

// debianPlatformRe extracts the Debian major version from the
// <platform>Debian GNU/Linux 12</platform> text in definition metadata.
// Debian's per-file feed puts each release in its own document, but the
// distro version is not in the OVAL namespace (unlike Ubuntu) — it's
// recoverable only from the platform string.
var debianPlatformRe = regexp.MustCompile(`Debian\s+GNU/Linux\s+(\d+)`)

// FromDebianOVAL parses a Debian Security Tracker OVAL document from r
// and returns the statements implied by its definitions.
//
// Each definition targets one (CVE, package) pair. The fix-version is
// recovered by walking criterion → dpkginfo_test → (object → name,
// state → evr). Statements emit PURLs in the form
// pkg:deb/debian/<name>?distro=debian-<N>.
//
// VEX status mapping (mirror model — report what the vendor publishes,
// let consumers decide how to use it):
//   - class="patch" or class="vulnerability" with a dpkginfo evr bound
//     → status="fixed", version=<evr> (the bound is the fix boundary)
//   - class="vulnerability" with no resolvable dpkginfo test
//     → status="affected", version="" (unpatched CVE record — Debian's
//     tracker knows about it, no patch shipped yet). Keyed on the
//     <product> name from metadata's <affected> block.
//   - other classes → skipped
//
// Definitions whose metadata/platform text does not match the expected
// "Debian GNU/Linux N" pattern are skipped (we can't build a stable
// PURL without the distro version).
func FromDebianOVAL(r io.Reader) ([]Statement, error) {
	doc, err := oval.DecodeDebian(r)
	if err != nil {
		return nil, err
	}
	return fromDebianDocument(doc), nil
}

// fromDebianDocument walks the parsed document and emits Statements.
// Split from FromDebianOVAL so tests can build documents directly.
func fromDebianDocument(doc *oval.DebianDocument) []Statement {
	testObj := make(map[string]string, len(doc.Tests.DpkginfoTests))
	testState := make(map[string]string, len(doc.Tests.DpkginfoTests))
	for _, t := range doc.Tests.DpkginfoTests {
		testObj[t.ID] = t.Object.Ref
		testState[t.ID] = t.State.Ref
	}
	objName := make(map[string]string, len(doc.Objects.DpkginfoObjects))
	for _, o := range doc.Objects.DpkginfoObjects {
		objName[o.ID] = o.Name
	}
	stateEVR := make(map[string]string, len(doc.States.DpkginfoStates))
	for _, s := range doc.States.DpkginfoStates {
		stateEVR[s.ID] = s.EVR.Value
	}

	var out []Statement
	for i := range doc.Definitions.Definitions {
		def := &doc.Definitions.Definitions[i]
		if def.Class != "patch" && def.Class != "vulnerability" {
			continue
		}
		cves := collectDebianCVEs(def)
		if len(cves) == 0 {
			continue
		}
		distroVersion := extractDebianVersion(def.Metadata.Affected.Platforms)
		if distroVersion == "" {
			continue
		}

		// Walk the criteria tree and collect dpkginfo test_refs only.
		// A Debian definition typically carries one package test_ref
		// interleaved with a release-install check (textfilecontent54)
		// and an architecture check (uname) — both are not in our
		// dpkginfo test map, so they're skipped naturally.
		emittedFixed := false
		for _, ref := range collectDebianTestRefs(&def.Criteria) {
			objID, hasObj := testObj[ref]
			if !hasObj {
				continue
			}
			name := objName[objID]
			if name == "" {
				continue
			}
			fixedVersion := stateEVR[testState[ref]]
			id := "pkg:deb/debian/" + name + "?distro=debian-" + distroVersion
			for _, cve := range cves {
				out = append(out, Statement{
					CVE:       cve,
					ProductID: id,
					BaseID:    id,
					Version:   fixedVersion,
					IDType:    "purl",
					Status:    "fixed",
					Vendor:    "debian",
				})
			}
			emittedFixed = true
		}

		// No dpkginfo_test resolved → Debian's tracker has logged the
		// CVE for this release but not yet shipped a fix. Emit as
		// affected keyed on the <product> name from metadata.
		if !emittedFixed && def.Class == "vulnerability" {
			product := strings.TrimSpace(def.Metadata.Affected.Product)
			if product == "" {
				continue
			}
			id := "pkg:deb/debian/" + product + "?distro=debian-" + distroVersion
			for _, cve := range cves {
				out = append(out, Statement{
					CVE:       cve,
					ProductID: id,
					BaseID:    id,
					IDType:    "purl",
					Status:    "affected",
					Vendor:    "debian",
				})
			}
		}
	}
	return out
}

// collectDebianTestRefs walks a (possibly nested) criteria tree and
// returns every criterion test_ref it contains. Non-dpkginfo tests
// (textfilecontent54 release-check, uname architecture-check) are
// resolved against the test map by the caller and dropped when absent.
func collectDebianTestRefs(c *oval.DebianCriteria) []string {
	var refs []string
	var walk func(*oval.DebianCriteria)
	walk = func(node *oval.DebianCriteria) {
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

// extractDebianVersion returns the Debian major version from the list of
// platform strings in a definition's affected metadata. Returns "" on
// no match.
func extractDebianVersion(platforms []string) string {
	for _, p := range platforms {
		if m := debianPlatformRe.FindStringSubmatch(p); len(m) >= 2 {
			return m[1]
		}
	}
	return ""
}

// collectDebianCVEs gathers unique CVE IDs from a Debian definition.
// Debian puts them in <metadata>/<reference source="CVE"> — sometimes
// more than one per definition when a single DSA covers multiple CVEs.
func collectDebianCVEs(def *oval.DebianDefinition) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, ref := range def.Metadata.References {
		if ref.Source != "CVE" {
			continue
		}
		id := strings.TrimSpace(ref.RefID)
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
