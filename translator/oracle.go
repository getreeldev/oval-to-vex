package translator

import (
	"io"
	"regexp"
	"strings"

	"github.com/getreeldev/oval-to-vex/oval"
)

// oracleReleaseRe matches the <version> pattern of an Oracle release gate:
// the "Oracle Linux 9 is installed" test compares oraclelinux-release's
// version against "^9". Stream patterns elsewhere in the tree (kernel-uek
// "5.15.0", cri-o "^1\.26\.") sit on other objects and are not a caret-only
// major, so they never match.
var oracleReleaseRe = regexp.MustCompile(`^\^(\d+)$`)

// FromOracleOVAL parses an Oracle Linux errata OVAL document (e.g.
// com.oracle.elsa-ol9.xml, OVAL 5.11) from r and returns the package-level
// statements implied by its definitions.
//
// Each ELSA definition (class="patch") binds binary packages to a fixed evr
// through its criteria tree. One ELSA can target several releases at once
// (OL8 and OL9); its tree then has one branch per release, each an AND of
// that release's gate ("Oracle Linux 9 is installed") and the release's own
// rpminfo tests with their own .elN evrs. The release a package is fixed in
// is read from the gate of the branch its version test sits in, and the
// package is emitted under that release only: status="fixed" with the
// verbatim evr (epoch included) and a PURL of the form
// pkg:rpm/oracle/<name>?distro=oracle-<N>. A version test under no gate has
// no release and is dropped. The <platform> list in the metadata is not
// read: it names every release of the errata, not which package belongs to
// which.
//
// Ksplice variants are skipped in v1: Oracle ships Ksplice userspace package
// versions in the same errata (their fixed evr carries a "ksplice" marker
// such as 2:2.34-...ksplice1.el9_7), which key differently from the stock
// packages scanners report.
//
// Signature checks, arch gates, and the release gates themselves carry no
// evr and emit nothing.
func FromOracleOVAL(r io.Reader) ([]Statement, error) {
	doc, err := oval.DecodeRpminfo(r)
	if err != nil {
		return nil, err
	}
	return fromOracleDocument(doc), nil
}

// fromOracleDocument walks the parsed document and emits Statements. Split
// from FromOracleOVAL so tests can build documents directly.
func fromOracleDocument(doc *oval.RpminfoDocument) []Statement {
	resolver := newRpminfoResolver(doc)
	gates := oracleReleaseGates(doc)

	var out []Statement
	for i := range doc.Definitions.Definitions {
		def := &doc.Definitions.Definitions[i]
		if def.Class != "patch" {
			continue
		}
		cves := collectRpminfoCVEs(def)
		if len(cves) == 0 {
			continue
		}
		for _, rp := range oraclePackagesByRelease(resolver, gates, def) {
			for _, pkg := range rp.pkgs {
				id := "pkg:rpm/oracle/" + pkg.Name + "?distro=oracle-" + rp.release
				for _, cve := range cves {
					out = append(out, Statement{
						CVE:       cve,
						ProductID: id,
						BaseID:    id,
						Version:   pkg.EVR,
						IDType:    "purl",
						Status:    "fixed",
						Vendor:    "oracle",
					})
				}
			}
		}
	}
	return out
}

// oracleReleaseGates maps the ID of every release-gate test in the document
// to the release it gates ("9"). A release gate is an rpminfo_test on the
// oraclelinux-release object whose state is
// <version operation="pattern match">^N</version>.
func oracleReleaseGates(doc *oval.RpminfoDocument) map[string]string {
	objName := make(map[string]string, len(doc.Objects.Objects))
	for _, o := range doc.Objects.Objects {
		objName[o.ID] = o.Name
	}
	release := make(map[string]string)
	for _, s := range doc.States.States {
		if s.Version.Operation != "pattern match" {
			continue
		}
		if m := oracleReleaseRe.FindStringSubmatch(strings.TrimSpace(s.Version.Value)); m != nil {
			release[s.ID] = m[1]
		}
	}
	gates := make(map[string]string)
	for _, t := range doc.Tests.Tests {
		if objName[t.Object.Ref] != "oraclelinux-release" {
			continue
		}
		if r, ok := release[t.State.Ref]; ok {
			gates[t.ID] = r
		}
	}
	return gates
}

// oracleReleasePackages is the (name, evr) pairs one definition fixes in one
// release.
type oracleReleasePackages struct {
	release string
	pkgs    []rpminfoPackage
}

// oraclePackagesByRelease walks a definition's criteria tree, carrying the
// release of the nearest enclosing gate down into each branch, and returns
// the version tests found under each release, releases in order of first
// appearance. A gate applies to the criteria node it sits in and everything
// nested below it. Pairs are deduped on (release, name, evr) for the same
// per-architecture repetition packagesFor collapses.
func oraclePackagesByRelease(r *rpminfoResolver, gates map[string]string, def *oval.RpminfoDefinition) []oracleReleasePackages {
	var out []oracleReleasePackages
	index := make(map[string]int)
	type key struct {
		release string
		pkg     rpminfoPackage
	}
	seen := make(map[key]struct{})

	var walk func(node *oval.RpminfoCriteria, release string)
	walk = func(node *oval.RpminfoCriteria, release string) {
		for _, crit := range node.Criterions {
			if g, ok := gates[crit.TestRef]; ok {
				release = g
			}
		}
		if release != "" {
			for _, crit := range node.Criterions {
				pkg, ok := r.versionTest(crit.TestRef, true) // skip ksplice
				if !ok {
					continue
				}
				k := key{release, pkg}
				if _, dup := seen[k]; dup {
					continue
				}
				seen[k] = struct{}{}
				i, ok := index[release]
				if !ok {
					i = len(out)
					index[release] = i
					out = append(out, oracleReleasePackages{release: release})
				}
				out[i].pkgs = append(out[i].pkgs, pkg)
			}
		}
		for i := range node.Criteria {
			walk(&node.Criteria[i], release)
		}
	}
	walk(&def.Criteria, "")
	return out
}
