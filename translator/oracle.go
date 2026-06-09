package translator

import (
	"io"
	"regexp"

	"github.com/getreeldev/oval-to-vex/oval"
)

// oraclePlatformRe extracts the Oracle Linux major version from the
// <platform>Oracle Linux 9</platform> text in a definition's affected
// metadata. Oracle ships every major (OL6, OL7, OL8, OL9, …) in one OVAL
// file and a single ELSA errata can target several at once, so — unlike
// AlmaLinux's per-major file — the release is read per-definition from the
// platform string, the same way the Debian parser recovers its version.
var oraclePlatformRe = regexp.MustCompile(`Oracle Linux (\d+)`)

// FromOracleOVAL parses an Oracle Linux errata OVAL document (e.g.
// com.oracle.elsa-ol9.xml, OVAL 5.11) from r and returns the package-level
// statements implied by its definitions.
//
// Each ELSA definition (class="patch") declares its target release(s) in
// <metadata>/<affected>/<platform> ("Oracle Linux 9") and binds binary
// packages to a fixed evr through its criteria tree. For each
// (CVE × package × platform) the parser emits status="fixed" with the
// verbatim evr (epoch included) and a PURL of the form
// pkg:rpm/oracle/<name>?distro=oracle-<N>. A multi-platform errata (OL8 and
// OL9 in one definition) emits one row per platform; the over-emission is
// harmless — consumers query by the distro they care about.
//
// Ksplice variants are skipped in v1: Oracle ships Ksplice userspace package
// versions in the same errata (their fixed evr carries a "ksplice" marker
// such as 2:2.34-...ksplice1.el9_7), which key differently from the stock
// packages scanners report. They are filtered by the shared resolver.
//
// Signature checks, arch gates, and "Oracle Linux N is installed" gate tests
// carry no evr and are dropped by the shared resolver.
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
		releases := extractOracleVersions(def.Metadata.Affected.Platforms)
		if len(releases) == 0 {
			continue
		}
		pkgs := resolver.packagesFor(def, true) // skip ksplice
		for _, release := range releases {
			for _, pkg := range pkgs {
				id := "pkg:rpm/oracle/" + pkg.Name + "?distro=oracle-" + release
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

// extractOracleVersions returns every distinct Oracle Linux major version
// named in a definition's <platform> list, in document order. A definition
// with no recognised platform yields an empty slice (skipped — a PURL
// without the distro qualifier is not a stable identity).
func extractOracleVersions(platforms []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, p := range platforms {
		if m := oraclePlatformRe.FindStringSubmatch(p); len(m) >= 2 {
			v := m[1]
			if _, dup := seen[v]; dup {
				continue
			}
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}
