package translator

import (
	"io"
	"strings"

	"github.com/getreeldev/oval-to-vex/oval"
)

// FromAlmaLinuxOVAL parses an AlmaLinux errata OVAL document (e.g.
// org.almalinux.alsa-9.xml, OVAL 5.10) from r and returns the package-level
// statements implied by its definitions.
//
// AlmaLinux's OVAL ID namespace does not encode the distro major version, so
// the caller passes it via release ("9", "8", …) — it becomes the
// ?distro= qualifier on the emitted PURLs. release must be non-empty;
// otherwise no statements are produced (a PURL without the distro qualifier
// is not a stable identity).
//
// Each ALSA definition (class="patch") binds one or more binary packages to
// a fixed evr via its criteria tree. For each (CVE × package) the parser
// emits status="fixed" with the verbatim evr (epoch included). To insure
// against scanner namespace drift it emits TWO rows per package — one under
// pkg:rpm/almalinux/<name> and one under pkg:rpm/alma/<name> — because Trivy
// keys AlmaLinux content under the short "alma" namespace while the canonical
// purl-spec namespace is "almalinux". Vendor is "almalinux" on both.
//
// Non-version criteria (signature checks, arch gates, the
// rpmverifyfile-based "AlmaLinux N is installed" gates) carry no evr and are
// dropped by the shared resolver — see rpminfoResolver.packagesFor.
func FromAlmaLinuxOVAL(r io.Reader, release string) ([]Statement, error) {
	doc, err := oval.DecodeRpminfo(r)
	if err != nil {
		return nil, err
	}
	return fromAlmaLinuxDocument(doc, release), nil
}

// fromAlmaLinuxDocument walks the parsed document and emits Statements.
// Split from FromAlmaLinuxOVAL so tests can build documents directly.
func fromAlmaLinuxDocument(doc *oval.RpminfoDocument, release string) []Statement {
	release = strings.TrimSpace(release)
	if release == "" {
		return nil
	}
	resolver := newRpminfoResolver(doc)

	// Namespaces AlmaLinux content is keyed under across scanners.
	// purl-spec says "almalinux"; Trivy uses "alma". Emit both.
	namespaces := []string{"almalinux", "alma"}

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
		pkgs := resolver.packagesFor(def, false)
		for _, pkg := range pkgs {
			for _, ns := range namespaces {
				id := "pkg:rpm/" + ns + "/" + pkg.Name + "?distro=almalinux-" + release
				for _, cve := range cves {
					out = append(out, Statement{
						CVE:       cve,
						ProductID: id,
						BaseID:    id,
						Version:   pkg.EVR,
						IDType:    "purl",
						Status:    "fixed",
						Vendor:    "almalinux",
					})
				}
			}
		}
	}
	return out
}
