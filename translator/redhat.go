package translator

import (
	"io"
	"strings"

	"github.com/getreeldev/oval-to-vex/oval"
)

// FromRedHatOVAL parses an OVAL document from r (typically a Red Hat
// security-data OVAL feed) and returns the statements implied by its
// definitions.
//
// v0.1.0 scope: one Statement per (CVE, CPE) pair drawn from
// <metadata>/<advisory>/<affected_cpe_list>. Status is inferred from
// Definition.Class:
//
//   - class="patch"        → status=fixed         (Red Hat errata; the
//     listed CPEs are platforms the advisory fixed)
//   - class="vulnerability" → status=affected      (unpatched
//     advisories; the listed CPEs are platforms with the vuln)
//   - anything else         → skipped
//
// This covers the core Red Hat multi-stream coverage gap (SECDATA-1181):
// CSAF omits EUS/AUS/E4S/SAP/HA/NFV variants for affected-cpe matching,
// OVAL includes them, and v0.1.0's output restores that coverage when
// consumed alongside CSAF statements.
//
// RPM-level statements (with version-range comparison and criteria-tree
// evaluation) are out of v0.1.0 scope — deferred to v0.2.0.
func FromRedHatOVAL(r io.Reader) ([]Statement, error) {
	doc, err := oval.Decode(r)
	if err != nil {
		return nil, err
	}
	return fromDocument(doc), nil
}

// fromDocument walks the parsed document and emits Statements. Split from
// FromRedHatOVAL so tests can construct Documents directly.
func fromDocument(doc *oval.Document) []Statement {
	var out []Statement
	for i := range doc.Definitions.Definitions {
		def := &doc.Definitions.Definitions[i]
		status, ok := statusForClass(def.Class)
		if !ok {
			continue
		}
		cves := collectCVEs(def)
		cpes := def.Metadata.Advisory.AffectedCPEList.CPEs
		if len(cves) == 0 || len(cpes) == 0 {
			continue
		}
		for _, cve := range cves {
			for _, cpe := range cpes {
				out = append(out, Statement{
					CVE:       cve,
					ProductID: cpe,
					BaseID:    cpe, // CPEs pass through unchanged
					IDType:    "cpe",
					Status:    status,
					Vendor:    "redhat",
				})
			}
		}
	}
	return out
}

// statusForClass maps an OVAL definition class to a VEX status. The
// second return value is false when the class is unknown / unsupported.
func statusForClass(class string) (string, bool) {
	switch class {
	case "patch":
		return "fixed", true
	case "vulnerability":
		return "affected", true
	default:
		return "", false
	}
}

// collectCVEs gathers unique CVE IDs from a Definition. Red Hat puts them
// in two places that can overlap:
//
//   - <metadata>/<reference source="CVE"> — one per CVE
//   - <metadata>/<advisory>/<cve> — one per CVE with CVSS + CWE attrs
//
// We read both and dedupe by CVE ID so callers don't get duplicate
// statements when the same CVE appears in both.
func collectCVEs(def *oval.Definition) []string {
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
