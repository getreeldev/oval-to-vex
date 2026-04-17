// Package translator converts parsed OVAL documents into VEX-shaped
// statements. The Statement type is the library's output contract.
//
// Downstream consumers (scanners, VEX hubs like reel-vex) compose their own
// richer records from these — adding fields like SourceFormat, Updated,
// MatchReason that belong to the consumer's pipeline, not to the OVAL data.
package translator

// Statement is one VEX assertion produced from an OVAL definition.
//
// Field semantics match the VEX vocabulary (not_affected / fixed / affected
// / under_investigation) so downstream consumers can merge these with
// statements from other sources (CSAF, OpenVEX, ...) without re-mapping.
type Statement struct {
	// CVE is the canonical CVE identifier the statement applies to.
	CVE string

	// ProductID is the identifier the advisory targets. For Red Hat
	// advisories this is a CPE 2.2 URI from <affected_cpe_list>.
	ProductID string

	// BaseID is ProductID normalized for indexing — PURLs stripped of
	// @version and qualifiers; CPEs returned as-is.
	BaseID string

	// Version is the patched or affected version when encoded in the
	// OVAL definition. Empty for CPE-keyed statements produced by
	// v0.1.0.
	Version string

	// IDType is "cpe" or "purl".
	IDType string

	// Status is one of: fixed, affected, not_affected, under_investigation.
	Status string

	// Justification, when present, explains a not_affected status
	// (e.g. "vulnerable_code_not_present"). Red Hat OVAL rarely sets
	// this; typically only for "will not fix" type records.
	Justification string

	// Vendor is the advisory publisher, e.g. "redhat". Set when the
	// source signals it; consumers may override.
	Vendor string
}
