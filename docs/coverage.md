# Coverage

What each vendor parser extracts, and what's deliberately out of scope.

## Red Hat (`FromRedHatOVAL`)

- OVAL 5.10 / 5.11 `<oval_definitions>` parsing
- One statement per `(CVE, CPE)` pair drawn from `<affected_cpe_list>`
- `class="patch"` → `status=fixed`; `class="vulnerability"` → `status=affected`
- CVE dedupe across `<reference>` and `<advisory>/<cve>` elements

Recovers the Red Hat EUS / AUS / E4S / SAP / HA / NFV multi-stream coverage that Red Hat's CSAF VEX feed omits for affected-CPE matching ([SECDATA-1181](https://redhat.atlassian.net/browse/SECDATA-1181)). RPM-level statements (version-range comparison, criteria-tree evaluation) are not yet emitted — output is CPE-level.

## Ubuntu (`FromUbuntuOVAL`, v0.2.0)

- One statement per `(CVE, binary package)` pair, resolved by walking `criteria → dpkginfo_test → (object → constant_variable)` for packages and `(test → state → evr)` for the fixed version
- `class="patch"` → `status=fixed`. Ubuntu's USN feed is patches only; the CVE OVAL feed (unfixed/affected) is a separate future adapter
- Supported release codenames: `focal` (20.04), `jammy` (22.04), `noble` (24.04). Other codenames are skipped
- PURL identifiers of the form `pkg:deb/ubuntu/<name>?distro=ubuntu-<version>` — the distro qualifier is part of package identity (noble `openssl` ≠ jammy `openssl`)
- CVE dedupe as Red Hat; USNs with no CVE references (rare) are skipped

## Debian (`FromDebianOVAL`, v0.2.1)

- One statement per `(CVE, binary package)` pair. Each Debian definition targets exactly one package; the `dpkginfo_object` carries the binary name directly (no constant_variable indirection)
- Distro version recovered from the `<platform>Debian GNU/Linux N</platform>` metadata text — the OVAL ID namespace carries no codename
- Both `class="patch"` (DSA) and `class="vulnerability"` (per-CVE) emit `status=fixed` with the dpkginfo `evr` as the fix version. Vulnerability records with no resolvable dpkginfo test (known-but-unfixed CVEs) are skipped — `affected` without a fix version isn't actionable for VEX
- PURL identifiers of the form `pkg:deb/debian/<name>?distro=debian-<N>` (12, 11, 13, …)

## Not covered yet

- OVAL test / object / state applicability evaluation beyond resolving package identity. The library extracts what the advisory declares; it doesn't evaluate whether a given host matches
- SUSE, Alpine/Wolfi, Oracle/Alma/Rocky OVAL. The type set is vendor-scoped — add `FromAlpineOVAL` etc. in subsequent minor releases
- Per-package version-range semantics with explicit "vulnerable" bounds. Current output carries the fixed version string; consumers do the version compare
