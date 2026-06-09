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

## AlmaLinux (`FromAlmaLinuxOVAL`)

- RPM package-level statements. One statement per `(CVE, binary package)` resolved by walking `criteria → rpminfo_test → (object → name)` for the package and `(test → state → evr)` for the fixed version. The `rpminfo_object` carries the binary name directly (no variable indirection — like Debian, unlike Ubuntu)
- `class="patch"` (ALSA errata) → `status=fixed` with the verbatim `evr` (epoch included)
- AlmaLinux's OVAL ID namespace does **not** encode the distro major, so the caller passes it: `FromAlmaLinuxOVAL(r, release)`. Empty release → no statements (a PURL without `?distro=` is not stable identity)
- Emits **two** PURLs per package — `pkg:rpm/almalinux/<name>` and `pkg:rpm/alma/<name>` (both `?distro=almalinux-<release>`) — as namespace-drift insurance: the purl-spec namespace is `almalinux` but Trivy keys AlmaLinux content under the short `alma`. `Vendor` is `almalinux` on both
- Signature checks, arch gates, and the `rpmverifyfile`-based "AlmaLinux N is installed" gate criteria carry no `evr` and are dropped automatically (the version-vs-signature distinction is made on the resolved **state's** `evr`, since a package's version test and its signature test share the same object)
- CVE dedupe across `<reference source="CVE">` and `<advisory>/<cve>`, as Red Hat. Errata with no CVE reference are skipped (we key and serve by CVE)

## Oracle Linux (`FromOracleOVAL`)

- RPM package-level statements, same `rpminfo` walk as AlmaLinux
- `class="patch"` (ELSA errata) → `status=fixed` with the verbatim `evr` (epoch included)
- Distro major recovered per-definition from `<platform>Oracle Linux N</platform>` (Oracle ships every major in one file; AlmaLinux is per-major). A multi-platform ELSA (OL8 **and** OL9) emits one row set per platform
- PURL identifiers of the form `pkg:rpm/oracle/<name>?distro=oracle-<N>`. `Vendor` is `oracle`
- **Ksplice variants are skipped (v1)**: Oracle ships Ksplice userspace package versions in the same errata (their fixed `evr` carries a `ksplice` marker, e.g. `2:2.34-…ksplice1.el9_7`), which key differently from the stock packages scanners report. They are filtered on the resolved `evr`
- Signature / arch / "Oracle Linux N is installed" gate criteria carry no `evr` and are dropped automatically
- CVE dedupe as Red Hat

## Not covered yet

- OVAL test / object / state applicability evaluation beyond resolving package identity. The library extracts what the advisory declares; it doesn't evaluate whether a given host matches
- SUSE, Alpine/Wolfi, Rocky OVAL. The type set is vendor-scoped — add `FromAlpineOVAL` etc. in subsequent minor releases
- Per-package version-range semantics with explicit "vulnerable" bounds. Current output carries the fixed version string; consumers do the version compare
