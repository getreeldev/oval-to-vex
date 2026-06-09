# Changelog

All notable changes to `oval-to-vex` are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the library is pre-1.0, so minor bumps may carry breaking changes. Per-parser extraction detail (and what's deliberately out of scope) lives in [`docs/coverage.md`](./docs/coverage.md).

## [0.3.0] — RPM-level OVAL parsers (AlmaLinux, Oracle Linux)

### Added

- **`FromAlmaLinuxOVAL(r, release)`** and **`FromOracleOVAL(r)`** — the first RPM *package-level* parsers. Unlike `FromRedHatOVAL` (CPE-only), they walk the criteria tree → `rpminfo_test` → `(object → name)` + `(state → evr)` to emit one `(CVE, binary package)` statement per fixed version (`status=fixed`, verbatim `evr` incl. epoch). The version-vs-signature distinction is made on the resolved **state's** `evr`, so signature / arch / "is installed" gate criteria (no `evr`) drop automatically.
  - AlmaLinux: release major is a caller argument (the OVAL IDs don't encode it); emitted under **both** `pkg:rpm/almalinux/<name>` and `pkg:rpm/alma/<name>` (`?distro=almalinux-<release>`) as scanner-namespace-drift insurance.
  - Oracle: release major(s) read per-definition from `<platform>Oracle Linux N</platform>` (one ELSA can target several majors → one row set each); `pkg:rpm/oracle/<name>?distro=oracle-<N>`. **Ksplice variants skipped in v1** (their `evr` carries a `ksplice` marker and keys differently from stock packages).
- **`oval.RpminfoDocument`** + `DecodeRpminfo` — shared decode types (`rpminfo_test`/`_object`/`_state`) carrying the full Tests/Objects/States sections, and a shared criteria-walk + CVE-dedup core (`translator/rpminfo.go`) reused by both parsers.

### Unchanged

- `FromRedHatOVAL` stays CPE-only (its purpose is the Red Hat EUS/AUS/E4S/SAP/HA/NFV affected-CPE coverage gap, not RPM versions).

## [0.2.2] — Debian: `affected` for unpatched CVE records

### Changed

- **`FromDebianOVAL`** now emits `status=affected` for `class="vulnerability"` records that are known-but-unfixed (a named package with no fix version), rather than only `fixed` rows. Records with no resolvable `dpkginfo` test at all are still skipped.

## [0.2.1] — Debian OVAL support

### Added

- **`FromDebianOVAL`** — one statement per `(CVE, binary package)`; the `dpkginfo_object` carries the binary name directly (no `constant_variable` indirection). Distro version recovered from the `<platform>Debian GNU/Linux N</platform>` text. PURLs `pkg:deb/debian/<name>?distro=debian-<N>`.

## [0.2.0] — Ubuntu OVAL support

### Added

- **`FromUbuntuOVAL`** — one statement per `(CVE, binary package)`, resolving packages via `criteria → dpkginfo_test → (object → constant_variable)` and the fixed version via `(test → state → evr)`. Codenames focal/jammy/noble; PURLs `pkg:deb/ubuntu/<name>?distro=ubuntu-<version>` (the `distro` qualifier is package identity). USN feed is patches-only.

## [0.1.0] — initial release (Red Hat OVAL → VEX)

### Added

- **`FromRedHatOVAL`** — parses OVAL 5.10/5.11 `<oval_definitions>` into one statement per `(CVE, CPE)` from `<affected_cpe_list>`; `class="patch"` → `fixed`, `class="vulnerability"` → `affected`; CVE dedup across `<reference>` and `<advisory>/<cve>`. Recovers the multi-stream affected-CPE coverage Red Hat's CSAF VEX feed omits ([SECDATA-1181](https://redhat.atlassian.net/browse/SECDATA-1181)).
- Shared vs Red-Hat-specific OVAL type split (`oval/`). Zero dependencies beyond the standard library.
