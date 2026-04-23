# oval-to-vex

[![Go Reference](https://pkg.go.dev/badge/github.com/getreeldev/oval-to-vex.svg)](https://pkg.go.dev/github.com/getreeldev/oval-to-vex)

Go library that parses vendor OVAL XML (Red Hat and Ubuntu) and emits VEX-shaped statements. Zero dependencies beyond the standard library.

Built so scanners and VEX hubs can consume vendor OVAL feeds without pulling in the full Trivy pipeline — in particular to recover the Red Hat EUS / AUS / E4S / SAP / HA / NFV stream coverage that Red Hat's CSAF VEX feed omits (see [SECDATA-1181](https://redhat.atlassian.net/browse/SECDATA-1181)), and to provide first-class Ubuntu USN coverage for container scanning.

## Install

```bash
go get github.com/getreeldev/oval-to-vex
```

## Use

```go
import "github.com/getreeldev/oval-to-vex/translator"

// Red Hat
stmts, err := translator.FromRedHatOVAL(r)  // r is any io.Reader of OVAL XML

// Ubuntu
stmts, err := translator.FromUbuntuOVAL(r)  // Canonical USN feeds
```

Red Hat output (real data from `rhel-9.6-eus.oval.xml`):

```
CVE-2022-0413 fixed cpe:/a:redhat:rhel_eus:9.6::appstream
CVE-2022-0413 fixed cpe:/a:redhat:rhel_eus:9.6::baseos
CVE-2022-0413 fixed cpe:/a:redhat:rhel_eus:9.6::sap_hana
```

Ubuntu output (real data from `oci.com.ubuntu.noble.usn.oval.xml`):

```
CVE-2024-26130 fixed pkg:deb/ubuntu/python3-cryptography?distro=ubuntu-24.04
CVE-2024-26130 fixed pkg:deb/ubuntu/python-cryptography-doc?distro=ubuntu-24.04
```

## CLI

A small CLI is included for smoke testing. Default vendor is `redhat`; pass `-vendor=ubuntu` for Canonical feeds:

```bash
go install github.com/getreeldev/oval-to-vex/cmd/oval-to-vex@latest

# Red Hat
curl -sL https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.6-eus.oval.xml.bz2 \
  | bunzip2 | oval-to-vex > statements.json

# Ubuntu (OCI-flavoured feed — kernel/HWE noise stripped)
curl -sL https://security-metadata.canonical.com/oval/oci.com.ubuntu.noble.usn.oval.xml.bz2 \
  | bunzip2 | oval-to-vex -vendor=ubuntu > statements.json
```

## What's covered

**Red Hat** (`FromRedHatOVAL`):
- OVAL 5.10 / 5.11 `<oval_definitions>` parsing
- One statement per `(CVE, CPE)` pair drawn from `<affected_cpe_list>`
- `class="patch"` → `status=fixed`; `class="vulnerability"` → `status=affected`
- CVE dedupe across `<reference>` and `<advisory>/<cve>` elements

**Ubuntu** (`FromUbuntuOVAL`, added in v0.2.0):
- One statement per `(CVE, binary package)` pair, resolved by walking `criteria → dpkginfo_test → (object → constant_variable)` for packages and `(test → state → evr)` for the fixed version
- `class="patch"` → `status=fixed`. Ubuntu's USN feed is patches only; the CVE OVAL feed (for unfixed/affected) is a separate future adapter
- Supported release codenames: `focal` (20.04), `jammy` (22.04), `noble` (24.04). Definitions for unsupported codenames are skipped
- Statements emit PURL identifiers in the form `pkg:deb/ubuntu/<name>?distro=ubuntu-<version>`. The distro qualifier is part of the package identity — noble `openssl` and jammy `openssl` are distinct products
- CVE dedupe across `<reference>` and `<advisory>/<cve>` elements, same as Red Hat
- USNs with no CVE references (rare) are skipped — emitting USN-keyed statements is future work

## What's NOT covered yet

- OVAL test / object / state applicability evaluation beyond what's needed to resolve package identity. The library extracts what the advisory declares; it doesn't evaluate whether a given host matches
- Debian, SUSE, Alpine/Wolfi, Oracle/Alma/Rocky OVAL. The type set is vendor-scoped — add `FromDebianOVAL` etc. in subsequent minor releases
- Per-package version-range semantics with explicit "vulnerable" bounds. Current output carries the fixed version string; consumers do the version compare

## Statement shape

```go
type Statement struct {
    CVE           string // e.g. "CVE-2024-0217"
    ProductID     string // vendor identifier (CPE or PURL)
    BaseID        string // normalized form for indexing
    Version       string // fixed evr, when encoded in the OVAL (Ubuntu) — empty for RH v0.1.0 CPE statements
    IDType        string // "cpe" or "purl"
    Status        string // "fixed" | "affected" | "not_affected" | "under_investigation"
    Justification string // e.g. "vulnerable_code_not_present"
    Vendor        string // "redhat" or "ubuntu"
}
```

Downstream consumers layer their own metadata (ingest timestamp, upstream source format, etc.) when they persist these.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for prior-art attribution.

## Related projects

- [`getreeldev/reel-vex`](https://github.com/getreeldev/reel-vex) — free VEX resolution service; this library is its OVAL adapter's backbone.
- [`aquasecurity/trivy-db`](https://github.com/aquasecurity/trivy-db) — prior art we read while building this.
