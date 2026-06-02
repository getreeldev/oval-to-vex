# oval-to-vex

[![Go Reference](https://pkg.go.dev/badge/github.com/getreeldev/oval-to-vex.svg)](https://pkg.go.dev/github.com/getreeldev/oval-to-vex)

Go library that parses vendor OVAL XML (Red Hat, Ubuntu, and Debian) and emits VEX-shaped statements. Zero dependencies beyond the standard library.

Built so scanners and VEX hubs can consume vendor OVAL feeds without pulling in the full Trivy pipeline — in particular to recover the Red Hat EUS / AUS / E4S / SAP / HA / NFV stream coverage that Red Hat's CSAF VEX feed omits (see [SECDATA-1181](https://redhat.atlassian.net/browse/SECDATA-1181)), and to provide first-class Ubuntu USN and Debian Security Tracker coverage.

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

// Debian
stmts, err := translator.FromDebianOVAL(r)  // Debian Security Tracker feeds
```

Red Hat output (real data from `rhel-9.6-eus.oval.xml`):

```
CVE-2022-0413 fixed cpe:/a:redhat:rhel_eus:9.6::appstream
CVE-2022-0413 fixed cpe:/a:redhat:rhel_eus:9.6::baseos
CVE-2022-0413 fixed cpe:/a:redhat:rhel_eus:9.6::sap_hana
```

Ubuntu output (real data from `com.ubuntu.noble.usn.oval.xml`):

```
CVE-2024-26130 fixed pkg:deb/ubuntu/python3-cryptography?distro=ubuntu-24.04
CVE-2024-26130 fixed pkg:deb/ubuntu/python-cryptography-doc?distro=ubuntu-24.04
```

Debian output (real data from `oval-definitions-bookworm.xml`):

```
CVE-2021-44228 fixed pkg:deb/debian/apache-log4j2?distro=debian-12
CVE-2022-0778 fixed pkg:deb/debian/openssl?distro=debian-12
```

## CLI

A small CLI is included for smoke testing. Default vendor is `redhat`; pass `-vendor=ubuntu` or `-vendor=debian` for the others:

```bash
go install github.com/getreeldev/oval-to-vex/cmd/oval-to-vex@latest

# Red Hat
curl -sL https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.6-eus.oval.xml.bz2 \
  | bunzip2 | oval-to-vex > statements.json

# Ubuntu
curl -sL https://security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2 \
  | bunzip2 | oval-to-vex -vendor=ubuntu > statements.json

# Debian
curl -sL https://www.debian.org/security/oval/oval-definitions-bookworm.xml.bz2 \
  | bunzip2 | oval-to-vex -vendor=debian > statements.json
```

## What's covered

Red Hat (CPE-level, multi-stream EUS/AUS/E4S/SAP/HA/NFV), Ubuntu USN, and Debian Security Tracker feeds. Per-vendor parsing detail and what's out of scope: see [`docs/coverage.md`](docs/coverage.md).

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
    Vendor        string // "redhat", "ubuntu", or "debian"
}
```

Downstream consumers layer their own metadata (ingest timestamp, upstream source format, etc.) when they persist these.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for prior-art attribution.

## Related projects

- [`getreeldev/reel-vex`](https://github.com/getreeldev/reel-vex) — free VEX resolution service; this library is its OVAL adapter's backbone.
- [`aquasecurity/trivy-db`](https://github.com/aquasecurity/trivy-db) — prior art we read while building this.
