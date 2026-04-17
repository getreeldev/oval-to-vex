# oval-to-vex

[![Go Reference](https://pkg.go.dev/badge/github.com/getreeldev/oval-to-vex.svg)](https://pkg.go.dev/github.com/getreeldev/oval-to-vex)

Go library that parses Red Hat OVAL XML and emits VEX-shaped statements. Zero dependencies beyond the standard library.

Built so scanners and VEX hubs can consume Red Hat OVAL without pulling in the full Trivy pipeline — in particular to recover the EUS / AUS / E4S / SAP / HA / NFV stream coverage that Red Hat's CSAF VEX feed omits (see [SECDATA-1181](https://redhat.atlassian.net/browse/SECDATA-1181)).

## Install

```bash
go get github.com/getreeldev/oval-to-vex
```

## Use

```go
import "github.com/getreeldev/oval-to-vex/translator"

stmts, err := translator.FromRedHatOVAL(r)  // r is any io.Reader of OVAL XML
if err != nil {
    return err
}
for _, s := range stmts {
    fmt.Printf("%s %s %s\n", s.CVE, s.Status, s.ProductID)
}
```

Output (real data from `rhel-9.6-eus.oval.xml`):

```
CVE-2022-0413 fixed cpe:/a:redhat:rhel_eus:9.6::appstream
CVE-2022-0413 fixed cpe:/a:redhat:rhel_eus:9.6::baseos
CVE-2022-0413 fixed cpe:/a:redhat:rhel_eus:9.6::sap_hana
…
```

## CLI

A small CLI is included for smoke testing:

```bash
go install github.com/getreeldev/oval-to-vex/cmd/oval-to-vex@latest

curl -sL https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.6-eus.oval.xml.bz2 \
  | bunzip2 \
  | oval-to-vex \
  > statements.json
```

## What v0.1.0 covers

- OVAL 5.10 / 5.11 `<oval_definitions>` parsing (stdlib `encoding/xml`)
- One statement per `(CVE, CPE)` pair drawn from `<affected_cpe_list>`
- `class="patch"` → `status=fixed`
- `class="vulnerability"` → `status=affected`
- CVE dedupe across `<reference>` and `<advisory>/<cve>` elements

## What v0.1.0 does NOT cover (yet)

- RPM-level statements with version-range logic (walking the `<criteria>` tree). The VEX consumer gets platform/CPE coverage but not per-package affected-version granularity. Deferred to v0.2.0.
- Other vendors' OVAL (Ubuntu, Debian, SUSE). Add `FromUbuntuOVAL` etc. in subsequent minor releases — the type set is already vendor-agnostic.
- OVAL test / object / state applicability evaluation. The library extracts what the advisory *declares* about its CPEs; it doesn't evaluate whether a given host matches.

## Statement shape

```go
type Statement struct {
    CVE           string // e.g. "CVE-2024-0217"
    ProductID     string // vendor identifier, e.g. "cpe:/o:redhat:enterprise_linux:8"
    BaseID        string // normalized form for indexing
    Version       string // empty in v0.1.0 (CPE-level only)
    IDType        string // "cpe" or "purl"
    Status        string // "fixed" | "affected" | "not_affected" | "under_investigation"
    Justification string // e.g. "vulnerable_code_not_present"
    Vendor        string // e.g. "redhat"
}
```

Downstream consumers layer their own metadata (ingest timestamp, upstream source format, etc.) when they persist these.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for prior-art attribution.

## Related projects

- [`getreeldev/reel-vex`](https://github.com/getreeldev/reel-vex) — free VEX resolution service; this library is its OVAL adapter's backbone.
- [`aquasecurity/trivy-db`](https://github.com/aquasecurity/trivy-db) — prior art we read while building this.
