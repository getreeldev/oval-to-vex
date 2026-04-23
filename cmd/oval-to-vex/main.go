// Command oval-to-vex reads an OVAL XML document from stdin and writes
// the VEX-shaped statements as JSON to stdout. Intended for local
// smoke-testing the library; production consumers should import the
// translator package directly.
//
// Examples:
//
//	bunzip2 -c rhel-9.6-eus.oval.xml.bz2                    | oval-to-vex > out.json
//	bunzip2 -c com.ubuntu.noble.usn.oval.xml.bz2            | oval-to-vex -vendor=ubuntu > out.json
//	bunzip2 -c oval-definitions-bookworm.xml.bz2            | oval-to-vex -vendor=debian > out.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/getreeldev/oval-to-vex/translator"
)

func main() {
	vendor := flag.String("vendor", "redhat", "OVAL vendor: redhat, ubuntu, or debian")
	flag.Parse()

	var (
		stmts []translator.Statement
		err   error
	)
	switch *vendor {
	case "redhat":
		stmts, err = translator.FromRedHatOVAL(os.Stdin)
	case "ubuntu":
		stmts, err = translator.FromUbuntuOVAL(os.Stdin)
	case "debian":
		stmts, err = translator.FromDebianOVAL(os.Stdin)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown vendor %q (want redhat, ubuntu, or debian)\n", *vendor)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(stmts); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
