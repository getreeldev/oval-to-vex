// Command oval-to-vex reads a Red Hat OVAL XML document from stdin and
// writes the VEX-shaped statements as JSON to stdout. Intended for local
// smoke-testing the library; production consumers should import the
// translator package directly.
//
// Example:
//
//	bunzip2 -c rhel-9.6-eus.oval.xml.bz2 | oval-to-vex > statements.json
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/getreeldev/oval-to-vex/translator"
)

func main() {
	stmts, err := translator.FromRedHatOVAL(os.Stdin)
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
