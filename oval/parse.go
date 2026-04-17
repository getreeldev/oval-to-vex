package oval

import (
	"encoding/xml"
	"fmt"
	"io"
)

// Decode reads an OVAL 5.x definitions document from r and returns the
// parsed Document. The decoder is permissive about unknown elements so
// newer OVAL schema extensions don't trip parsing.
func Decode(r io.Reader) (*Document, error) {
	dec := xml.NewDecoder(r)
	// Red Hat's OVAL feed uses UTF-8 but declares explicit namespaces on
	// every element. Go's encoding/xml ignores namespaces by default,
	// matching fields on local element names — which is what we want.
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode OVAL: %w", err)
	}
	return &doc, nil
}
