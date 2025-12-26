package reporter

import (
	"encoding/json"
	"io"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// JSONReporter outputs results in JSON format.
type JSONReporter struct {
	Compact bool
}

// Report writes the scan result as JSON.
func (r *JSONReporter) Report(w io.Writer, result *types.ScanResult) error {
	encoder := json.NewEncoder(w)
	if !r.Compact {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(result)
}

// Format returns the format name.
func (r *JSONReporter) Format() string {
	return string(FormatJSON)
}
