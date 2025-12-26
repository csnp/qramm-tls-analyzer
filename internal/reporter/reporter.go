// Package reporter provides output formatting for scan results.
package reporter

import (
	"io"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// Reporter defines the interface for output formatters.
type Reporter interface {
	// Report writes the scan result to the writer.
	Report(w io.Writer, result *types.ScanResult) error

	// Format returns the format name.
	Format() string
}

// Format represents supported output formats.
type Format string

const (
	FormatJSON  Format = "json"
	FormatText  Format = "text"
	FormatSARIF Format = "sarif"
	FormatCBOM  Format = "cbom"
	FormatHTML  Format = "html"
)

// New creates a new reporter for the given format.
func New(format Format) Reporter {
	switch format {
	case FormatJSON:
		return &JSONReporter{}
	case FormatText:
		return &TextReporter{}
	case FormatSARIF:
		return &SARIFReporter{}
	case FormatCBOM:
		return &CBOMReporter{}
	case FormatHTML:
		return &HTMLReporter{IncludeCSS: true}
	default:
		return &TextReporter{}
	}
}

// ValidFormats returns all valid format strings.
func ValidFormats() []string {
	return []string{
		string(FormatJSON),
		string(FormatText),
		string(FormatSARIF),
		string(FormatCBOM),
		string(FormatHTML),
	}
}
