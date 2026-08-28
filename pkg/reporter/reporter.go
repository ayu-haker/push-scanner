package reporter

import (
	"io"
	"push-scanner/pkg/scanner"
)

// Reporter formats scan results for terminal, JSON, SARIF, or GitHub Actions.
type Reporter interface {
	Report(w io.Writer, res scanner.ScanResult) error
}
