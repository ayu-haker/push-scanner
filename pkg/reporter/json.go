package reporter

import (
	"encoding/json"
	"io"

	"push-scanner/pkg/scanner"
)

type JSONReporter struct{}

func (j *JSONReporter) Report(w io.Writer, res scanner.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}
