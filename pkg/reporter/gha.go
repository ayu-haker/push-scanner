package reporter

import (
	"fmt"
	"io"

	"push-scanner/pkg/scanner"
)

type GHAReporter struct{}

func (g *GHAReporter) Report(w io.Writer, res scanner.ScanResult) error {
	for _, f := range res.Findings {
		level := "warning"
		if f.Severity == scanner.SeverityCritical || f.Severity == scanner.SeverityHigh {
			level = "error"
		}
		lineStr := ""
		if f.Line > 0 {
			lineStr = fmt.Sprintf(",line=%d", f.Line)
		}
		fmt.Fprintf(w, "::%s file=%s%s,title=%s::%s (%s)\n", level, f.File, lineStr, f.Title, f.Description, f.Remediation)
	}
	return nil
}
