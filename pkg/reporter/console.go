package reporter

import (
	"fmt"
	"io"

	"push-scanner/pkg/scanner"
)

type ConsoleReporter struct{}

func (c *ConsoleReporter) Report(w io.Writer, res scanner.ScanResult) error {
	fmt.Fprintln(w, "=========================================================================")
	fmt.Fprintln(w, "                    PUSH-SCANNER PRE-PUBLISH SECURITY GATE              ")
	fmt.Fprintln(w, "=========================================================================")
	fmt.Fprintf(w, " Target Directory : %s\n", res.RootPath)
	fmt.Fprintf(w, " Policy Mode      : %s\n", res.PolicyMode)
	fmt.Fprintf(w, " Scanned Files    : %d (Staged for Publish: %d)\n", res.TotalFilesScanned, res.StagedFilesCount)
	fmt.Fprintf(w, " Scan Duration    : %d ms\n", res.DurationMs)
	fmt.Fprintln(w, "-------------------------------------------------------------------------")

	if len(res.Findings) == 0 {
		fmt.Fprintln(w, " \033[32m✔ SUCCESS: Zero security issues detected. Safe to publish!\033[0m")
		fmt.Fprintln(w, "=========================================================================")
		return nil
	}

	fmt.Fprintf(w, " Total Findings   : %d\n", len(res.Findings))
	fmt.Fprintf(w, " Summary          : [CRITICAL: %d | HIGH: %d | MEDIUM: %d | LOW: %d | INFO: %d]\n\n",
		res.Summary[scanner.SeverityCritical],
		res.Summary[scanner.SeverityHigh],
		res.Summary[scanner.SeverityMedium],
		res.Summary[scanner.SeverityLow],
		res.Summary[scanner.SeverityInfo])

	for i, f := range res.Findings {
		sevBadge := formatSeverityBadge(f.Severity)
		stagedBadge := ""
		if f.IsStagedForPublish {
			stagedBadge = " \033[31m[STAGED FOR PUBLISH]\033[0m"
		}

		fmt.Fprintf(w, " [%d] %s %s (%s)%s\n", i+1, sevBadge, f.Title, f.ID, stagedBadge)
		fmt.Fprintf(w, "     File        : %s", f.File)
		if f.Line > 0 {
			fmt.Fprintf(w, ":%d", f.Line)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "     Scanner     : %s (CWE: %s)\n", f.Scanner, f.CWE)
		fmt.Fprintf(w, "     Description : %s\n", f.Description)
		if f.Context != "" {
			fmt.Fprintf(w, "     Snippet     : \033[33m%s\033[0m\n", f.Context)
		}
		fmt.Fprintf(w, "     Remediation : %s\n", f.Remediation)
		fmt.Fprintln(w, " -----------------------------------------------------------------------")
	}

	if !res.Passed {
		fmt.Fprintln(w, " \033[31m✘ PRE-PUBLISH GATE FAILED!\033[0m Security policy violations must be resolved.")
		if res.HardBlockTriggered {
			fmt.Fprintln(w, " \033[31m  CRITICAL HARD-BLOCK TRIGGERED: Live secret or private key present!\033[0m")
		}
	} else {
		fmt.Fprintln(w, " \033[33m! WARNINGS PRESENT: Scan passed policy threshold, but findings remain.\033[0m")
	}
	fmt.Fprintln(w, "=========================================================================")

	return nil
}

func formatSeverityBadge(sev scanner.Severity) string {
	switch sev {
	case scanner.SeverityCritical:
		return "\033[41m\033[37m CRITICAL \033[0m"
	case scanner.SeverityHigh:
		return "\033[31m HIGH \033[0m"
	case scanner.SeverityMedium:
		return "\033[33m MEDIUM \033[0m"
	case scanner.SeverityLow:
		return "\033[36m LOW \033[0m"
	default:
		return "\033[37m INFO \033[0m"
	}
}
