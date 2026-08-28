package scanner

import (
	"path/filepath"
	"regexp"
	"strings"
)

type AISignalScanner struct{}

func (a *AISignalScanner) Name() string {
	return "AISignalScanner"
}

var aiProvenanceRegex = regexp.MustCompile(`(?i)(generated\s+by\s+(claude|chatgpt|copilot|gemini|vibe-coder|ai)|#\s*prompt:|//\s*ai-assisted|\bllm-generated\b)`)

func (a *AISignalScanner) Scan(opts ScanOptions, files []TargetFile) ([]Finding, error) {
	var findings []Finding
	count := 1

	for _, f := range files {
		clean := filepath.ToSlash(f.Path)
		lower := strings.ToLower(clean)

		if isBinaryExtension(lower) {
			continue
		}

		lines := strings.Split(string(f.Content), "\n")
		for lineIdx, line := range lines {
			lineNum := lineIdx + 1
			trimmed := strings.TrimSpace(line)

			if loc := aiProvenanceRegex.FindString(trimmed); loc != "" {
				findings = append(findings, Finding{
					ID:                 FormatFindingID("AIS", count),
					Title:              "AI-Generated Code Signal Detected",
					Description:        "Source file contains code generation metadata (`" + loc + "`). AI-assisted code requires heightened policy enforcement to prevent unverified dependencies, secrets, or sourcemap leaks.",
					File:               f.Path,
					Line:               lineNum,
					Scanner:            a.Name(),
					Severity:           SeverityInfo,
					CWE:                "CWE-1104",
					Remediation:        "Review AI-generated code snippets for security compliance before publishing.",
					AISignal:           true,
					Context:            trimmed,
					IsStagedForPublish: f.IsStagedForPublish,
				})
				count++
				break
			}
		}
	}

	return findings, nil
}
