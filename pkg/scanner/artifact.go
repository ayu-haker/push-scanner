package scanner

import (
	"path/filepath"
	"strings"
)

type ArtifactScanner struct{}

func (a *ArtifactScanner) Name() string {
	return "ArtifactScanner"
}

func (a *ArtifactScanner) Scan(opts ScanOptions, files []TargetFile) ([]Finding, error) {
	var findings []Finding
	count := 1

	for _, f := range files {
		clean := filepath.ToSlash(f.Path)
		lower := strings.ToLower(clean)
		base := filepath.Base(lower)

		// Check for sensitive environment files
		if base == ".env" || strings.HasPrefix(base, ".env.") {
			sev := SeverityHigh
			if f.IsStagedForPublish {
				sev = SeverityCritical
			}
			findings = append(findings, Finding{
				ID:                 FormatFindingID("ART", count),
				Title:              "Environment Configuration File Included",
				Description:        "Environment files (.env) often contain secret tokens, DB passwords, and local state.",
				File:               f.Path,
				Scanner:            a.Name(),
				Severity:           sev,
				CWE:                "CWE-540",
				Remediation:        "Add `.env` files to `.npmignore`, `MANIFEST.in`, or `.gitignore`.",
				IsHardBlock:        f.IsStagedForPublish,
				IsStagedForPublish: f.IsStagedForPublish,
			})
			count++
		}

		// Check for private keys and certificates
		if strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".p12") || strings.HasSuffix(lower, ".pfx") || strings.HasSuffix(lower, ".key") || base == "id_rsa" || base == "id_ed25519" {
			findings = append(findings, Finding{
				ID:                 FormatFindingID("ART", count),
				Title:              "Private Key / Certificate File Detected",
				Description:        "Cryptographic private keys or certificates should never be published to public package registries.",
				File:               f.Path,
				Scanner:            a.Name(),
				Severity:           SeverityCritical,
				CWE:                "CWE-312",
				Remediation:        "Remove key/cert files from distribution and rotate compromised credentials immediately.",
				IsHardBlock:        true,
				IsStagedForPublish: f.IsStagedForPublish,
			})
			count++
		}

		// Check for raw databases or dumps
		if strings.HasSuffix(lower, ".sqlite") || strings.HasSuffix(lower, ".sqlite3") || strings.HasSuffix(lower, ".db") || strings.HasSuffix(lower, ".dump") || strings.HasSuffix(lower, ".sql") {
			findings = append(findings, Finding{
				ID:                 FormatFindingID("ART", count),
				Title:              "Database Dump File Detected",
				Description:        "Database files or SQL dumps can leak internal user data and schema details.",
				File:               f.Path,
				Scanner:            a.Name(),
				Severity:           SeverityHigh,
				CWE:                "CWE-200",
				Remediation:        "Exclude database files from package publish targets.",
				IsStagedForPublish: f.IsStagedForPublish,
			})
			count++
		}

		// Check for IDE / Editor workspace metadata
		if strings.HasPrefix(lower, ".vscode/") || strings.HasPrefix(lower, ".idea/") || base == ".ds_store" {
			if f.IsStagedForPublish {
				findings = append(findings, Finding{
					ID:                 FormatFindingID("ART", count),
					Title:              "IDE Workspace Metadata Staged for Publish",
					Description:        "IDE metadata directories contain local environment paths and personal developer settings.",
					File:               f.Path,
					Scanner:            a.Name(),
					Severity:           SeverityMedium,
					CWE:                "CWE-200",
					Remediation:        "Ignore `.vscode`, `.idea`, and `.DS_Store` in `.npmignore` or `.gitignore`.",
					IsStagedForPublish: true,
				})
				count++
			}
		}

		// Check for test fixtures / raw data left in publish target
		if f.IsStagedForPublish && (strings.Contains(lower, "test/fixtures/") || strings.Contains(lower, "__tests__/fixtures/") || strings.Contains(lower, "tests/data/")) {
			findings = append(findings, Finding{
				ID:                 FormatFindingID("ART", count),
				Title:              "Test Fixture Data Included in Published Output",
				Description:        "Test fixture files bloat package size and often contain dummy secrets or private internal mock data.",
				File:               f.Path,
				Scanner:            a.Name(),
				Severity:           SeverityLow,
				CWE:                "CWE-400",
				Remediation:        "Exclude test fixture directories from published package files.",
				IsStagedForPublish: true,
			})
			count++
		}
	}

	return findings, nil
}
