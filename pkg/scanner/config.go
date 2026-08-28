package scanner

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

type ConfigScanner struct{}

func (c *ConfigScanner) Name() string {
	return "ConfigScanner"
}

type npmPackageConfig struct {
	Scripts map[string]string `json:"scripts"`
}

var dangerousCmdRegex = regexp.MustCompile(`(?i)(curl|wget|powershell|cmd\.exe|bash\s+-c|sh\s+-c|eval|nc\s+-e|netcat)`)

func (c *ConfigScanner) Scan(opts ScanOptions, files []TargetFile) ([]Finding, error) {
	var findings []Finding
	count := 1

	for _, f := range files {
		clean := filepath.ToSlash(f.Path)
		lower := strings.ToLower(clean)
		base := filepath.Base(lower)

		// 1. Inspect package.json
		if base == "package.json" {
			var pkg npmPackageConfig
			if err := json.Unmarshal(f.Content, &pkg); err == nil {
				for scriptName, scriptCmd := range pkg.Scripts {
					// Check lifecycle hooks
					if scriptName == "preinstall" || scriptName == "postinstall" || scriptName == "install" {
						sev := SeverityMedium
						if dangerousCmdRegex.MatchString(scriptCmd) {
							sev = SeverityCritical
						}
						findings = append(findings, Finding{
							ID:                 FormatFindingID("CFG", count),
							Title:              "Package Lifecycle Hook Detected: " + scriptName,
							Description:        "Lifecycle scripts run automatically when consumers install your package. Malicious packages abuse install scripts for execution supply-chain attacks.",
							File:               f.Path,
							Scanner:            c.Name(),
							Severity:           sev,
							CWE:                "CWE-829",
							Remediation:        "Avoid using `preinstall` or `postinstall` hooks unless strictly necessary. Ensure installation scripts do not fetch remote binaries via `curl | bash`.",
							Context:            scriptName + ": " + scriptCmd,
							IsStagedForPublish: f.IsStagedForPublish,
						})
						count++
					} else if dangerousCmdRegex.MatchString(scriptCmd) {
						findings = append(findings, Finding{
							ID:                 FormatFindingID("CFG", count),
							Title:              "Dangerous Command Pattern in Script: " + scriptName,
							Description:        "Package script invokes remote execution or shell commands which may leak credentials or execute unverified payloads.",
							File:               f.Path,
							Scanner:            c.Name(),
							Severity:           SeverityHigh,
							CWE:                "CWE-78",
							Remediation:        "Review script definition and eliminate direct unverified remote script downloads.",
							Context:            scriptName + ": " + scriptCmd,
							IsStagedForPublish: f.IsStagedForPublish,
						})
						count++
					}
				}
			}
		}

		// 2. Inspect .npmrc / .pypirc for auth tokens
		if base == ".npmrc" || base == ".pypirc" {
			contentStr := string(f.Content)
			if strings.Contains(contentStr, "_authToken=") || strings.Contains(contentStr, "password =") || strings.Contains(contentStr, "secret=") {
				findings = append(findings, Finding{
					ID:                 FormatFindingID("CFG", count),
					Title:              "Exposed Registry Auth Token in Config File",
					Description:        "Configuration file contains plaintext auth tokens or registry secrets.",
					File:               f.Path,
					Scanner:            c.Name(),
					Severity:           SeverityCritical,
					CWE:                "CWE-798",
					Remediation:        "Use environment variables (e.g. `${NPM_TOKEN}`) instead of committing raw tokens to `.npmrc` or `.pypirc`.",
					IsHardBlock:        true,
					IsStagedForPublish: f.IsStagedForPublish,
				})
				count++
			}
		}
	}

	return findings, nil
}
