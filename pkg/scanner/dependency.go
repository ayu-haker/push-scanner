package scanner

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

type DependencyScanner struct{}

func (d *DependencyScanner) Name() string {
	return "DependencyScanner"
}

type npmDepManifest struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

var typosquatMap = map[string]string{
	"reqeusts":     "requests",
	"requets":      "requests",
	"expresss":     "express",
	"expres":       "express",
	"lodash-v2":    "lodash",
	"loadash":      "lodash",
	"axios-v2":     "axios",
	"react-dom-v2": "react-dom",
	"cross-env-v2": "cross-env",
	"urllib4":      "urllib3",
}

var unpinnedRegex = regexp.MustCompile(`^(\*|>=|>|\^0\.0|latest)`)

func (d *DependencyScanner) Scan(opts ScanOptions, files []TargetFile) ([]Finding, error) {
	var findings []Finding
	count := 1

	for _, f := range files {
		clean := filepath.ToSlash(f.Path)
		base := strings.ToLower(filepath.Base(clean))

		// 1. Inspect package.json
		if base == "package.json" {
			var pkg npmDepManifest
			if json.Unmarshal(f.Content, &pkg) == nil {
				allDeps := make(map[string]string)
				for k, v := range pkg.Dependencies {
					allDeps[k] = v
				}
				for k, v := range pkg.DevDependencies {
					allDeps[k] = v
				}

				for depName, version := range allDeps {
					lowerName := strings.ToLower(depName)

					// Check Typosquatting
					if orig, exists := typosquatMap[lowerName]; exists {
						findings = append(findings, Finding{
							ID:                 FormatFindingID("DEP", count),
							Title:              "Potential Typosquatting Dependency Detected: " + depName,
							Description:        "Package name `" + depName + "` closely mimics popular package `" + orig + "`. Typosquatting is frequently used in supply-chain malware attacks.",
							File:               f.Path,
							Scanner:            d.Name(),
							Severity:           SeverityCritical,
							CWE:                "CWE-829",
							Remediation:        "Verify package name. Change dependency to official package `" + orig + "`.",
							Context:            depName + ": " + version,
							IsHardBlock:        true,
							IsStagedForPublish: f.IsStagedForPublish,
						})
						count++
					}

					// Check Raw HTTP/Git URLs
					if strings.HasPrefix(version, "git+") || strings.HasPrefix(version, "http://") || strings.HasPrefix(version, "git://") {
						findings = append(findings, Finding{
							ID:                 FormatFindingID("DEP", count),
							Title:              "Unverified Git/HTTP Direct URL Dependency: " + depName,
							Description:        "Direct git or HTTP URL dependencies bypass package registry integrity checks and can change unpredictably.",
							File:               f.Path,
							Scanner:            d.Name(),
							Severity:           SeverityHigh,
							CWE:                "CWE-829",
							Remediation:        "Use pinned npm registry versions or verified git commit SHAs.",
							Context:            depName + ": " + version,
							IsStagedForPublish: f.IsStagedForPublish,
						})
						count++
					}

					// Check Unpinned dependencies
					if unpinnedRegex.MatchString(version) {
						findings = append(findings, Finding{
							ID:                 FormatFindingID("DEP", count),
							Title:              "Unpinned Dependency Version: " + depName,
							Description:        "Wildcard or loose version ranges (`*`, `latest`) allow unverified upstream minor/patch releases to introduce breaking changes or compromised code.",
							File:               f.Path,
							Scanner:            d.Name(),
							Severity:           SeverityMedium,
							CWE:                "CWE-1104",
							Remediation:        "Pin dependency to exact version or strict semantic range (e.g. `^1.2.3`).",
							Context:            depName + ": " + version,
							IsStagedForPublish: f.IsStagedForPublish,
						})
						count++
					}
				}
			}
		}

		// 2. Inspect requirements.txt
		if base == "requirements.txt" {
			lines := strings.Split(string(f.Content), "\n")
			for _, line := range lines {
				l := strings.TrimSpace(line)
				if l == "" || strings.HasPrefix(l, "#") {
					continue
				}
				lowerLine := strings.ToLower(l)
				for typo, orig := range typosquatMap {
					if strings.HasPrefix(lowerLine, typo) {
						findings = append(findings, Finding{
							ID:                 FormatFindingID("DEP", count),
							Title:              "Potential Typosquatting Dependency in requirements.txt",
							Description:        "Python package `" + l + "` matches known typosquatting signature for `" + orig + "`.",
							File:               f.Path,
							Scanner:            d.Name(),
							Severity:           SeverityCritical,
							CWE:                "CWE-829",
							Remediation:        "Replace suspicious requirement `" + typo + "` with `" + orig + "`.",
							Context:            l,
							IsHardBlock:        true,
							IsStagedForPublish: f.IsStagedForPublish,
						})
						count++
					}
				}
			}
		}
	}

	return findings, nil
}
