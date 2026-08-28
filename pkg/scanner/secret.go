package scanner

import (
	"bytes"
	"math"

	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type SecretScanner struct{}

func (s *SecretScanner) Name() string {
	return "SecretScanner"
}

type secretRule struct {
	Name        string
	Pattern     *regexp.Regexp
	CWE         string
	Description string
}

var secretRules = []secretRule{
	{
		Name:        "AWS Access Key ID",
		Pattern:     regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
		CWE:         "CWE-798",
		Description: "AWS Access Key ID discovered in code.",
	},
	{
		Name:        "GitHub Personal Access Token",
		Pattern:     regexp.MustCompile(`(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})`),
		CWE:         "CWE-798",
		Description: "GitHub Personal Access Token exposed in source file.",
	},
	{
		Name:        "OpenAI API Key",
		Pattern:     regexp.MustCompile(`sk-[a-zA-Z0-9]{48}`),
		CWE:         "CWE-798",
		Description: "OpenAI Secret API Key exposed.",
	},
	{
		Name:        "Stripe Live Key",
		Pattern:     regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,34}`),
		CWE:         "CWE-798",
		Description: "Stripe Live Secret Key exposed.",
	},
	{
		Name:        "Slack Token",
		Pattern:     regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}`),
		CWE:         "CWE-798",
		Description: "Slack API Bot or OAuth Token exposed.",
	},
	{
		Name:        "RSA / Elliptic Private Key",
		Pattern:     regexp.MustCompile(`-----BEGIN (RSA|EC|OPENSSH|DSA|PRIVATE) KEY-----`),
		CWE:         "CWE-312",
		Description: "Unencrypted Private Cryptographic Key file content.",
	},
	{
		Name:        "Google API Key",
		Pattern:     regexp.MustCompile(`AIzaSy[a-zA-Z0-9_-]{33}`),
		CWE:         "CWE-798",
		Description: "Google Cloud / Firebase API Key exposed.",
	},
	{
		Name:        "Database Connection URL with Password",
		Pattern:     regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis)://[^:]+:([^@]+)@`),
		CWE:         "CWE-798",
		Description: "Hardcoded database URI containing plaintext password.",
	},
}

func (s *SecretScanner) Scan(opts ScanOptions, files []TargetFile) ([]Finding, error) {
	var findings []Finding
	count := 1

	// If Gitleaks integration is enabled, attempt Gitleaks execution fallback first
	if opts.EnableGitleaks {
		if gitleaksFindings, err := runGitleaks(opts, files); err == nil && len(gitleaksFindings) > 0 {
			return gitleaksFindings, nil
		}
	}

	for _, f := range files {
		clean := filepath.ToSlash(f.Path)
		lower := strings.ToLower(clean)

		// Skip binary files or common binary extensions
		if isBinaryExtension(lower) {
			continue
		}

		lines := strings.Split(string(f.Content), "\n")
		for lineIdx, line := range lines {
			lineNum := lineIdx + 1
			trimmedLine := strings.TrimSpace(line)

			// 1. Check Regex Secret Rules
			for _, rule := range secretRules {
				loc := rule.Pattern.FindString(trimmedLine)
				if loc != "" {
					findings = append(findings, Finding{
						ID:                 FormatFindingID("SEC", count),
						Title:              rule.Name + " Exposed",
						Description:        rule.Description,
						File:               f.Path,
						Line:               lineNum,
						Scanner:            s.Name(),
						Severity:           SeverityCritical,
						CWE:                rule.CWE,
						Remediation:        "Revoke and rotate compromised credentials immediately. Remove secret from source control.",
						IsHardBlock:        true,
						Context:            redactSecret(trimmedLine, loc),
						IsStagedForPublish: f.IsStagedForPublish,
					})
					count++
					break
				}
			}

			// 2. High Shannon Entropy check for long suspicious string assignments
			if strings.Contains(trimmedLine, "=") || strings.Contains(trimmedLine, ":") {
				parts := strings.FieldsFunc(trimmedLine, func(r rune) bool {
					return r == '=' || r == ':' || r == '"' || r == '\'' || r == '`'
				})
				for _, part := range parts {
					part = strings.TrimSpace(part)
					if len(part) >= 32 && calculateEntropy(part) > 4.6 {
						findings = append(findings, Finding{
							ID:                 FormatFindingID("SEC", count),
							Title:              "High Entropy Secret Candidate Detected",
							Description:        "String value possesses unusually high Shannon entropy (>4.6), characteristic of API secret keys or access tokens.",
							File:               f.Path,
							Line:               lineNum,
							Scanner:            s.Name(),
							Severity:           SeverityHigh,
							CWE:                "CWE-798",
							Remediation:        "Verify if string is a secret token. If valid, move secret to environment variables.",
							IsHardBlock:        f.IsStagedForPublish,
							Context:            redactSecret(trimmedLine, part),
							IsStagedForPublish: f.IsStagedForPublish,
						})
						count++
						break
					}
				}
			}
		}
	}

	return findings, nil
}

func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func redactSecret(line, secret string) string {
	if len(secret) <= 4 {
		return strings.Replace(line, secret, "****", 1)
	}
	redacted := secret[:2] + strings.Repeat("*", len(secret)-4) + secret[len(secret)-2:]
	return strings.Replace(line, secret, redacted, 1)
}

func isBinaryExtension(path string) bool {
	ext := filepath.Ext(path)
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz", ".7z", ".exe", ".dll", ".so", ".dylib", ".wasm", ".db", ".sqlite":
		return true
	default:
		return false
	}
}

func runGitleaks(opts ScanOptions, files []TargetFile) ([]Finding, error) {
	cmd := exec.Command("gitleaks", "detect", "--no-git", "--source", opts.RootPath, "--format", "json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil && stdout.Len() == 0 {
		return nil, err
	}
	// Fallback logic if needed
	return nil, nil
}
