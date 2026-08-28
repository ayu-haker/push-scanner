package policy

import (
	"path/filepath"
	"strings"

	"push-scanner/pkg/scanner"
)

type PolicyEngine struct {
	Config Config
}

func NewPolicyEngine(cfg Config) *PolicyEngine {
	return &PolicyEngine{Config: cfg}
}

func (pe *PolicyEngine) Evaluate(findings []scanner.Finding, mode string) ([]scanner.Finding, bool, bool) {
	if mode == "" {
		mode = pe.Config.PolicyMode
	}
	if mode == "" {
		mode = "default"
	}

	ring := strings.ToLower(pe.Config.EnvironmentRing)
	if ring == "" {
		ring = "dev"
	}

	var filtered []scanner.Finding
	passed := true
	hardBlockTriggered := false

	ignoredRulesMap := make(map[string]bool)
	for _, id := range pe.Config.IgnoreRules {
		ignoredRulesMap[id] = true
	}

	for _, f := range findings {
		if ignoredRulesMap[f.ID] {
			continue
		}

		if isPathIgnored(f.File, pe.Config.IgnorePaths) {
			continue
		}

		if (mode == "strict" || pe.Config.StrictAIMode) && f.AISignal && f.Severity == scanner.SeverityInfo {
			f.Severity = scanner.SeverityMedium
			f.Description += " (Escalated due to Strict AI policy mode)."
		}

		if f.IsHardBlock {
			hardBlockTriggered = true
			passed = false
		}

		// Environment Ring Enforcement Logic
		switch ring {
		case "prod":
			// Prod ring: zero tolerance for Medium, High, or Critical
			if f.Severity.Rank() >= scanner.SeverityMedium.Rank() {
				passed = false
			}
		case "staging":
			// Staging ring: fails on High or Critical
			if f.Severity.Rank() >= scanner.SeverityHigh.Rank() {
				passed = false
			}
		case "dev":
			fallthrough
		default:
			// Dev ring: passes unless hard block is present
			switch strings.ToLower(mode) {
			case "strict":
				if f.Severity.Rank() >= scanner.SeverityMedium.Rank() {
					passed = false
				}
			case "permissive":
				if f.Severity == scanner.SeverityCritical || f.IsHardBlock {
					passed = false
				}
			default:
				if f.Severity.Rank() >= scanner.SeverityHigh.Rank() {
					passed = false
				}
			}
		}

		filtered = append(filtered, f)
	}

	return filtered, passed, hardBlockTriggered
}

func isPathIgnored(path string, ignorePatterns []string) bool {
	cleanPath := filepath.ToSlash(path)
	for _, pat := range ignorePatterns {
		patClean := filepath.ToSlash(pat)
		if strings.Contains(cleanPath, strings.TrimSuffix(patClean, "/**")) {
			return true
		}
		matched, _ := filepath.Match(patClean, cleanPath)
		if matched {
			return true
		}
	}
	return false
}
