package policy

import (
	"testing"

	"push-scanner/pkg/scanner"
)

func TestPolicyEngineModes(t *testing.T) {
	cfg := DefaultConfig()
	pe := NewPolicyEngine(cfg)

	findings := []scanner.Finding{
		{
			ID:          "PS-SEC-001",
			Title:       "Exposed AWS Key",
			Severity:    scanner.SeverityCritical,
			IsHardBlock: true,
		},
		{
			ID:       "PS-ART-001",
			Title:    "Medium severity artifact",
			Severity: scanner.SeverityMedium,
		},
	}

	// Default Mode (Blocks on Critical / High)
	_, passedDefault, hardBlockDefault := pe.Evaluate(findings, "default")
	if passedDefault {
		t.Errorf("Default mode should fail on Critical finding")
	}
	if !hardBlockDefault {
		t.Errorf("Hard block should be triggered")
	}

	// Permissive Mode (Fails on Critical / Hard block, passes Medium)
	mediumOnly := []scanner.Finding{
		{
			ID:       "PS-ART-001",
			Title:    "Medium severity artifact",
			Severity: scanner.SeverityMedium,
		},
	}
	_, passedPermissive, _ := pe.Evaluate(mediumOnly, "permissive")
	if !passedPermissive {
		t.Errorf("Permissive mode should pass Medium severity finding")
	}

	// Strict Mode (Fails on Medium severity)
	_, passedStrict, _ := pe.Evaluate(mediumOnly, "strict")
	if passedStrict {
		t.Errorf("Strict mode should fail on Medium severity finding")
	}
}
