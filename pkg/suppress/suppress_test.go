package suppress

import (
	"os"
	"path/filepath"
	"testing"

	"push-scanner/pkg/scanner"
)

func TestBaselineSuppressionEngine(t *testing.T) {
	tempDir := t.TempDir()
	baselinePath := filepath.Join(tempDir, ".push-scanner-baseline.json")

	finding1 := scanner.Finding{
		ID:          "PS-SEC-001",
		Title:       "AWS Key",
		File:        "config.js",
		Scanner:     "SecretScanner",
		CWE:         "CWE-798",
		Line:        10,
		Severity:    scanner.SeverityCritical,
		IsHardBlock: true,
	}

	finding2 := scanner.Finding{
		ID:       "PS-ART-001",
		Title:    "Environment file",
		File:     ".env",
		Scanner:  "ArtifactScanner",
		CWE:      "CWE-540",
		Line:     1,
		Severity: scanner.SeverityHigh,
	}

	// 1. Save finding1 to baseline
	if err := SaveBaseline(baselinePath, []scanner.Finding{finding1}); err != nil {
		t.Fatalf("Failed to save baseline: %v", err)
	}

	// 2. Load baseline back
	loaded, err := LoadBaseline(baselinePath)
	if err != nil {
		t.Fatalf("Failed to load baseline: %v", err)
	}

	if len(loaded.Items) != 1 {
		t.Fatalf("Expected 1 baseline item, got %d", len(loaded.Items))
	}

	// 3. Filter findings (finding1 should be suppressed, finding2 should remain active)
	active, suppressed := FilterFindings(loaded, []scanner.Finding{finding1, finding2})

	if len(suppressed) != 1 || suppressed[0].ID != "PS-SEC-001" {
		t.Errorf("finding1 should be suppressed")
	}

	if len(active) != 1 || active[0].ID != "PS-ART-001" {
		t.Errorf("finding2 should remain active")
	}

	_ = os.Remove(baselinePath)
}
