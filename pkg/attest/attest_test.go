package attest

import (
	"encoding/json"
	"testing"
	"time"

	"push-scanner/pkg/scanner"
)

func TestGenerateSLSAAttestation(t *testing.T) {
	resPassed := scanner.ScanResult{
		RootPath:          "my-app",
		Timestamp:         time.Now(),
		TotalFilesScanned: 5,
		StagedFilesCount:  3,
		Passed:            true,
		PolicyMode:        "strict",
		EnvironmentRing:   "prod",
		Team:              "platform-sec",
	}

	data, err := GenerateSLSAAttestation(resPassed)
	if err != nil {
		t.Fatalf("Failed to generate SLSA Attestation: %v", err)
	}

	var stmt map[string]interface{}
	if err := json.Unmarshal(data, &stmt); err != nil {
		t.Fatalf("Invalid JSON produced for SLSA Attestation: %v", err)
	}

	if predType, _ := stmt["predicateType"].(string); predType != "https://slsa.dev/provenance/v1" {
		t.Errorf("Expected predicateType https://slsa.dev/provenance/v1, got %s", predType)
	}

	// Verify failure case
	resFailed := scanner.ScanResult{Passed: false}
	_, errFailed := GenerateSLSAAttestation(resFailed)
	if errFailed == nil {
		t.Errorf("Expected error when generating attestation for failed scan result")
	}
}
