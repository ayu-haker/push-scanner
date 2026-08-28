package sbom

import (
	"encoding/json"
	"testing"
	"time"

	"push-scanner/pkg/scanner"
)

func TestGenerateCycloneDX(t *testing.T) {
	res := scanner.ScanResult{
		RootPath:          "my-pkg",
		Timestamp:         time.Now(),
		TotalFilesScanned: 2,
		StagedFilesCount:  2,
		Passed:            true,
	}

	files := []scanner.TargetFile{
		{
			Path:               "package.json",
			Content:            []byte(`{"name": "my-pkg", "version": "1.0.0"}`),
			IsStagedForPublish: true,
		},
		{
			Path:               "index.js",
			Content:            []byte(`console.log("hello");`),
			IsStagedForPublish: true,
		},
	}

	data, err := GenerateCycloneDX(res, files)
	if err != nil {
		t.Fatalf("Failed to generate CycloneDX SBOM: %v", err)
	}

	var bom map[string]interface{}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("Invalid JSON produced for CycloneDX SBOM: %v", err)
	}

	if bomFormat, _ := bom["bomFormat"].(string); bomFormat != "CycloneDX" {
		t.Errorf("Expected bomFormat CycloneDX, got %s", bomFormat)
	}

	comps, ok := bom["components"].([]interface{})
	if !ok || len(comps) != 2 {
		t.Errorf("Expected 2 SBOM components, got %d", len(comps))
	}
}
