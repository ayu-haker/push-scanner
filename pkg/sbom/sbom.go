package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"push-scanner/pkg/scanner"
)

// CycloneDX BOM models for v1.5 JSON specification
type CycloneDXBOM struct {
	BOMFormat    string              `json:"bomFormat"`
	SpecVersion  string              `json:"specVersion"`
	SerialNumber string              `json:"serialNumber"`
	Version      int                 `json:"version"`
	Metadata     BOMMetadata         `json:"metadata"`
	Components   []Component         `json:"components"`
	Dependencies []BOMDependency     `json:"dependencies,omitempty"`
}

type BOMMetadata struct {
	Timestamp time.Time `json:"timestamp"`
	Tool      BOMTool   `json:"tool"`
	Component Component `json:"component"`
}

type BOMTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Component struct {
	Type       string     `json:"type"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	Hashes     []Hash     `json:"hashes,omitempty"`
	Licenses   []License  `json:"licenses,omitempty"`
}

type Hash struct {
	Algorithm string `json:"alg"`
	Value     string `json:"content"`
}

type License struct {
	Expression string `json:"expression,omitempty"`
}

type BOMDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// GenerateCycloneDX creates a CycloneDX v1.5 JSON SBOM payload for a passing scan.
func GenerateCycloneDX(res scanner.ScanResult, files []scanner.TargetFile) ([]byte, error) {
	bom := CycloneDXBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:" + fmtUUID(time.Now().UnixNano()),
		Version:      1,
		Metadata: BOMMetadata{
			Timestamp: time.Now(),
			Tool: BOMTool{
				Vendor:  "push-scanner",
				Name:    "push-scanner",
				Version: "0.4.0",
			},
			Component: Component{
				Type: "application",
				Name: filepath.Base(res.RootPath),
			},
		},
		Components: make([]Component, 0),
	}

	for _, f := range files {
		if !f.IsStagedForPublish || len(f.Content) == 0 {
			continue
		}

		cleanPath := filepath.ToSlash(f.Path)
		h := sha256.Sum256(f.Content)
		shaHex := hex.EncodeToString(h[:])

		comp := Component{
			Type: "file",
			Name: cleanPath,
			Hashes: []Hash{
				{Algorithm: "SHA-256", Value: shaHex},
			},
		}

		if strings.HasSuffix(cleanPath, "package.json") {
			comp.Type = "framework"
			comp.PURL = "pkg:npm/" + filepath.Base(res.RootPath)
		} else if strings.HasSuffix(cleanPath, "pyproject.toml") {
			comp.Type = "framework"
			comp.PURL = "pkg:pypi/" + filepath.Base(res.RootPath)
		}

		bom.Components = append(bom.Components, comp)
	}

	return json.MarshalIndent(bom, "", "  ")
}

func fmtUUID(n int64) string {
	h := sha256.Sum256([]byte(string(rune(n))))
	hexStr := hex.EncodeToString(h[:])
	return hexStr[:8] + "-" + hexStr[8:12] + "-" + hexStr[12:16] + "-" + hexStr[16:20] + "-" + hexStr[20:32]
}
