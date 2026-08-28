package scanner

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type DockerLayerScanner struct{}

func (d *DockerLayerScanner) Name() string {
	return "DockerLayerScanner"
}

// DockerManifestEntry represents a manifest.json item inside exported Docker tar archives.
type DockerManifestEntry struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type LayerFileInfo struct {
	Path               string
	LayerIndex         int
	LayerHash          string
	IsWhiteout         bool
	IsOpaqueWhiteout   bool
	Content            []byte
	SizeBytes          int64
	StagedForPublish   bool
}

func (d *DockerLayerScanner) Scan(opts ScanOptions, files []TargetFile) ([]Finding, error) {
	var findings []Finding
	count := 1

	for _, f := range files {
		clean := filepath.ToSlash(f.Path)
		if !strings.HasSuffix(clean, ".tar") && !strings.HasSuffix(clean, "image.tar") {
			continue
		}

		layerFindings, err := ScanDockerTarContent(f.Path, f.Content, d.Name(), count)
		if err == nil {
			findings = append(findings, layerFindings...)
			count += len(layerFindings)
		}
	}

	return findings, nil
}

// ScanDockerImageFile scans an exported Docker image tarball file directly from disk.
func ScanDockerImageFile(tarPath string) ([]Finding, error) {
	data, err := os.ReadFile(tarPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Docker image tar file: %w", err)
	}
	scanner := &DockerLayerScanner{}
	return ScanDockerTarContent(filepath.Base(tarPath), data, scanner.Name(), 1)
}

// ScanDockerTarContent parses Docker image tar contents layer by layer.
func ScanDockerTarContent(tarName string, tarData []byte, scannerName string, startCount int) ([]Finding, error) {
	var findings []Finding
	count := startCount

	tr := tar.NewReader(bytes.NewReader(tarData))

	var manifest []DockerManifestEntry
	layerTarBytes := make(map[string][]byte)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		cleanName := filepath.ToSlash(hdr.Name)
		if cleanName == "manifest.json" {
			manifestData, _ := io.ReadAll(tr)
			_ = json.Unmarshal(manifestData, &manifest)
		} else if strings.HasSuffix(cleanName, ".tar") || strings.HasSuffix(cleanName, "/layer.tar") || strings.HasPrefix(cleanName, "blobs/sha256/") {
			layerData, _ := io.ReadAll(tr)
			layerTarBytes[cleanName] = layerData
		}
	}

	// Determine layer order
	var layerPaths []string
	if len(manifest) > 0 && len(manifest[0].Layers) > 0 {
		layerPaths = manifest[0].Layers
	} else {
		for p := range layerTarBytes {
			layerPaths = append(layerPaths, p)
		}
	}

	// Track files per layer
	fileHistory := make(map[string][]LayerFileInfo)
	secretScanner := &SecretScanner{}
	opts := ScanOptions{PolicyMode: "strict"}

	for idx, layerPath := range layerPaths {
		layerData, exists := layerTarBytes[layerPath]
		if !exists {
			continue
		}

		subTr := tar.NewReader(bytes.NewReader(layerData))
		layerHash := filepath.Base(filepath.Dir(layerPath))
		if layerHash == "." || layerHash == "/" {
			layerHash = fmt.Sprintf("layer_%d", idx+1)
		}

		for {
			hdr, err := subTr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}

			clean := filepath.ToSlash(hdr.Name)
			base := filepath.Base(clean)
			dir := filepath.Dir(clean)

			if base == ".wh..wh..opq" {
				// Opaque whiteout: clears directory
				fileHistory[dir] = append(fileHistory[dir], LayerFileInfo{
					Path:             dir,
					LayerIndex:       idx + 1,
					LayerHash:        layerHash,
					IsOpaqueWhiteout: true,
				})
			} else if strings.HasPrefix(base, ".wh.") {
				// Whiteout file deletion
				deletedFile := filepath.ToSlash(filepath.Join(dir, strings.TrimPrefix(base, ".wh.")))
				fileHistory[deletedFile] = append(fileHistory[deletedFile], LayerFileInfo{
					Path:       deletedFile,
					LayerIndex: idx + 1,
					LayerHash:  layerHash,
					IsWhiteout: true,
				})
			} else if !hdr.FileInfo().IsDir() {
				content, _ := io.ReadAll(subTr)
				info := LayerFileInfo{
					Path:             clean,
					LayerIndex:       idx + 1,
					LayerHash:        layerHash,
					Content:          content,
					SizeBytes:        hdr.Size,
					StagedForPublish: true,
				}
				fileHistory[clean] = append(fileHistory[clean], info)

				// Scan layer file content immediately for secrets
				tf := TargetFile{
					Path:               clean,
					SizeBytes:          hdr.Size,
					Content:            content,
					IsStagedForPublish: true,
				}
				secFindings, _ := secretScanner.Scan(opts, []TargetFile{tf})
				for _, sf := range secFindings {
					findings = append(findings, Finding{
						ID:          FormatFindingID("DOC", count),
						Title:       fmt.Sprintf("Secret Exposed in Intermediate Layer %d (%s)", idx+1, sf.Title),
						Description: fmt.Sprintf("Secret discovered inside container filesystem at `%s` in layer %d (`%s`).", clean, idx+1, layerHash),
						File:        fmt.Sprintf("%s => [Layer %d] %s", tarName, idx+1, clean),
						Line:        sf.Line,
						Scanner:     scannerName,
						Severity:    SeverityCritical,
						CWE:         sf.CWE,
						Remediation: "Do not include secrets in Docker build steps. Use BuildKit secret mounts (`RUN --mount=type=secret...`) or multi-stage builds.",
						IsHardBlock: true,
						Context:     fmt.Sprintf("Layer: %s, Snippet: %s", layerHash, sf.Context),
					})
					count++
				}
			}
		}
	}

	// Check for whiteouted (deleted) secrets across layer transitions
	for path, history := range fileHistory {
		if len(history) > 1 {
			firstRec := history[0]
			lastRec := history[len(history)-1]

			if lastRec.IsWhiteout && !firstRec.IsWhiteout && len(firstRec.Content) > 0 {
				// Verify if the deleted file in firstRec contained a secret or private key
				tf := TargetFile{
					Path:               path,
					SizeBytes:          int64(len(firstRec.Content)),
					Content:            firstRec.Content,
					IsStagedForPublish: true,
				}
				secFindings, _ := secretScanner.Scan(opts, []TargetFile{tf})
				if len(secFindings) > 0 {
					findings = append(findings, Finding{
						ID:          FormatFindingID("DOC", count),
						Title:       "Secret Deleted in Later Layer Persists in Intermediate Layer",
						Description: fmt.Sprintf("File `%s` contained secret in layer %d (`%s`) and was deleted (`.wh.`) in layer %d (`%s`). The secret bytes remain extractable via `docker history` or layer tarball extraction.", path, firstRec.LayerIndex, firstRec.LayerHash, lastRec.LayerIndex, lastRec.LayerHash),
						File:        fmt.Sprintf("%s => %s", tarName, path),
						Scanner:     scannerName,
						Severity:    SeverityCritical,
						CWE:         "CWE-200",
						Remediation: "Deleting a secret in a subsequent Docker layer does not purge it from earlier layers. Remove secret from build history.",
						IsHardBlock: true,
						Context:     fmt.Sprintf("Introduced: Layer %d (%s), Deleted: Layer %d (%s)", firstRec.LayerIndex, firstRec.LayerHash, lastRec.LayerIndex, lastRec.LayerHash),
					})
					count++
				}
			}
		}
	}

	return findings, nil
}
