package scanner

import (
	"archive/tar"
	"bytes"
	"testing"
)

func TestDockerLayerScannerWhiteoutDetection(t *testing.T) {
	// 1. Create sub-tar for Layer 1 containing secret
	var layer1Buf bytes.Buffer
	tw1 := tar.NewWriter(&layer1Buf)
	secretContent := []byte("AWS_SECRET=AKIA0000000000000000")
	_ = tw1.WriteHeader(&tar.Header{
		Name: "app/secret.key",
		Mode: 0644,
		Size: int64(len(secretContent)),
	})
	_, _ = tw1.Write(secretContent)
	_ = tw1.Close()

	// 2. Create sub-tar for Layer 2 containing whiteout (.wh.secret.key)
	var layer2Buf bytes.Buffer
	tw2 := tar.NewWriter(&layer2Buf)
	_ = tw2.WriteHeader(&tar.Header{
		Name: "app/.wh.secret.key",
		Mode: 0644,
		Size: 0,
	})
	_ = tw2.Close()

	// 3. Construct outer Docker image archive containing manifest.json and the 2 layer tars
	var mainBuf bytes.Buffer
	twMain := tar.NewWriter(&mainBuf)

	manifestData := []byte(`[{"Config":"config.json","RepoTags":["test:latest"],"Layers":["layer1/layer.tar","layer2/layer.tar"]}]`)
	_ = twMain.WriteHeader(&tar.Header{
		Name: "manifest.json",
		Mode: 0644,
		Size: int64(len(manifestData)),
	})
	_, _ = twMain.Write(manifestData)

	_ = twMain.WriteHeader(&tar.Header{
		Name: "layer1/layer.tar",
		Mode: 0644,
		Size: int64(layer1Buf.Len()),
	})
	_, _ = twMain.Write(layer1Buf.Bytes())

	_ = twMain.WriteHeader(&tar.Header{
		Name: "layer2/layer.tar",
		Mode: 0644,
		Size: int64(layer2Buf.Len()),
	})
	_, _ = twMain.Write(layer2Buf.Bytes())
	_ = twMain.Close()

	// 4. Run DockerLayerScanner
	findings, err := ScanDockerTarContent("mock-image.tar", mainBuf.Bytes(), "DockerLayerScanner", 1)
	if err != nil {
		t.Fatalf("Unexpected error scanning Docker tar content: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("Expected findings for intermediate layer secret persistence, got 0")
	}

	foundWhiteoutLeak := false
	for _, f := range findings {
		if f.ID == "PS-DOC-002" || f.Title == "Secret Deleted in Later Layer Persists in Intermediate Layer" || f.Scanner == "DockerLayerScanner" {
			foundWhiteoutLeak = true
			if !f.IsHardBlock {
				t.Errorf("Docker layer finding should trigger hard block")
			}
		}
	}

	if !foundWhiteoutLeak {
		t.Errorf("Failed to detect whiteout secret leak across Docker layers")
	}
}
