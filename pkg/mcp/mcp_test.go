package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExecuteMCPTools(t *testing.T) {
	// 1. Test check_file tool
	checkFileResult := executeMCPTool("check_file", map[string]interface{}{
		"path":    "src/index.js",
		"content": `const aws = "AKIA0000000000000000";`,
	})

	var res map[string]interface{}
	if err := json.Unmarshal([]byte(checkFileResult), &res); err != nil {
		t.Fatalf("Failed to parse check_file output JSON: %v", err)
	}
	if passed, _ := res["passed"].(bool); passed {
		t.Errorf("check_file should fail when AWS secret is present")
	}

	// 2. Test validate_publish tool
	validRes := executeMCPTool("validate_publish", map[string]interface{}{
		"path": ".",
	})
	if validRes == "" {
		t.Errorf("validate_publish output should not be empty")
	}

	// 3. Test explain_finding tool
	explanation := executeMCPTool("explain_finding", map[string]interface{}{
		"finding_id": "PS-SEC-001",
	})
	if !strings.Contains(explanation, "CWE-798") {
		t.Errorf("explain_finding should contain CWE-798 for PS-SEC-001, got: %s", explanation)
	}

	// 4. Test scan_docker_image error handling
	dockerRes := executeMCPTool("scan_docker_image", map[string]interface{}{
		"tar_path": "non_existent_image.tar",
	})
	if !strings.Contains(dockerRes, "Error scanning Docker image") {
		t.Errorf("Expected error message for non-existent image tarball, got: %s", dockerRes)
	}
}
