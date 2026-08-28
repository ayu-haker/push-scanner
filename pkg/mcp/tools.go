package mcp

import (
	"encoding/json"
)

type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

var ListToolsResponse = []Tool{
	{
		Name:        "scan_project",
		Description: "Runs a full push-scanner pre-publish security audit on a project workspace. Identifies leaked secrets, unminified sourcemaps, raw test data, dangerous install scripts, unpinned dependencies, and Docker layer persistence issues.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"path": {
					"type": "string",
					"description": "Absolute or relative path to project workspace directory."
				},
				"mode": {
					"type": "string",
					"enum": ["default", "strict", "permissive"],
					"description": "Policy enforcement mode."
				}
			},
			"required": ["path"]
		}`),
	},
	{
		Name:        "check_file",
		Description: "Fast security check on a specific file content before saving or staging for publish.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"path": {
					"type": "string",
					"description": "Relative file path."
				},
				"content": {
					"type": "string",
					"description": "File text content."
				}
			},
			"required": ["path", "content"]
		}`),
	},
	{
		Name:        "validate_publish",
		Description: "Simulates package creation for npm or PyPI and returns whether package is safe to execute publish commands (npm publish / twine upload).",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"path": {
					"type": "string",
					"description": "Project workspace root path."
				},
				"ecosystem": {
					"type": "string",
					"enum": ["npm", "pypi", "auto"],
					"description": "Target ecosystem."
				}
			},
			"required": ["path"]
		}`),
	},
	{
		Name:        "scan_docker_image",
		Description: "Inspects an exported OCI/Docker container image archive (.tar) layer-by-layer to detect secrets introduced in early layers and deleted in upper layers.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"tar_path": {
					"type": "string",
					"description": "Path to exported Docker image tarball file."
				}
			},
			"required": ["tar_path"]
		}`),
	},
	{
		Name:        "explain_finding",
		Description: "Returns detailed CWE risk analysis, security impact, and step-by-step remediation guide for a specific push-scanner finding ID (e.g. PS-SEC-001, PS-CFG-001).",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"finding_id": {
					"type": "string",
					"description": "Finding ID code (e.g. PS-SEC-001)."
				}
			},
			"required": ["finding_id"]
		}`),
	},
}
