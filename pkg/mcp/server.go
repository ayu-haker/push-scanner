package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"push-scanner/pkg/attest"
	"push-scanner/pkg/packager"
	"push-scanner/pkg/policy"
	"push-scanner/pkg/reporter"
	"push-scanner/pkg/sbom"
	"push-scanner/pkg/scanner"
	"push-scanner/pkg/suppress"
)

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func StartMCPServer() error {
	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			sendError(nil, -32700, "Parse error")
			continue
		}

		handleRequest(req)
	}
}

func handleRequest(req JSONRPCRequest) {
	switch req.Method {
	case "initialize":
		sendResponse(req.ID, map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]string{
				"name":    "push-scanner",
				"version": "0.4.0",
			},
		})
	case "notifications/initialized":
	case "tools/list":
		sendResponse(req.ID, map[string]interface{}{
			"tools": ListToolsResponse,
		})
	case "tools/call":
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			sendError(req.ID, -32602, "Invalid params")
			return
		}
		resultText := executeMCPTool(params.Name, params.Arguments)
		sendResponse(req.ID, map[string]interface{}{
			"content": []map[string]string{
				{
					"type": "text",
					"text": resultText,
				},
			},
		})
	default:
		sendError(req.ID, -32601, "Method not found: "+req.Method)
	}
}

func executeMCPTool(name string, args map[string]interface{}) string {
	switch name {
	case "scan_project":
		path, _ := args["path"].(string)
		if path == "" {
			path = "."
		}
		mode, _ := args["mode"].(string)
		if mode == "" {
			mode = "default"
		}
		ring, _ := args["ring"].(string)

		res := ExecuteScan(scanner.ScanOptions{
			RootPath:   path,
			PolicyMode: mode,
			Ring:       ring,
		})

		var buf bytes.Buffer
		rep := &reporter.ConsoleReporter{}
		_ = rep.Report(&buf, res)
		return buf.String()

	case "check_file":
		relPath, _ := args["path"].(string)
		contentStr, _ := args["content"].(string)

		file := scanner.TargetFile{
			Path:               relPath,
			SizeBytes:          int64(len(contentStr)),
			Content:            []byte(contentStr),
			IsStagedForPublish: true,
		}

		scanners := []scanner.Scanner{
			&scanner.SecretScanner{},
			&scanner.ArtifactScanner{},
			&scanner.SourceMapScanner{},
			&scanner.ConfigScanner{},
			&scanner.AISignalScanner{},
		}

		var findings []scanner.Finding
		opts := scanner.ScanOptions{PolicyMode: "strict"}
		for _, s := range scanners {
			f, _ := s.Scan(opts, []scanner.TargetFile{file})
			findings = append(findings, f...)
		}

		res := scanner.ScanResult{
			RootPath:           relPath,
			Timestamp:          time.Now(),
			Findings:           findings,
			TotalFilesScanned:  1,
			StagedFilesCount:   1,
			Passed:             len(findings) == 0,
			HardBlockTriggered: false,
		}

		var buf bytes.Buffer
		rep := &reporter.JSONReporter{}
		_ = rep.Report(&buf, res)
		return buf.String()

	case "validate_publish":
		path, _ := args["path"].(string)
		if path == "" {
			path = "."
		}
		res := ExecuteScan(scanner.ScanOptions{
			RootPath:   path,
			PolicyMode: "strict",
		})
		if res.Passed {
			return fmt.Sprintf("SAFE TO PUBLISH: %d files verified in %s. Zero blocking policy violations found.", res.StagedFilesCount, path)
		}
		return fmt.Sprintf("BLOCKED FOR PUBLISH: Found %d security/policy issues in %s. Run push-scanner scan for detailed remediation.", len(res.Findings), path)

	case "scan_docker_image":
		tarPath, _ := args["tar_path"].(string)
		if tarPath == "" {
			return "Error: tar_path is required"
		}
		findings, err := scanner.ScanDockerImageFile(tarPath)
		if err != nil {
			return fmt.Sprintf("Error scanning Docker image: %v", err)
		}

		res := scanner.ScanResult{
			RootPath:           tarPath,
			Timestamp:          time.Now(),
			Findings:           findings,
			TotalFilesScanned:  1,
			StagedFilesCount:   1,
			Passed:             len(findings) == 0,
			HardBlockTriggered: len(findings) > 0,
			PolicyMode:         "docker_layer",
		}

		var buf bytes.Buffer
		rep := &reporter.ConsoleReporter{}
		_ = rep.Report(&buf, res)
		return buf.String()

	case "explain_finding":
		findingID, _ := args["finding_id"].(string)
		return explainFindingID(findingID)

	default:
		return "Unknown tool: " + name
	}
}

func explainFindingID(findingID string) string {
	switch {
	case strings.HasPrefix(findingID, "PS-SEC"):
		return fmt.Sprintf("[%s - Hardcoded Secret Exposure]\nCWE-798 / CWE-312: Hardcoded credentials or API tokens discovered in code.\nRisk: Attackers can scrape public repos or package registries to compromise AWS accounts, GitHub tokens, or API keys.\nRemediation:\n1. Revoke the token in provider dashboard immediately.\n2. Remove the secret from code.\n3. Use environment variables or secret managers.", findingID)
	case strings.HasPrefix(findingID, "PS-CFG"):
		return fmt.Sprintf("[%s - Package Lifecycle Script Execution]\nCWE-829 / CWE-78: Package contains automatically executing install hooks (preinstall/postinstall).\nRisk: Supply-chain attackers inject install hooks to download remote payloads via `curl | bash`.\nRemediation:\n1. Remove `preinstall` or `postinstall` hooks from `package.json` unless mandatory.\n2. Ensure installation scripts do not download unverified binaries.", findingID)
	case strings.HasPrefix(findingID, "PS-SRC"):
		return fmt.Sprintf("[%s - Unminified SourceMap Leaked]\nCWE-540: Bundled output includes `.map` files or inline base64 sourcemaps.\nRisk: Exposes original TypeScript/JavaScript source code, internal comments, and private directory paths.\nRemediation:\n1. Exclude `.map` files from public package targets (`.npmignore` or `files` field).\n2. Strip inline sourcemaps in production build configs.", findingID)
	case strings.HasPrefix(findingID, "PS-DEP"):
		return fmt.Sprintf("[%s - Typosquatting / Unpinned Dependency]\nCWE-829: Package depends on suspicious typosquatting package or unpinned version range.\nRisk: Typosquatting packages execute malware on installation; loose version ranges (`*`) pull compromised patches.\nRemediation:\n1. Verify dependency spelling against official registries.\n2. Pin version numbers strictly.", findingID)
	case strings.HasPrefix(findingID, "PS-DOC"):
		return fmt.Sprintf("[%s - Intermediate Docker Layer Secret Persistence]\nCWE-200: Secret was deleted in an upper Docker layer, but persists in an earlier layer.\nRisk: Deleting a file in a Dockerfile line does not remove it from image history. Anyone with image tarball access can extract earlier layers.\nRemediation:\n1. Use BuildKit secret mounts (`RUN --mount=type=secret...`).\n2. Use multi-stage builds (`FROM ... AS builder`).", findingID)
	default:
		return fmt.Sprintf("[%s] Refer to push-scanner documentation for CWE risk analysis and remediation guidelines.", findingID)
	}
}

func sendResponse(id interface{}, result interface{}) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	b, _ := json.Marshal(resp)
	fmt.Printf("%s\n", b)
}

func sendError(id interface{}, code int, message string) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
		},
	}
	b, _ := json.Marshal(resp)
	fmt.Printf("%s\n", b)
}

func ExecuteScan(opts scanner.ScanOptions) scanner.ScanResult {
	startTime := time.Now()
	if opts.RootPath == "" {
		opts.RootPath = "."
	}
	absPath, err := filepath.Abs(opts.RootPath)
	if err == nil {
		opts.RootPath = absPath
	}

	targetFiles := collectFiles(opts.RootPath)

	packagers := []packager.Packager{
		&packager.NPMPackager{},
		&packager.PyPIPackager{},
		&packager.MavenPackager{},
		&packager.CargoPackager{},
		&packager.NuGetPackager{},
	}

	for _, p := range packagers {
		if p.Detect(opts.RootPath, targetFiles) {
			targetFiles, _ = p.Simulate(opts.RootPath, targetFiles)
			break
		}
	}

	stagedCount := 0
	for _, f := range targetFiles {
		if f.IsStagedForPublish {
			stagedCount++
		}
	}

	activeScanners := []scanner.Scanner{
		&scanner.SecretScanner{},
		&scanner.ArtifactScanner{},
		&scanner.ConfigScanner{},
		&scanner.SourceMapScanner{},
		&scanner.DependencyScanner{},
		&scanner.DockerLayerScanner{},
		&scanner.AISignalScanner{},
	}

	var rawFindings []scanner.Finding
	for _, s := range activeScanners {
		f, err := s.Scan(opts, targetFiles)
		if err == nil {
			rawFindings = append(rawFindings, f...)
		}
	}

	policyCfg := policy.DefaultConfig()
	if opts.ConfigPath != "" {
		loaded, err := policy.LoadConfig(opts.ConfigPath)
		if err == nil {
			policyCfg = loaded
		}
	} else {
		defaultCfgFile := filepath.Join(opts.RootPath, ".push-scanner.yml")
		if loaded, err := policy.LoadConfig(defaultCfgFile); err == nil {
			policyCfg = loaded
		}
	}

	if opts.Ring != "" {
		policyCfg.EnvironmentRing = opts.Ring
	}
	if opts.Team != "" {
		policyCfg.Team = opts.Team
	}

	engine := policy.NewPolicyEngine(policyCfg)
	evalMode := opts.PolicyMode
	if evalMode == "" {
		evalMode = policyCfg.PolicyMode
	}

	filteredFindings, passed, hardBlock := engine.Evaluate(rawFindings, evalMode)

	baselineFile := opts.BaselinePath
	if baselineFile == "" {
		baselineFile = policyCfg.BaselinePath
	}
	if baselineFile == "" {
		baselineFile = filepath.Join(opts.RootPath, ".push-scanner-baseline.json")
	}

	var suppressedFindings []scanner.Finding
	if loadedBaseline, err := suppress.LoadBaseline(baselineFile); err == nil {
		filteredFindings, suppressedFindings = suppress.FilterFindings(loadedBaseline, filteredFindings)
		if len(filteredFindings) == 0 && !hardBlock {
			passed = true
		}
	}

	summary := map[scanner.Severity]int{
		scanner.SeverityCritical: 0,
		scanner.SeverityHigh:     0,
		scanner.SeverityMedium:   0,
		scanner.SeverityLow:      0,
		scanner.SeverityInfo:     0,
	}
	for _, f := range filteredFindings {
		summary[f.Severity]++
	}

	res := scanner.ScanResult{
		RootPath:           opts.RootPath,
		Timestamp:          startTime,
		DurationMs:         time.Since(startTime).Milliseconds(),
		TotalFilesScanned:  len(targetFiles),
		StagedFilesCount:   stagedCount,
		Findings:           filteredFindings,
		SuppressedFindings: suppressedFindings,
		Summary:            summary,
		Passed:             passed,
		HardBlockTriggered: hardBlock,
		PolicyMode:         evalMode,
		EnvironmentRing:    policyCfg.EnvironmentRing,
		Team:               policyCfg.Team,
	}

	// Output CycloneDX SBOM if requested and scan passed
	if opts.SBOMPath != "" && res.Passed {
		if sbomData, err := sbom.GenerateCycloneDX(res, targetFiles); err == nil {
			_ = os.WriteFile(opts.SBOMPath, sbomData, 0644)
		}
	}

	// Output SLSA Provenance / Sigstore Attestation if requested and scan passed
	if opts.AttestationPath != "" && res.Passed {
		if attData, err := attest.GenerateSLSAAttestation(res); err == nil {
			_ = os.WriteFile(opts.AttestationPath, attData, 0644)
		}
	}

	webhookURL := opts.WebhookURL
	if webhookURL == "" {
		webhookURL = policyCfg.WebhookURL
	}
	if webhookURL != "" {
		wb := &reporter.WebhookReporter{URL: webhookURL}
		_ = wb.Report(os.Stdout, res)
	}

	return res
}

func collectFiles(root string) []scanner.TargetFile {
	var files []scanner.TargetFile
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		relClean := filepath.ToSlash(rel)

		if strings.HasPrefix(relClean, ".git/") || relClean == ".git" {
			return nil
		}

		if info.Size() > 10*1024*1024 {
			return nil
		}
		content, _ := os.ReadFile(path)

		files = append(files, scanner.TargetFile{
			Path:               relClean,
			FullPath:           path,
			SizeBytes:          info.Size(),
			IsDir:              false,
			IsStagedForPublish: true,
			Content:            content,
		})
		return nil
	})
	return files
}
