package cmd

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"push-scanner/pkg/mcp"
	"push-scanner/pkg/reporter"
	"push-scanner/pkg/scanner"
	"push-scanner/pkg/suppress"
)

func Execute() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	subCmd := os.Args[1]
	switch subCmd {
	case "scan":
		runScan(os.Args[2:])
	case "docker":
		runDockerScan(os.Args[2:])
	case "attest":
		runAttest(os.Args[2:])
	case "baseline":
		runBaseline(os.Args[2:])
	case "mcp":
		if err := mcp.StartMCPServer(); err != nil {
			fmt.Fprintf(os.Stderr, "MCP Server error: %v\n", err)
			os.Exit(1)
		}
	case "init":
		runInit()
	case "version", "-v", "--version":
		fmt.Println("push-scanner v0.4.0 (Go Enterprise & SLSA Supply-Chain Security Gate)")
	case "-h", "--help", "help":
		printUsage()
	default:
		if _, err := os.Stat(subCmd); err == nil {
			runScan(os.Args[1:])
		} else {
			fmt.Fprintf(os.Stderr, "Unknown command or path: %s\n\n", subCmd)
			printUsage()
			os.Exit(1)
		}
	}
}

func printUsage() {
	fmt.Println(`push-scanner - High-Performance Pre-Publish Security Gate & MCP Server

Usage:
  push-scanner <command> [options] [path|archive]

Commands:
  scan [path]         Scan workspace or archive for pre-publish security risks (default)
  docker <image.tar>  Scan Docker/OCI container image tarball layer-by-layer
  attest [path]       Generate CycloneDX SBOM and SLSA Provenance v1.0 Attestation
  baseline generate   Generate .push-scanner-baseline.json suppression file for current findings
  mcp                 Run as Model Context Protocol (MCP) server over stdio for AI agents
  init                Create default .push-scanner.yml configuration file
  version             Print push-scanner version info

Flags for 'scan':
  --mode string         Policy mode: "default", "strict", "permissive" (default "default")
  --ring string         Environment ring: "prod", "staging", "dev" (default "dev")
  --team string         Team identifier (e.g. "platform-sec")
  --format string       Output format: "console", "json", "sarif", "github" (default "console")
  --sbom string         Export CycloneDX v1.5 JSON SBOM to file on gate pass
  --attest string       Export Sigstore SLSA Provenance v1.0 Attestation to file on gate pass
  --webhook-url string  SIEM / Webhook audit endpoint URL
  --baseline string     Custom path to baseline suppression file (.push-scanner-baseline.json)
  --config string       Path to custom .push-scanner.yml config
  --gitleaks            Enable Gitleaks integration fallback

Examples:
  push-scanner scan .
  push-scanner scan --sbom sbom.json --attest provenance.json
  push-scanner attest .
  push-scanner docker my-app-image.tar
  push-scanner mcp`)
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	modeFlag := fs.String("mode", "default", "Policy mode: default, strict, permissive")
	ringFlag := fs.String("ring", "", "Environment ring: prod, staging, dev")
	teamFlag := fs.String("team", "", "Team identifier")
	formatFlag := fs.String("format", "console", "Output format: console, json, sarif, github")
	sbomFlag := fs.String("sbom", "", "Export CycloneDX v1.5 JSON SBOM file")
	attestFlag := fs.String("attest", "", "Export SLSA Provenance v1.0 Attestation file")
	webhookFlag := fs.String("webhook-url", "", "SIEM / Webhook endpoint URL")
	baselineFlag := fs.String("baseline", "", "Path to baseline file")
	configFlag := fs.String("config", "", "Path to custom .push-scanner.yml")
	gitleaksFlag := fs.Bool("gitleaks", false, "Enable Gitleaks integration")

	_ = fs.Parse(args)

	targetPath := "."
	if fs.NArg() > 0 {
		targetPath = fs.Arg(0)
	}

	opts := scanner.ScanOptions{
		RootPath:        targetPath,
		PolicyMode:      *modeFlag,
		Ring:            *ringFlag,
		Team:            *teamFlag,
		SBOMPath:        *sbomFlag,
		AttestationPath: *attestFlag,
		WebhookURL:      *webhookFlag,
		BaselinePath:    *baselineFlag,
		ConfigPath:      *configFlag,
		EnableGitleaks:  *gitleaksFlag,
	}

	res := mcp.ExecuteScan(opts)

	var rep reporter.Reporter
	switch *formatFlag {
	case "json":
		rep = &reporter.JSONReporter{}
	case "sarif":
		rep = &reporter.SARIFReporter{}
	case "github", "gha":
		rep = &reporter.GHAReporter{}
	case "console":
		fallthrough
	default:
		rep = &reporter.ConsoleReporter{}
	}

	if err := rep.Report(os.Stdout, res); err != nil {
		fmt.Fprintf(os.Stderr, "Reporting error: %v\n", err)
	}

	if len(res.SuppressedFindings) > 0 {
		fmt.Printf(" [push-scanner baseline] %d finding(s) suppressed via baseline file.\n", len(res.SuppressedFindings))
	}

	if *sbomFlag != "" && res.Passed {
		fmt.Printf(" [push-scanner sbom] CycloneDX v1.5 SBOM generated at: %s\n", *sbomFlag)
	}
	if *attestFlag != "" && res.Passed {
		fmt.Printf(" [push-scanner attest] Sigstore SLSA Provenance Attestation generated at: %s\n", *attestFlag)
	}

	if !res.Passed {
		os.Exit(1)
	}
}

func runAttest(args []string) {
	targetPath := "."
	if len(args) > 0 {
		targetPath = args[0]
	}

	sbomPath := filepath.Join(targetPath, "sbom.cyclonedx.json")
	attPath := filepath.Join(targetPath, "provenance.slsa.json")

	opts := scanner.ScanOptions{
		RootPath:        targetPath,
		PolicyMode:      "default",
		SBOMPath:        sbomPath,
		AttestationPath: attPath,
	}

	res := mcp.ExecuteScan(opts)
	rep := &reporter.ConsoleReporter{}
	_ = rep.Report(os.Stdout, res)

	if res.Passed {
		fmt.Printf("\n [push-scanner supply-chain] Generated CycloneDX SBOM: %s\n", sbomPath)
		fmt.Printf(" [push-scanner supply-chain] Generated Sigstore SLSA Attestation: %s\n", attPath)
	} else {
		fmt.Println("\n ✘ Attestation generation aborted due to security gate failure.")
		os.Exit(1)
	}
}

func runDockerScan(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: Docker image tarball file path required.")
		fmt.Fprintln(os.Stderr, "Usage: push-scanner docker <image.tar>")
		os.Exit(1)
	}

	tarPath := args[0]
	findings, err := scanner.ScanDockerImageFile(tarPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Docker scan error: %v\n", err)
		os.Exit(1)
	}

	res := scanner.ScanResult{
		RootPath:           tarPath,
		TotalFilesScanned:  1,
		StagedFilesCount:   1,
		Findings:           findings,
		Passed:             len(findings) == 0,
		HardBlockTriggered: len(findings) > 0,
		PolicyMode:         "docker_layer",
		Summary: map[scanner.Severity]int{
			scanner.SeverityCritical: len(findings),
		},
	}

	rep := &reporter.ConsoleReporter{}
	_ = rep.Report(os.Stdout, res)

	if !res.Passed {
		os.Exit(1)
	}
}

func runBaseline(args []string) {
	if len(args) == 0 || args[0] != "generate" {
		fmt.Println("Usage: push-scanner baseline generate [path]")
		return
	}

	targetPath := "."
	if len(args) > 1 {
		targetPath = args[1]
	}

	res := mcp.ExecuteScan(scanner.ScanOptions{
		RootPath:   targetPath,
		PolicyMode: "permissive",
	})

	baselineFile := filepath.Join(targetPath, ".push-scanner-baseline.json")
	if err := suppress.SaveBaseline(baselineFile, res.Findings); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate baseline: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully generated baseline file %s with %d suppressed items.\n", baselineFile, len(res.Findings))
}

func runInit() {
	target := ".push-scanner.yml"
	if _, err := os.Stat(target); err == nil {
		fmt.Println(".push-scanner.yml already exists in current directory.")
		return
	}

	defaultContent := `# push-scanner enterprise v0.4 configuration file
team: platform-sec
environment_ring: dev # Options: prod, staging, dev
mode: default # Options: default, strict, permissive
fail_on: HIGH # Options: CRITICAL, HIGH, MEDIUM, LOW, INFO
strict_ai: false

webhook_url: "" # SIEM / Webhook audit stream URL
baseline_path: ".push-scanner-baseline.json"

ignore_paths:
  - "node_modules/**"
  - ".git/**"
  - "vendor/**"

ignore_rules:
  # - "PS-ART-004"
`
	if err := os.WriteFile(target, []byte(defaultContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create .push-scanner.yml: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Created .push-scanner.yml successfully.")
}
