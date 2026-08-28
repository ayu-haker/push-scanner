package scanner

import (
	"fmt"
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

type Finding struct {
	ID                 string   `json:"id"`
	Title              string   `json:"title"`
	Description        string   `json:"description"`
	File               string   `json:"file"`
	Line               int      `json:"line,omitempty"`
	Scanner            string   `json:"scanner"`
	Severity           Severity `json:"severity"`
	CWE                string   `json:"cwe,omitempty"`
	Remediation        string   `json:"remediation"`
	IsHardBlock        bool     `json:"is_hard_block"`
	AISignal           bool     `json:"ai_signal"`
	Context            string   `json:"context,omitempty"`
	IsStagedForPublish bool     `json:"is_staged_for_publish"`
}

type TargetFile struct {
	Path               string
	FullPath           string
	SizeBytes          int64
	IsDir              bool
	IsStagedForPublish bool
	Content            []byte
}

type ScanOptions struct {
	RootPath        string   `json:"root_path"`
	PolicyMode      string   `json:"policy_mode"` // "default", "strict", "permissive"
	ConfigPath      string   `json:"config_path"`
	EnableDocker    bool     `json:"enable_docker"`
	EnableGitleaks  bool     `json:"enable_gitleaks"`
	Ecosystem       string   `json:"ecosystem"` // "npm", "pypi", "maven", "cargo", "nuget", "auto"
	Ring            string   `json:"ring"`      // "prod", "staging", "dev"
	Team            string   `json:"team"`
	WebhookURL      string   `json:"webhook_url"`
	BaselinePath    string   `json:"baseline_path"`
	SBOMPath        string   `json:"sbom_path"`
	AttestationPath string   `json:"attestation_path"`
	IgnorePatterns  []string `json:"ignore_patterns"`
	IncludePatterns []string `json:"include_patterns"`
}

type ScanResult struct {
	RootPath           string           `json:"root_path"`
	Timestamp          time.Time        `json:"timestamp"`
	DurationMs         int64            `json:"duration_ms"`
	TotalFilesScanned  int              `json:"total_files_scanned"`
	StagedFilesCount   int              `json:"staged_files_count"`
	Findings           []Finding        `json:"findings"`
	SuppressedFindings []Finding        `json:"suppressed_findings,omitempty"`
	Summary            map[Severity]int `json:"summary"`
	Passed             bool             `json:"passed"`
	HardBlockTriggered bool             `json:"hard_block_triggered"`
	PolicyMode         string           `json:"policy_mode"`
	EnvironmentRing    string           `json:"environment_ring,omitempty"`
	Team               string           `json:"team,omitempty"`
}

type Scanner interface {
	Name() string
	Scan(opts ScanOptions, files []TargetFile) ([]Finding, error)
}

func FormatFindingID(scannerPrefix string, index int) string {
	return fmt.Sprintf("PS-%s-%03d", scannerPrefix, index)
}
