package reporter

import (
	"encoding/json"
	"io"

	"push-scanner/pkg/scanner"
)

type SarifReport struct {
	Version string     `json:"$schema"`
	Ver     string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SarifRule `json:"rules"`
}

type SarifRule struct {
	ID               string `json:"id"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	HelpURI string `json:"helpUri"`
}

type SarifResult struct {
	RuleID    string         `json:"ruleId"`
	Level     string         `json:"level"`
	Message   SarifMessage   `json:"message"`
	Locations []SarifLoc     `json:"locations"`
}

type SarifMessage struct {
	Text string `json:"text"`
}

type SarifLoc struct {
	PhysicalLocation SarifPhysLoc `json:"physicalLocation"`
}

type SarifPhysLoc struct {
	ArtifactLocation struct {
		URI string `json:"uri"`
	} `json:"artifactLocation"`
	Region struct {
		StartLine int `json:"startLine,omitempty"`
	} `json:"region"`
}

type SARIFReporter struct{}

func (s *SARIFReporter) Report(w io.Writer, res scanner.ScanResult) error {
	report := SarifReport{
		Version: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Ver:     "2.1.0",
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           "push-scanner",
						Version:        "0.1.0",
						InformationURI: "https://github.com/push-scanner/push-scanner",
						Rules:          []SarifRule{},
					},
				},
				Results: []SarifResult{},
			},
		},
	}

	for _, f := range res.Findings {
		level := "warning"
		if f.Severity == scanner.SeverityCritical || f.Severity == scanner.SeverityHigh {
			level = "error"
		} else if f.Severity == scanner.SeverityInfo {
			level = "note"
		}

		sRes := SarifResult{
			RuleID: f.ID,
			Level:  level,
			Message: SarifMessage{
				Text: f.Title + ": " + f.Description + " Remediation: " + f.Remediation,
			},
			Locations: []SarifLoc{
				{
					PhysicalLocation: SarifPhysLoc{
						ArtifactLocation: struct {
							URI string `json:"uri"`
						}{URI: f.File},
						Region: struct {
							StartLine int `json:"startLine,omitempty"`
						}{StartLine: f.Line},
					},
				},
			},
		}

		report.Runs[0].Results = append(report.Runs[0].Results, sRes)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
