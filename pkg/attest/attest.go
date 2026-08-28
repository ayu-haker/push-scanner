package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"push-scanner/pkg/scanner"
)

// InTotoStatement represents an in-toto v1 statement containing a SLSA v1.0 provenance predicate.
type InTotoStatement struct {
	Type          string          `json:"_type"`
	Subject       []SubjectDigest `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     SLSAPredicate   `json:"predicate"`
}

type SubjectDigest struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type SLSAPredicate struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

type BuildDefinition struct {
	BuildType          string      `json:"buildType"`
	ExternalParameters Invocation `json:"externalParameters"`
	InternalParameters Parameters `json:"internalParameters"`
}

type Invocation struct {
	RootPath        string `json:"root_path"`
	PolicyMode      string `json:"policy_mode"`
	EnvironmentRing string `json:"environment_ring,omitempty"`
	Team            string `json:"team,omitempty"`
}

type Parameters struct {
	TotalScanned int `json:"total_scanned"`
	StagedFiles  int `json:"staged_files"`
}

type RunDetails struct {
	Builder  BuilderInfo `json:"builder"`
	Metadata Metadata    `json:"metadata"`
}

type BuilderInfo struct {
	ID string `json:"id"`
}

type Metadata struct {
	InvocationID string    `json:"invocationId"`
	StartedOn    time.Time `json:"startedOn"`
	FinishedOn   time.Time `json:"finishedOn"`
}

// GenerateSLSAAttestation creates an in-toto SLSA v1.0 Provenance attestation JSON envelope.
func GenerateSLSAAttestation(res scanner.ScanResult) ([]byte, error) {
	if !res.Passed {
		return nil, fmt.Errorf("cannot generate SLSA attestation for failed security gate")
	}

	h := sha256.Sum256([]byte(res.RootPath + res.Timestamp.String()))
	digestHex := hex.EncodeToString(h[:])

	stmt := InTotoStatement{
		Type:          "https://in-toto.io/Statement/v1",
		PredicateType: "https://slsa.dev/provenance/v1",
		Subject: []SubjectDigest{
			{
				Name: filepath.Base(res.RootPath),
				Digest: map[string]string{
					"sha256": digestHex,
				},
			},
		},
		Predicate: SLSAPredicate{
			BuildDefinition: BuildDefinition{
				BuildType: "https://push-scanner.dev/attestation/v1",
				ExternalParameters: Invocation{
					RootPath:        res.RootPath,
					PolicyMode:      res.PolicyMode,
					EnvironmentRing: res.EnvironmentRing,
					Team:            res.Team,
				},
				InternalParameters: Parameters{
					TotalScanned: res.TotalFilesScanned,
					StagedFiles:  res.StagedFilesCount,
				},
			},
			RunDetails: RunDetails{
				Builder: BuilderInfo{
					ID: "https://github.com/push-scanner/push-scanner@v0.4.0",
				},
				Metadata: Metadata{
					InvocationID: "push-scanner-" + digestHex[:16],
					StartedOn:    res.Timestamp,
					FinishedOn:   time.Now(),
				},
			},
		},
	}

	return json.MarshalIndent(stmt, "", "  ")
}
