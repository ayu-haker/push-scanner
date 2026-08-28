package packager

import (
	"push-scanner/pkg/scanner"
)

// Packager defines the interface for simulating package inclusion rules.
type Packager interface {
	Name() string
	Detect(rootPath string, files []scanner.TargetFile) bool
	Simulate(rootPath string, files []scanner.TargetFile) ([]scanner.TargetFile, error)
}
