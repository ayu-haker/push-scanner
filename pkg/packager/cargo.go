package packager

import (
	"path/filepath"
	"strings"

	"push-scanner/pkg/scanner"
)

type CargoPackager struct{}

func (c *CargoPackager) Name() string {
	return "cargo"
}

func (c *CargoPackager) Detect(rootPath string, files []scanner.TargetFile) bool {
	for _, f := range files {
		clean := strings.ToLower(filepath.ToSlash(f.Path))
		if clean == "cargo.toml" {
			return true
		}
	}
	return false
}

func (c *CargoPackager) Simulate(rootPath string, files []scanner.TargetFile) ([]scanner.TargetFile, error) {
	var gitIgnoreLines []string
	for _, f := range files {
		if filepath.ToSlash(f.Path) == ".gitignore" {
			gitIgnoreLines = parseIgnoreFile(string(f.Content))
		}
	}

	result := make([]scanner.TargetFile, len(files))
	for i, f := range files {
		cleanPath := filepath.ToSlash(f.Path)
		staged := isCargoStaged(cleanPath, gitIgnoreLines)
		f.IsStagedForPublish = staged
		result[i] = f
	}

	return result, nil
}

func isCargoStaged(path string, gitIgnore []string) bool {
	lower := strings.ToLower(path)

	// Always included files for Rust Cargo .crate package
	if lower == "cargo.toml" || lower == "cargo.lock" || strings.HasPrefix(lower, "src/") || lower == "build.rs" ||
		strings.HasPrefix(lower, "readme") || strings.HasPrefix(lower, "license") {
		return true
	}

	// Always excluded target / build directories
	if strings.HasPrefix(lower, ".git/") || lower == ".git" ||
		strings.HasPrefix(lower, "target/") || strings.HasSuffix(lower, ".rs.bk") ||
		lower == ".env" || strings.HasPrefix(lower, ".env.") {
		return false
	}

	if len(gitIgnore) > 0 && matchesIgnore(path, gitIgnore) {
		return false
	}

	return true
}
