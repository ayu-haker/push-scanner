package packager

import (
	"path/filepath"
	"strings"

	"push-scanner/pkg/scanner"
)

type PyPIPackager struct{}

func (p *PyPIPackager) Name() string {
	return "pypi"
}

func (p *PyPIPackager) Detect(rootPath string, files []scanner.TargetFile) bool {
	for _, f := range files {
		clean := strings.ToLower(filepath.ToSlash(f.Path))
		if clean == "pyproject.toml" || clean == "setup.py" || clean == "setup.cfg" || clean == "requirements.txt" {
			return true
		}
	}
	return false
}

func (p *PyPIPackager) Simulate(rootPath string, files []scanner.TargetFile) ([]scanner.TargetFile, error) {
	var manifestExcludes []string
	var gitIgnoreLines []string

	for _, f := range files {
		clean := filepath.ToSlash(f.Path)
		if clean == "MANIFEST.in" {
			manifestExcludes = parseManifestInExcludes(string(f.Content))
		} else if clean == ".gitignore" {
			gitIgnoreLines = parseIgnoreFile(string(f.Content))
		}
	}

	result := make([]scanner.TargetFile, len(files))
	for i, f := range files {
		cleanPath := filepath.ToSlash(f.Path)
		staged := isPyPIStaged(cleanPath, manifestExcludes, gitIgnoreLines)
		f.IsStagedForPublish = staged
		result[i] = f
	}

	return result, nil
}

func parseManifestInExcludes(content string) []string {
	var excludes []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "global-exclude ") || strings.HasPrefix(line, "exclude ") || strings.HasPrefix(line, "prune ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				excludes = append(excludes, parts[1:]...)
			}
		}
	}
	return excludes
}

func isPyPIStaged(path string, manifestExcludes []string, gitIgnore []string) bool {
	lower := strings.ToLower(path)

	// Always included files
	if lower == "pyproject.toml" || lower == "setup.py" || lower == "setup.cfg" || lower == "manifest.in" ||
		strings.HasPrefix(lower, "readme") || strings.HasPrefix(lower, "license") {
		return true
	}

	// Always excluded Python build / dev / secret paths
	if strings.HasPrefix(lower, ".git/") || lower == ".git" ||
		strings.Contains(lower, "__pycache__/") || strings.HasSuffix(lower, ".pyc") || strings.HasSuffix(lower, ".pyo") ||
		strings.HasPrefix(lower, ".pytest_cache/") || strings.HasPrefix(lower, ".venv/") || strings.HasPrefix(lower, "venv/") ||
		strings.HasPrefix(lower, ".tox/") || strings.HasSuffix(lower, ".egg-info/") || lower == ".env" || strings.HasPrefix(lower, ".env.") ||
		strings.HasSuffix(lower, ".so") || strings.HasSuffix(lower, ".dylib") || strings.HasSuffix(lower, ".dll") {
		return false
	}

	if len(manifestExcludes) > 0 && matchesIgnore(path, manifestExcludes) {
		return false
	}

	if len(gitIgnore) > 0 && matchesIgnore(path, gitIgnore) {
		return false
	}

	return true
}
