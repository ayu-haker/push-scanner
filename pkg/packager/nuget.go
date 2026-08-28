package packager

import (
	"path/filepath"
	"strings"

	"push-scanner/pkg/scanner"
)

type NuGetPackager struct{}

func (n *NuGetPackager) Name() string {
	return "nuget"
}

func (n *NuGetPackager) Detect(rootPath string, files []scanner.TargetFile) bool {
	for _, f := range files {
		clean := strings.ToLower(filepath.ToSlash(f.Path))
		if strings.HasSuffix(clean, ".csproj") || clean == "packages.config" || strings.HasSuffix(clean, ".nuspec") {
			return true
		}
	}
	return false
}

func (n *NuGetPackager) Simulate(rootPath string, files []scanner.TargetFile) ([]scanner.TargetFile, error) {
	var gitIgnoreLines []string
	for _, f := range files {
		if filepath.ToSlash(f.Path) == ".gitignore" {
			gitIgnoreLines = parseIgnoreFile(string(f.Content))
		}
	}

	result := make([]scanner.TargetFile, len(files))
	for i, f := range files {
		cleanPath := filepath.ToSlash(f.Path)
		staged := isNuGetStaged(cleanPath, gitIgnoreLines)
		f.IsStagedForPublish = staged
		result[i] = f
	}

	return result, nil
}

func isNuGetStaged(path string, gitIgnore []string) bool {
	lower := strings.ToLower(path)

	// Always included files for NuGet .nupkg package
	if strings.HasSuffix(lower, ".csproj") || strings.HasSuffix(lower, ".nuspec") || lower == "packages.config" ||
		strings.HasPrefix(lower, "bin/release/") || strings.HasPrefix(lower, "lib/") || strings.HasPrefix(lower, "content/") ||
		strings.HasPrefix(lower, "readme") || strings.HasPrefix(lower, "license") {
		return true
	}

	// Always excluded build / object outputs
	if strings.HasPrefix(lower, ".git/") || lower == ".git" ||
		strings.HasPrefix(lower, "bin/debug/") || strings.HasPrefix(lower, "obj/") || strings.HasPrefix(lower, ".vs/") ||
		lower == ".env" || strings.HasPrefix(lower, ".env.") || strings.HasSuffix(lower, ".user") {
		return false
	}

	if len(gitIgnore) > 0 && matchesIgnore(path, gitIgnore) {
		return false
	}

	return true
}
