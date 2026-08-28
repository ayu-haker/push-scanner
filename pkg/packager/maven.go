package packager

import (
	"path/filepath"
	"strings"

	"push-scanner/pkg/scanner"
)

type MavenPackager struct{}

func (m *MavenPackager) Name() string {
	return "maven"
}

func (m *MavenPackager) Detect(rootPath string, files []scanner.TargetFile) bool {
	for _, f := range files {
		clean := strings.ToLower(filepath.ToSlash(f.Path))
		if clean == "pom.xml" || clean == "build.gradle" || clean == "build.gradle.kts" {
			return true
		}
	}
	return false
}

func (m *MavenPackager) Simulate(rootPath string, files []scanner.TargetFile) ([]scanner.TargetFile, error) {
	var gitIgnoreLines []string
	for _, f := range files {
		if filepath.ToSlash(f.Path) == ".gitignore" {
			gitIgnoreLines = parseIgnoreFile(string(f.Content))
		}
	}

	result := make([]scanner.TargetFile, len(files))
	for i, f := range files {
		cleanPath := filepath.ToSlash(f.Path)
		staged := isMavenStaged(cleanPath, gitIgnoreLines)
		f.IsStagedForPublish = staged
		result[i] = f
	}

	return result, nil
}

func isMavenStaged(path string, gitIgnore []string) bool {
	lower := strings.ToLower(path)

	// Always included files for Java packaging
	if lower == "pom.xml" || lower == "build.gradle" || lower == "build.gradle.kts" ||
		strings.HasPrefix(lower, "src/main/") || strings.HasPrefix(lower, "target/classes/") || strings.HasPrefix(lower, "build/classes/") {
		return true
	}

	// Always excluded build/dev files
	if strings.HasPrefix(lower, ".git/") || lower == ".git" ||
		strings.HasPrefix(lower, "target/") || strings.HasPrefix(lower, "build/") || strings.HasPrefix(lower, ".gradle/") ||
		strings.HasPrefix(lower, ".idea/") || strings.HasSuffix(lower, ".class") || lower == ".env" || strings.HasPrefix(lower, ".env.") {
		return false
	}

	if len(gitIgnore) > 0 && matchesIgnore(path, gitIgnore) {
		return false
	}

	return true
}
