package packager

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"push-scanner/pkg/scanner"
)

type NPMPackager struct{}

func (n *NPMPackager) Name() string {
	return "npm"
}

func (n *NPMPackager) Detect(rootPath string, files []scanner.TargetFile) bool {
	for _, f := range files {
		if strings.ToLower(f.Path) == "package.json" {
			return true
		}
	}
	return false
}

type packageJSON struct {
	Files []string `json:"files"`
	Main  string   `json:"main"`
}

func (n *NPMPackager) Simulate(rootPath string, files []scanner.TargetFile) ([]scanner.TargetFile, error) {
	var pkgJson packageJSON
	var hasPkgJson bool
	var npmIgnoreLines []string
	var gitIgnoreLines []string

	// Look for package.json, .npmignore, .gitignore
	for _, f := range files {
		cleanPath := filepath.ToSlash(f.Path)
		if cleanPath == "package.json" {
			hasPkgJson = true
			_ = json.Unmarshal(f.Content, &pkgJson)
		} else if cleanPath == ".npmignore" {
			npmIgnoreLines = parseIgnoreFile(string(f.Content))
		} else if cleanPath == ".gitignore" {
			gitIgnoreLines = parseIgnoreFile(string(f.Content))
		}
	}

	result := make([]scanner.TargetFile, len(files))
	for i, f := range files {
		cleanPath := filepath.ToSlash(f.Path)
		staged := isNPMStaged(cleanPath, hasPkgJson, pkgJson, npmIgnoreLines, gitIgnoreLines)
		f.IsStagedForPublish = staged
		result[i] = f
	}

	return result, nil
}

func isNPMStaged(path string, hasPkgJson bool, pkgJson packageJSON, npmIgnore []string, gitIgnore []string) bool {
	lower := strings.ToLower(path)

	// Always included files according to npm specs
	if lower == "package.json" || strings.HasPrefix(lower, "readme") || strings.HasPrefix(lower, "license") || strings.HasPrefix(lower, "changelog") {
		return true
	}

	// Always excluded files/directories
	if strings.HasPrefix(lower, ".git/") || lower == ".git" ||
		strings.HasPrefix(lower, "node_modules/") || lower == "node_modules" ||
		strings.HasSuffix(lower, ".log") || strings.HasSuffix(lower, ".tar.gz") ||
		strings.HasPrefix(lower, ".vscode/") || strings.HasPrefix(lower, ".idea/") ||
		lower == ".ds_store" || lower == ".env" || strings.HasPrefix(lower, ".env.") {
		return false
	}

	// Rule 1: package.json "files" white-listing takes priority if present
	if hasPkgJson && len(pkgJson.Files) > 0 {
		matched := false
		for _, pattern := range pkgJson.Files {
			p := strings.TrimPrefix(filepath.ToSlash(pattern), "./")
			p = strings.TrimSuffix(p, "/")
			if cleanMatch(path, p) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Rule 2: .npmignore takes precedence over .gitignore
	if len(npmIgnore) > 0 {
		return !matchesIgnore(path, npmIgnore)
	}

	// Rule 3: .gitignore used if no .npmignore exists
	if len(gitIgnore) > 0 {
		return !matchesIgnore(path, gitIgnore)
	}

	return true
}

func parseIgnoreFile(content string) []string {
	var lines []string
	for _, l := range strings.Split(content, "\n") {
		line := strings.TrimSpace(l)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}

func matchesIgnore(path string, ignoreList []string) bool {
	for _, rule := range ignoreList {
		r := strings.TrimPrefix(filepath.ToSlash(rule), "./")
		r = strings.TrimSuffix(r, "/")
		if cleanMatch(path, r) {
			return true
		}
	}
	return false
}

func cleanMatch(path, pattern string) bool {
	if strings.HasPrefix(path, pattern) || path == pattern {
		return true
	}
	matched, err := filepath.Match(pattern, path)
	if err == nil && matched {
		return true
	}
	matchedBase, err := filepath.Match(pattern, filepath.Base(path))
	return err == nil && matchedBase
}
