package scanner

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

type SourceMapScanner struct{}

func (s *SourceMapScanner) Name() string {
	return "SourceMapScanner"
}

var sourceMapURLRegex = regexp.MustCompile(`(?i)//[#@]\s*sourceMappingURL=([^\s]+)`)

type inlineSourceMap struct {
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

func (s *SourceMapScanner) Scan(opts ScanOptions, files []TargetFile) ([]Finding, error) {
	var findings []Finding
	count := 1

	for _, f := range files {
		clean := filepath.ToSlash(f.Path)
		lower := strings.ToLower(clean)

		// 1. Standalone .map file staged for publish
		if strings.HasSuffix(lower, ".js.map") || strings.HasSuffix(lower, ".css.map") || strings.HasSuffix(lower, ".map") {
			if f.IsStagedForPublish {
				findings = append(findings, Finding{
					ID:                 FormatFindingID("SRC", count),
					Title:              "Unminified SourceMap File Staged for Publish",
					Description:        "Publishing `.map` files exposes original unminified source code, private developer comments, and directory structures to the public.",
					File:               f.Path,
					Scanner:            s.Name(),
					Severity:           SeverityHigh,
					CWE:                "CWE-540",
					Remediation:        "Exclude `.map` files from public package releases or strip sourcemaps in production build steps.",
					IsStagedForPublish: true,
				})
				count++
			}
		}

		// 2. Scan JS/CSS files for inline base64 or sourceMappingURL comments
		if strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".mjs") || strings.HasSuffix(lower, ".cjs") || strings.HasSuffix(lower, ".css") {
			contentStr := string(f.Content)

			// Inline base64 sourcemap detection
			if strings.Contains(contentStr, "data:application/json;base64,") {
				idx := strings.Index(contentStr, "data:application/json;base64,")
				sub := contentStr[idx+len("data:application/json;base64,"):]
				endIdx := strings.IndexAny(sub, " \r\n\"'")
				if endIdx != -1 {
					sub = sub[:endIdx]
				}

				decoded, err := base64.StdEncoding.DecodeString(sub)
				if err == nil {
					var sm inlineSourceMap
					if json.Unmarshal(decoded, &sm) == nil && len(sm.SourcesContent) > 0 {
						findings = append(findings, Finding{
							ID:                 FormatFindingID("SRC", count),
							Title:              "Embedded Inline Base64 SourceMap with Raw Source Code",
							Description:        "Bundled JavaScript file contains inline base64 sourcemaps containing full unminified source code.",
							File:               f.Path,
							Scanner:            s.Name(),
							Severity:           SeverityHigh,
							CWE:                "CWE-540",
							Remediation:        "Disable inline sourcemaps in your bundler configuration (Webpack/Rollup/Vite/esbuild).",
							IsStagedForPublish: f.IsStagedForPublish,
						})
						count++
					}
				}
			}

			// sourceMappingURL comment check
			matches := sourceMapURLRegex.FindStringSubmatch(contentStr)
			if len(matches) > 1 {
				mapRef := matches[1]
				if !strings.HasPrefix(mapRef, "data:") && f.IsStagedForPublish {
					findings = append(findings, Finding{
						ID:                 FormatFindingID("SRC", count),
						Title:              "SourceMap URL Reference Comment in Published Asset",
						Description:        "Asset contains `//# sourceMappingURL=` pointing to `" + mapRef + "`. Browsers and tools will attempt to load original source maps.",
						File:               f.Path,
						Scanner:            s.Name(),
						Severity:           SeverityMedium,
						CWE:                "CWE-540",
						Remediation:        "Remove sourceMappingURL comments during production asset minification.",
						Context:            matches[0],
						IsStagedForPublish: true,
					})
					count++
				}
			}
		}
	}

	return findings, nil
}
