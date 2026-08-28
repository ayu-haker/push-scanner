package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"push-scanner/pkg/scanner"
)

type WebhookAuditEvent struct {
	EventID            string            `json:"event_id"`
	Timestamp          time.Time         `json:"timestamp"`
	RootPath           string            `json:"root_path"`
	PolicyMode         string            `json:"policy_mode"`
	Passed             bool              `json:"passed"`
	HardBlockTriggered bool              `json:"hard_block_triggered"`
	TotalFiles         int               `json:"total_files"`
	StagedFiles        int               `json:"staged_files"`
	FindingsCount      int               `json:"findings_count"`
	Summary            map[scanner.Severity]int `json:"summary"`
	Findings           []scanner.Finding `json:"findings"`
}

type WebhookReporter struct {
	URL string
}

func (w *WebhookReporter) Report(out io.Writer, res scanner.ScanResult) error {
	if w.URL == "" {
		return fmt.Errorf("webhook URL is empty")
	}

	event := WebhookAuditEvent{
		EventID:            fmt.Sprintf("evt_%d", time.Now().UnixNano()),
		Timestamp:          time.Now(),
		RootPath:           res.RootPath,
		PolicyMode:         res.PolicyMode,
		Passed:             res.Passed,
		HardBlockTriggered: res.HardBlockTriggered,
		TotalFiles:         res.TotalFilesScanned,
		StagedFiles:        res.StagedFilesCount,
		FindingsCount:      len(res.Findings),
		Summary:            res.Summary,
		Findings:           res.Findings,
	}

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(w.URL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		fmt.Fprintf(out, "[push-scanner webhook] Error transmitting audit event: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Fprintf(out, "[push-scanner webhook] Audit stream sent successfully to %s (HTTP %d)\n", w.URL, resp.StatusCode)
	} else {
		fmt.Fprintf(out, "[push-scanner webhook] SIEM endpoint responded with HTTP %d\n", resp.StatusCode)
	}

	return nil
}
