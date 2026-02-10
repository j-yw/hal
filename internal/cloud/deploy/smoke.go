package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SmokeResult holds the outcome of a single service health check.
type SmokeResult struct {
	Service    string `json:"service"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
}

// SmokeReport holds the results of all smoke checks.
type SmokeReport struct {
	Results []SmokeResult `json:"results"`
	AllOK   bool          `json:"all_ok"`
}

// RunSmoke checks that the control-plane and runner health endpoints return HTTP 200.
// It uses the provided HTTP client (or creates a default one with a 10-second timeout).
func RunSmoke(ctx context.Context, controlPlaneURL, runnerURL string, client *http.Client) SmokeReport {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	results := []SmokeResult{
		checkHealth(ctx, client, "control-plane", controlPlaneURL+"/health"),
		checkHealth(ctx, client, "runner", runnerURL+"/health"),
	}

	allOK := true
	for _, r := range results {
		if !r.OK {
			allOK = false
			break
		}
	}

	return SmokeReport{
		Results: results,
		AllOK:   allOK,
	}
}

func checkHealth(ctx context.Context, client *http.Client, service, url string) SmokeResult {
	result := SmokeResult{
		Service: service,
		URL:     url,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		result.Error = fmt.Sprintf("build request: %v", err)
		return result
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.OK = resp.StatusCode == http.StatusOK
	if !result.OK {
		result.Error = fmt.Sprintf("expected HTTP 200, got %d", resp.StatusCode)
	}

	return result
}

// WriteSmokeReport writes the smoke report in the requested format.
func WriteSmokeReport(out io.Writer, report SmokeReport, jsonOutput bool) error {
	if jsonOutput {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal report: %w", err)
		}
		_, err = fmt.Fprintf(out, "%s\n", data)
		return err
	}

	for _, r := range report.Results {
		status := "OK"
		if !r.OK {
			status = "FAIL"
		}
		fmt.Fprintf(out, "  %-16s %s", r.Service, status)
		if r.StatusCode > 0 {
			fmt.Fprintf(out, " (HTTP %d)", r.StatusCode)
		}
		if r.Error != "" {
			fmt.Fprintf(out, " — %s", r.Error)
		}
		fmt.Fprintln(out)
	}

	if report.AllOK {
		fmt.Fprintf(out, "\nAll services healthy.\n")
	} else {
		fmt.Fprintf(out, "\nSome services unhealthy.\n")
	}
	return nil
}
