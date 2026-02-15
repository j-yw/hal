package compound

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jywlabs/hal/internal/template"
)

const reviewLoopReportTimestampFormat = "2006-01-02-150405-000"

// WriteReviewLoopJSONReport writes a review loop result artifact under
// .hal/reports/review-loop-<timestamp>.json.
func WriteReviewLoopJSONReport(dir string, result *ReviewLoopResult) (string, error) {
	return writeReviewLoopJSONReport(dir, result, time.Now)
}

func writeReviewLoopJSONReport(dir string, result *ReviewLoopResult, now func() time.Time) (string, error) {
	if result == nil {
		return "", fmt.Errorf("review loop result is required")
	}
	if now == nil {
		now = time.Now
	}

	reportsDir := filepath.Join(dir, template.HalDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create reports directory: %w", err)
	}

	timestamp := now().Format(reviewLoopReportTimestampFormat)
	reportPath := filepath.Join(reportsDir, fmt.Sprintf("review-loop-%s.json", timestamp))

	payload, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal review loop result: %w", err)
	}
	payload = append(payload, '\n')

	if err := os.WriteFile(reportPath, payload, 0644); err != nil {
		return "", fmt.Errorf("failed to write review loop JSON report: %w", err)
	}

	return reportPath, nil
}
