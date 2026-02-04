package compound

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/engine"
)

// FindLatestReport returns the most recently modified file in the reports directory.
// Returns an error if the directory doesn't exist or contains no files.
func FindLatestReport(reportsDir string) (string, error) {
	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("reports directory does not exist: %s", reportsDir)
		}
		return "", fmt.Errorf("failed to read reports directory: %w", err)
	}

	var latestPath string
	var latestTime time.Time

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// Skip hidden files and .gitkeep
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if latestPath == "" || info.ModTime().After(latestTime) {
			latestPath = filepath.Join(reportsDir, entry.Name())
			latestTime = info.ModTime()
		}
	}

	if latestPath == "" {
		return "", fmt.Errorf("no reports found in %s", reportsDir)
	}

	return latestPath, nil
}

// FindRecentPRDs returns PRD files created in the last N days.
// It searches for files matching .goralph/prd-*.md pattern.
func FindRecentPRDs(dir string, days int) ([]string, error) {
	goralphDir := filepath.Join(dir, ".goralph")
	entries, err := os.ReadDir(goralphDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No .goralph directory means no PRDs
		}
		return nil, fmt.Errorf("failed to read .goralph directory: %w", err)
	}

	cutoff := time.Now().AddDate(0, 0, -days)
	var recentPRDs []string

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Match prd-*.md files
		if !strings.HasPrefix(name, "prd-") || !strings.HasSuffix(name, ".md") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().After(cutoff) {
			recentPRDs = append(recentPRDs, filepath.Join(goralphDir, name))
		}
	}

	return recentPRDs, nil
}

// AnalyzeReport uses the engine to analyze a report and identify the highest priority item.
// It returns an AnalysisResult with the priority item details.
func AnalyzeReport(ctx context.Context, eng engine.Engine, reportPath string, recentPRDs []string) (*AnalysisResult, error) {
	// Read the report content
	reportContent, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read report: %w", err)
	}

	if len(strings.TrimSpace(string(reportContent))) == 0 {
		return nil, fmt.Errorf("report is empty: %s", reportPath)
	}

	// Build the prompt
	prompt := buildAnalysisPrompt(string(reportContent), recentPRDs)

	// Call the engine
	response, err := eng.Prompt(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("engine prompt failed: %w", err)
	}

	// Parse the JSON response
	result, err := parseAnalysisResponse(response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse analysis response: %w", err)
	}

	return result, nil
}

// buildAnalysisPrompt constructs the prompt for the analysis engine.
func buildAnalysisPrompt(reportContent string, recentPRDs []string) string {
	var sb strings.Builder

	sb.WriteString(`You are analyzing a product/engineering report to identify the single highest priority item to work on next.

## Instructions

1. Read the report carefully
2. Identify the highest priority item that should be worked on
3. Consider items that are:
   - High impact
   - Well-defined enough to implement
   - Not already being worked on (see recent PRDs below)
4. Return ONLY a JSON object with the analysis result

## Recent PRDs (avoid duplicating these)
`)

	if len(recentPRDs) == 0 {
		sb.WriteString("None\n")
	} else {
		for _, prd := range recentPRDs {
			sb.WriteString(fmt.Sprintf("- %s\n", filepath.Base(prd)))
		}
	}

	sb.WriteString(`
## Report Content

`)
	sb.WriteString(reportContent)

	sb.WriteString(`

## Required JSON Response Format

Return ONLY valid JSON (no markdown code fences, no explanation):

{
  "priorityItem": "Short title of the priority item",
  "description": "2-3 sentence description of what needs to be built",
  "rationale": "Why this is the highest priority item",
  "acceptanceCriteria": ["Criterion 1", "Criterion 2", "..."],
  "estimatedTasks": 8,
  "branchName": "feature-name-kebab-case"
}

Notes:
- estimatedTasks should be 8-15 for a reasonable scope
- branchName should be kebab-case without any prefix (prefix will be added later)
- acceptanceCriteria should be boolean/verifiable statements
`)

	return sb.String()
}

// parseAnalysisResponse extracts the AnalysisResult from the engine response.
func parseAnalysisResponse(response string) (*AnalysisResult, error) {
	response = strings.TrimSpace(response)

	// Try to find JSON in the response (handle markdown code fences)
	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")

	if jsonStart == -1 || jsonEnd == -1 || jsonEnd < jsonStart {
		return nil, fmt.Errorf("no JSON object found in response")
	}

	jsonStr := response[jsonStart : jsonEnd+1]

	var result AnalysisResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Validate required fields
	if result.PriorityItem == "" {
		return nil, fmt.Errorf("missing required field: priorityItem")
	}
	if result.Description == "" {
		return nil, fmt.Errorf("missing required field: description")
	}
	if result.BranchName == "" {
		return nil, fmt.Errorf("missing required field: branchName")
	}

	return &result, nil
}
