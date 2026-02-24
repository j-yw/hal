package prd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/archive"
	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/skills"
	"github.com/jywlabs/hal/internal/template"
)

// ConvertOptions controls safety behavior during conversion.
type ConvertOptions struct {
	Archive bool
	Force   bool
}

// ConvertWithEngine converts a markdown PRD to JSON using the hal skill via an engine.
// If mdPath is empty, the most recent prd-*.md in .hal/ is used.
func ConvertWithEngine(ctx context.Context, eng engine.Engine, mdPath, outPath string, opts ConvertOptions, display *engine.Display) error {
	// Load hal skill content
	halSkill, err := skills.LoadSkill("hal")
	if err != nil {
		return fmt.Errorf("failed to load hal skill: %w", err)
	}

	mdSource, err := resolveMarkdownSource(mdPath, template.HalDir)
	if err != nil {
		return err
	}

	if display != nil {
		fmt.Fprintf(display.Writer(), "Using source: %s\n", mdSource)
	}

	archiveHalDir := ""
	if opts.Archive {
		halDir, ok := halDirForOutput(outPath)
		if !ok {
			return fmt.Errorf("--archive is only supported when output is .hal/prd.json")
		}
		archiveHalDir = halDir
	}

	mdContent, err := os.ReadFile(mdSource)
	if err != nil {
		return fmt.Errorf("failed to read markdown PRD: %w", err)
	}

	if opts.Archive {
		archiveOpts := archive.CreateOptions{ExcludePaths: []string{mdSource}}
		hasState, err := archive.HasFeatureStateWithOptions(archiveHalDir, archiveOpts)
		if err != nil {
			return fmt.Errorf("failed to check existing feature state: %w", err)
		}
		if hasState {
			out := io.Discard
			if display != nil {
				out = display.Writer()
			}
			fmt.Fprintln(out, "  auto-archiving current state...")
			if _, err := archive.CreateWithOptions(archiveHalDir, "auto-saved", out, archiveOpts); err != nil {
				return fmt.Errorf("failed to auto-archive current state: %w", err)
			}
		}
	}

	prompt := buildConversionPrompt(halSkill, string(mdContent))

	beforeOutput, err := readOutputSnapshot(outPath)
	if err != nil {
		return fmt.Errorf("failed to inspect output file before conversion: %w", err)
	}

	// Execute prompt — AI returns JSON text, but some engines may write the output file directly.
	var response string
	var err2 error
	if display != nil {
		response, err2 = eng.StreamPrompt(ctx, prompt, display)
	} else {
		response, err2 = eng.Prompt(ctx, prompt)
	}
	if err2 != nil {
		return fmt.Errorf("engine prompt failed: %w", err2)
	}

	// Parse and validate JSON from text response.
	prdJSON, parseErr := extractJSONFromResponse(response)
	usedOutputFallback := false
	if parseErr != nil {
		fallbackJSON, usedFallback, fallbackErr := fallbackJSONFromOutput(outPath, beforeOutput)
		if fallbackErr != nil {
			return fmt.Errorf("failed to extract JSON from response (%v) and output fallback failed: %w", parseErr, fallbackErr)
		}
		if !usedFallback {
			return fmt.Errorf("failed to extract JSON from response: %w", parseErr)
		}
		usedOutputFallback = true
		prdJSON = fallbackJSON
	}

	if err := enforceBranchMismatchGuard(outPath, beforeOutput, prdJSON, opts); err != nil {
		if usedOutputFallback {
			if rollbackErr := restoreOutputSnapshot(outPath, beforeOutput); rollbackErr != nil {
				return fmt.Errorf("%w (and failed to rollback output: %v)", err, rollbackErr)
			}
		}
		return err
	}

	// Ensure output directory exists
	outDir := filepath.Dir(outPath)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write prd.json
	if err := os.WriteFile(outPath, []byte(prdJSON), 0644); err != nil {
		return fmt.Errorf("failed to write prd.json: %w", err)
	}

	return nil
}

func buildConversionPrompt(skill, mdContent string) string {
	return fmt.Sprintf(`You are a PRD converter. Using the hal skill rules below, convert this markdown PRD to JSON.

<skill>
%s
</skill>

<markdown>
%s
</markdown>

Convert the markdown PRD to JSON format following the skill rules:
1. Each story must be completable in ONE iteration (split large stories)
2. Stories ordered by dependency (schema → backend → UI)
3. Every story has "Typecheck passes" as acceptance criteria
4. UI stories have "Verify in browser using agent-browser skill (skip if no dev server running)"
5. Acceptance criteria are verifiable (not vague)
6. IDs are sequential (US-001, US-002, etc.)
7. Priority based on dependency order
8. All stories have passes: false and empty notes

IMPORTANT: Do NOT use any tools (no Read, Write, Bash, etc.). Do NOT write any files.
File saving is handled by the caller. Return ONLY the JSON object (no markdown, no explanation). The format must be:
{
  "project": "ProjectName",
  "branchName": "hal/feature-name",
  "description": "Feature description",
  "userStories": [
    {
      "id": "US-001",
      "title": "Story title",
      "description": "As a user, I want X so that Y",
      "acceptanceCriteria": ["Criterion 1", "Criterion 2", "Typecheck passes"],
      "priority": 1,
      "passes": false,
      "notes": ""
    }
  ]
}`, skill, mdContent)
}

func extractJSONFromResponse(response string) (string, error) {
	response = strings.TrimSpace(response)

	// Handle markdown code blocks
	if strings.Contains(response, "```") {
		lines := strings.Split(response, "\n")
		var jsonLines []string
		inBlock := false
		for _, line := range lines {
			if strings.HasPrefix(line, "```") {
				inBlock = !inBlock
				continue
			}
			if inBlock {
				jsonLines = append(jsonLines, line)
			}
		}
		response = strings.Join(jsonLines, "\n")
	}

	// Find JSON object
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start == -1 || end == -1 || end < start {
		return "", fmt.Errorf("no JSON found in response")
	}
	response = response[start : end+1]

	// Validate JSON by parsing it
	var prd engine.PRD
	if err := json.Unmarshal([]byte(response), &prd); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}

	// Re-marshal with proper formatting
	formatted, err := json.MarshalIndent(prd, "", "  ")
	if err != nil {
		return "", err
	}

	return string(formatted), nil
}

type outputSnapshot struct {
	modTime time.Time
	size    int64
	data    []byte
}

func readOutputSnapshot(path string) (*outputSnapshot, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	return &outputSnapshot{
		modTime: info.ModTime(),
		size:    info.Size(),
		data:    data,
	}, nil
}

func fallbackJSONFromOutput(outPath string, before *outputSnapshot) (string, bool, error) {
	after, err := readOutputSnapshot(outPath)
	if err != nil {
		return "", false, err
	}
	if !outputWasUpdated(before, after) {
		return "", false, nil
	}

	var prd engine.PRD
	if err := json.Unmarshal(after.data, &prd); err != nil {
		return "", true, fmt.Errorf("invalid JSON in output file: %w", err)
	}

	formatted, err := json.MarshalIndent(prd, "", "  ")
	if err != nil {
		return "", true, err
	}

	return string(formatted), true, nil
}

func outputWasUpdated(before, after *outputSnapshot) bool {
	if after == nil {
		return false
	}
	if before == nil {
		return true
	}
	if !after.modTime.Equal(before.modTime) || after.size != before.size {
		return true
	}
	return !bytes.Equal(after.data, before.data)
}

func restoreOutputSnapshot(path string, before *outputSnapshot) error {
	if before == nil {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(path, before.data, 0644); err != nil {
		return err
	}
	if err := os.Chtimes(path, before.modTime, before.modTime); err != nil {
		return err
	}

	return nil
}

func enforceBranchMismatchGuard(outPath string, beforeOutput *outputSnapshot, prdJSON string, opts ConvertOptions) error {
	if _, canonical := halDirForOutput(outPath); !canonical {
		return nil
	}

	existingBranch := branchNameFromSnapshot(beforeOutput)
	incomingBranch, err := branchNameFromPRDJSON(prdJSON)
	if err != nil {
		return fmt.Errorf("failed to inspect converted branchName: %w", err)
	}

	if existingBranch == "" || incomingBranch == "" {
		return nil
	}
	if existingBranch == incomingBranch {
		return nil
	}
	if opts.Archive || opts.Force {
		return nil
	}

	return fmt.Errorf("branch changed from %s to %s; run 'hal convert --archive' or 'hal archive' first, or use --force", existingBranch, incomingBranch)
}

func branchNameFromSnapshot(snapshot *outputSnapshot) string {
	if snapshot == nil || len(snapshot.data) == 0 {
		return ""
	}

	var prd engine.PRD
	if err := json.Unmarshal(snapshot.data, &prd); err != nil {
		return ""
	}

	return strings.TrimSpace(prd.BranchName)
}

func branchNameFromPRDJSON(prdJSON string) (string, error) {
	var prd engine.PRD
	if err := json.Unmarshal([]byte(prdJSON), &prd); err != nil {
		return "", err
	}
	return strings.TrimSpace(prd.BranchName), nil
}

func halDirForOutput(outPath string) (string, bool) {
	clean := filepath.Clean(outPath)
	canonical := filepath.Join(template.HalDir, template.PRDFile)
	if clean == canonical {
		return template.HalDir, true
	}
	if !filepath.IsAbs(clean) {
		return "", false
	}
	if filepath.Base(clean) != template.PRDFile {
		return "", false
	}
	dir := filepath.Dir(clean)
	if filepath.Base(dir) != template.HalDir {
		return "", false
	}
	return dir, true
}

func resolveMarkdownSource(mdPath, halDir string) (string, error) {
	if mdPath != "" {
		if _, err := os.Stat(mdPath); err != nil {
			if os.IsNotExist(err) {
				return "", fmt.Errorf("markdown PRD not found: %s", mdPath)
			}
			return "", fmt.Errorf("failed to inspect markdown PRD %s: %w", mdPath, err)
		}
		return mdPath, nil
	}

	return findLatestPRDMarkdown(halDir)
}

func missingMarkdownSourceError(halDir string) error {
	return fmt.Errorf("no prd-*.md files found in %s; run `hal plan` or pass an explicit markdown path", halDir)
}

func findLatestPRDMarkdown(halDir string) (string, error) {
	prdMDs, err := filepath.Glob(filepath.Join(halDir, "prd-*.md"))
	if err != nil {
		return "", fmt.Errorf("failed to scan PRD markdown files: %w", err)
	}
	if len(prdMDs) == 0 {
		return "", missingMarkdownSourceError(halDir)
	}

	type prdMDCandidate struct {
		path    string
		modTime time.Time
	}

	candidates := make([]prdMDCandidate, 0, len(prdMDs))
	for _, path := range prdMDs {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		candidates = append(candidates, prdMDCandidate{path: path, modTime: info.ModTime()})
	}

	if len(candidates) == 0 {
		return "", missingMarkdownSourceError(halDir)
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].modTime.Equal(candidates[j].modTime) {
			return filepath.Base(candidates[i].path) < filepath.Base(candidates[j].path)
		}
		return candidates[i].modTime.After(candidates[j].modTime)
	})

	return candidates[0].path, nil
}
