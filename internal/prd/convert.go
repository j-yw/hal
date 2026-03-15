package prd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

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

	beforeOutput, err := readOutputSnapshot(outPath)
	if err != nil {
		return fmt.Errorf("failed to inspect output file before conversion: %w", err)
	}

	branchResolution := resolveMarkdownBranch(string(mdContent))
	targetBranchName := selectConvertBranchName(branchResolution)

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

	prompt := buildConversionPrompt(halSkill, string(mdContent), targetBranchName)

	// Execute prompt — AI returns JSON text, but some engines may write the output file directly.
	var response string
	var err2 error
	if display != nil {
		response, err2 = eng.StreamPrompt(ctx, prompt, display)
	} else {
		response, err2 = eng.Prompt(ctx, prompt)
	}
	if err2 != nil {
		if engine.RequiresOutputFallback(err2) {
			fallbackJSON, usedFallback, fallbackErr := fallbackJSONFromOutput(outPath, beforeOutput)
			if fallbackErr != nil {
				return fmt.Errorf("engine prompt failed: %w (and output fallback failed: %v)", err2, fallbackErr)
			}
			if usedFallback {
				response = fallbackJSON
			} else {
				return fmt.Errorf("engine prompt failed: %w", err2)
			}
		} else {
			return fmt.Errorf("engine prompt failed: %w", err2)
		}
	}

	// Parse and validate JSON from text response.
	prdJSON, parseErr := extractJSONFromResponse(response)
	if parseErr != nil {
		fallbackJSON, usedFallback, fallbackErr := fallbackJSONFromOutput(outPath, beforeOutput)
		if fallbackErr != nil {
			return fmt.Errorf("failed to extract JSON from response (%v) and output fallback failed: %w", parseErr, fallbackErr)
		}
		if !usedFallback {
			return fmt.Errorf("failed to extract JSON from response: %w", parseErr)
		}
		prdJSON = fallbackJSON
	}

	if targetBranchName != "" {
		prdJSON, err = setPRDBranchName(prdJSON, targetBranchName)
		if err != nil {
			return fmt.Errorf("failed to pin converted branchName: %w", err)
		}
	}

	if err := enforceBranchMismatchGuardWithRollback(outPath, beforeOutput, prdJSON, opts); err != nil {
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

func buildConversionPrompt(skill, mdContent, resolvedBranchName string) string {
	branchRule := `9. Set branchName to a stable feature branch name prefixed with hal/`
	branchExample := "hal/feature-name"
	if resolvedBranchName != "" {
		branchRule = fmt.Sprintf("9. Use this exact branchName: %s. Do not invent or rename it.", resolvedBranchName)
		branchExample = resolvedBranchName
	}

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
4. UI stories have "%s"
5. Acceptance criteria are verifiable (not vague)
6. IDs are sequential (US-001, US-002, etc.)
7. Priority based on dependency order
8. All stories have passes: false and empty notes
%s

IMPORTANT: Do NOT use any tools (no Read, Write, Bash, etc.). Do NOT write any files.
File saving is handled by the caller. Return ONLY the JSON object (no markdown, no explanation). The format must be:
{
  "project": "ProjectName",
  "branchName": "%s",
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
}`, skill, mdContent, template.BrowserVerificationCriterion, branchRule, branchExample)
}

var (
	branchSlugPattern               = regexp.MustCompile(`[^a-z0-9]+`)
	trailingBranchAnnotationPattern = regexp.MustCompile(`\s+\([^()]*\)$`)
)

const markdownBranchMetadataLineLimit = 20

type markdownBranchResolution struct {
	Name     string
	Explicit bool
}

func resolveMarkdownBranch(mdContent string) markdownBranchResolution {
	if branch := branchNameFromMarkdownField(mdContent); branch != "" {
		return markdownBranchResolution{Name: branch, Explicit: true}
	}

	return markdownBranchResolution{Name: branchNameFromMarkdownHeading(mdContent)}
}

func resolveMarkdownBranchName(mdContent string) string {
	return resolveMarkdownBranch(mdContent).Name
}

func selectConvertBranchName(branch markdownBranchResolution) string {
	return branch.Name
}

func branchNameFromMarkdownField(mdContent string) string {
	lines := strings.Split(mdContent, "\n")
	start, frontmatterEnd, hasFrontmatter := markdownFrontmatterBounds(lines)
	if hasFrontmatter {
		for i := start + 1; i < frontmatterEnd-1; i++ {
			if branch := explicitBranchNameFromLine(lines[i], true); branch != "" {
				return branch
			}
		}
		start = frontmatterEnd
	}

	fenceDelimiter := ""
	significantLines := 0
	for i := start; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if delimiter := markdownFenceDelimiter(trimmed); delimiter != "" {
			if fenceDelimiter == "" {
				fenceDelimiter = delimiter
			} else if fenceDelimiter == delimiter {
				fenceDelimiter = ""
			}
			continue
		}
		if fenceDelimiter != "" || trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "##") {
			break
		}

		significantLines++
		if significantLines > markdownBranchMetadataLineLimit {
			break
		}

		if branch := explicitBranchNameFromLine(lines[i], true); branch != "" {
			return branch
		}
	}
	return ""
}

func explicitBranchNameFromLine(line string, stripInlineComment bool) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return ""
	}

	trimmed = strings.TrimPrefix(trimmed, "- ")
	trimmed = strings.TrimPrefix(trimmed, "* ")
	plain := strings.ReplaceAll(trimmed, "**", "")
	lower := strings.ToLower(plain)

	switch {
	case strings.HasPrefix(lower, "branchname:"):
		return normalizeExplicitBranchName(plain[len("branchname:"):], stripInlineComment)
	case strings.HasPrefix(lower, "branch name:"):
		return normalizeExplicitBranchName(plain[len("branch name:"):], stripInlineComment)
	default:
		return ""
	}
}

func branchNameFromMarkdownHeading(mdContent string) string {
	lines := strings.Split(mdContent, "\n")
	start, frontmatterEnd, hasFrontmatter := markdownFrontmatterBounds(lines)
	if hasFrontmatter {
		start = frontmatterEnd
	}

	fenceDelimiter := ""
	for _, line := range lines[start:] {
		trimmed := strings.TrimSpace(line)
		if delimiter := markdownFenceDelimiter(trimmed); delimiter != "" {
			if fenceDelimiter == "" {
				fenceDelimiter = delimiter
			} else if fenceDelimiter == delimiter {
				fenceDelimiter = ""
			}
			continue
		}
		if fenceDelimiter != "" || !isMarkdownH1(trimmed) {
			continue
		}

		title := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
		title = stripMarkdownTitlePrefix(title)
		slug := slugifyBranchFragment(title)
		if isGenericBranchSlug(slug) {
			return ""
		}
		return "hal/" + slug
	}
	return ""
}

func markdownFrontmatterBounds(lines []string) (int, int, bool) {
	start := 0
	for start < len(lines) && strings.TrimSpace(lines[start]) == "" {
		start++
	}
	if start >= len(lines) || strings.TrimSpace(lines[start]) != "---" {
		return start, start, false
	}

	for i := start + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			return start, i + 1, true
		}
	}

	return start, start, false
}

func markdownFenceDelimiter(line string) string {
	switch {
	case strings.HasPrefix(line, "```"):
		return "```"
	case strings.HasPrefix(line, "~~~"):
		return "~~~"
	default:
		return ""
	}
}

func isMarkdownH1(line string) bool {
	return strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "##")
}

func stripMarkdownTitlePrefix(title string) string {
	trimmed := strings.TrimSpace(title)
	lower := strings.ToLower(trimmed)

	switch {
	case strings.HasPrefix(lower, "prd:"):
		return strings.TrimSpace(trimmed[len("prd:"):])
	case strings.HasPrefix(lower, "prd -"):
		return strings.TrimSpace(trimmed[len("prd -"):])
	case strings.HasPrefix(lower, "product requirements document:"):
		return strings.TrimSpace(trimmed[len("product requirements document:"):])
	case strings.HasPrefix(lower, "product requirements document -"):
		return strings.TrimSpace(trimmed[len("product requirements document -"):])
	case strings.HasPrefix(lower, "feature specification:"):
		return strings.TrimSpace(trimmed[len("feature specification:"):])
	case strings.HasPrefix(lower, "feature specification -"):
		return strings.TrimSpace(trimmed[len("feature specification -"):])
	default:
		return trimmed
	}
}

func normalizeExplicitBranchName(raw string, stripInlineComment bool) string {
	trimmed := trimExplicitBranchValue(raw)
	trimmed = stripExplicitBranchAnnotations(trimmed, stripInlineComment)
	trimmed = trimExplicitBranchValue(trimmed)
	if trimmed == "" {
		return ""
	}

	if len(trimmed) >= len("hal/") && strings.EqualFold(trimmed[:len("hal/")], "hal/") {
		suffix := normalizeExplicitBranchPath(trimmed[len("hal/"):])
		if suffix == "" {
			return ""
		}
		return "hal/" + suffix
	}

	normalized := normalizeExplicitBranchPath(trimmed)
	if normalized == "" {
		return ""
	}

	return "hal/" + normalized
}

func normalizeExplicitBranchPath(value string) string {
	segments := strings.Split(strings.TrimLeft(value, "/"), "/")
	normalized := make([]string, 0, len(segments))
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		if strings.ContainsAny(segment, " \t") {
			segment = slugifyBranchFragment(segment)
		}
		if segment == "" {
			continue
		}
		normalized = append(normalized, segment)
	}

	return strings.Join(normalized, "/")
}

func trimExplicitBranchValue(value string) string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.Trim(trimmed, "`\"'")
	trimmed = strings.TrimSpace(trimmed)
	trimmed = strings.TrimSuffix(trimmed, ".")
	return strings.TrimSpace(trimmed)
}

func stripExplicitBranchAnnotations(value string, stripInlineComment bool) string {
	trimmed := strings.TrimSpace(value)
	if stripInlineComment {
		trimmed = strings.TrimSpace(stripTrailingInlineBranchComment(trimmed))
	}
	for {
		next := strings.TrimSpace(trailingBranchAnnotationPattern.ReplaceAllString(trimmed, ""))
		if next == trimmed {
			return trimmed
		}
		trimmed = next
	}
}

func stripTrailingInlineBranchComment(value string) string {
	idx := strings.LastIndex(value, " #")
	if idx == -1 {
		return value
	}

	prefix := strings.TrimSpace(value[:idx])
	comment := strings.TrimSpace(value[idx+2:])
	if prefix == "" || comment == "" {
		return value
	}

	if shouldStripTrailingInlineBranchComment(prefix, comment) {
		return prefix
	}

	return value
}

func shouldStripTrailingInlineBranchComment(prefix, comment string) bool {
	for _, r := range comment {
		switch {
		case unicode.IsLetter(r):
			return true
		case unicode.IsDigit(r):
			return looksLikeNormalizedBranchPrefix(prefix)
		default:
			return false
		}
	}

	return false
}

func looksLikeNormalizedBranchPrefix(prefix string) bool {
	if prefix == "" || prefix != strings.ToLower(prefix) {
		return false
	}
	if strings.HasPrefix(prefix, "hal/") {
		return true
	}

	return strings.ContainsAny(prefix, "/-_.")
}

func slugifyBranchFragment(value string) string {
	slug := strings.ToLower(strings.TrimSpace(value))
	slug = branchSlugPattern.ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-")
	return slug
}

func isGenericBranchSlug(slug string) bool {
	switch slug {
	case "", "prd", "feature", "feature-specification", "product-requirements-document":
		return true
	default:
		return false
	}
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

func enforceBranchMismatchGuardWithRollback(outPath string, beforeOutput *outputSnapshot, prdJSON string, opts ConvertOptions) error {
	if err := enforceBranchMismatchGuard(outPath, beforeOutput, prdJSON, opts); err != nil {
		afterOutput, snapshotErr := readOutputSnapshot(outPath)
		if snapshotErr != nil {
			return fmt.Errorf("%w (and failed to inspect output for rollback: %v)", err, snapshotErr)
		}
		if outputWasUpdated(beforeOutput, afterOutput) {
			if rollbackErr := restoreOutputSnapshot(outPath, beforeOutput); rollbackErr != nil {
				return fmt.Errorf("%w (and failed to rollback output: %v)", err, rollbackErr)
			}
		}
		return err
	}

	return nil
}

func enforceBranchMismatchGuard(outPath string, beforeOutput *outputSnapshot, prdJSON string, opts ConvertOptions) error {
	incomingBranch, err := branchNameFromPRDJSON(prdJSON)
	if err != nil {
		return fmt.Errorf("failed to inspect converted branchName: %w", err)
	}

	return enforceBranchMismatch(outPath, beforeOutput, incomingBranch, opts)
}

func enforceBranchMismatch(outPath string, beforeOutput *outputSnapshot, incomingBranch string, opts ConvertOptions) error {
	if _, canonical := halDirForOutput(outPath); !canonical {
		return nil
	}

	existingBranch := branchNameFromSnapshot(beforeOutput)
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

func setPRDBranchName(prdJSON, branchName string) (string, error) {
	if strings.TrimSpace(branchName) == "" {
		return prdJSON, nil
	}

	var prd engine.PRD
	if err := json.Unmarshal([]byte(prdJSON), &prd); err != nil {
		return "", err
	}
	prd.BranchName = strings.TrimSpace(branchName)

	formatted, err := json.MarshalIndent(prd, "", "  ")
	if err != nil {
		return "", err
	}

	return string(formatted), nil
}

func halDirForOutput(outPath string) (string, bool) {
	clean := filepath.Clean(outPath)
	canonical := filepath.Join(template.HalDir, template.PRDFile)
	if clean == canonical {
		return template.HalDir, true
	}

	outAbs, err := filepath.Abs(clean)
	if err != nil {
		return "", false
	}

	canonicalAbs, err := filepath.Abs(canonical)
	if err != nil {
		return "", false
	}

	if !sameFilesystemPath(outAbs, canonicalAbs) {
		return "", false
	}

	return filepath.Dir(outAbs), true
}

func sameFilesystemPath(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}

	aEval, aErr := filepath.EvalSymlinks(a)
	bEval, bErr := filepath.EvalSymlinks(b)
	if aErr == nil && bErr == nil && filepath.Clean(aEval) == filepath.Clean(bEval) {
		return true
	}

	if filepath.Base(a) != filepath.Base(b) {
		return false
	}

	aDirEval, aDirErr := filepath.EvalSymlinks(filepath.Dir(a))
	bDirEval, bDirErr := filepath.EvalSymlinks(filepath.Dir(b))
	if aDirErr == nil && bDirErr == nil {
		return filepath.Clean(aDirEval) == filepath.Clean(bDirEval)
	}

	return false
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
