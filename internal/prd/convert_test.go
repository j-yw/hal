package prd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/archive"
	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/template"
)

type mockEngine struct {
	promptResponse string
	promptError    error
	promptHook     func() error
	lastPrompt     string
}

func (m *mockEngine) Name() string {
	return "mock"
}

func (m *mockEngine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	return engine.Result{}
}

func (m *mockEngine) Prompt(ctx context.Context, prompt string) (string, error) {
	m.lastPrompt = prompt
	if m.promptHook != nil {
		if err := m.promptHook(); err != nil {
			return "", err
		}
	}
	return m.promptResponse, m.promptError
}

func (m *mockEngine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	m.lastPrompt = prompt
	if m.promptHook != nil {
		if err := m.promptHook(); err != nil {
			return "", err
		}
	}
	return m.promptResponse, m.promptError
}

func writePRDJSON(t *testing.T, dir, filename, branchName string) {
	t.Helper()
	prd := engine.PRD{
		Project:     "test",
		BranchName:  branchName,
		Description: "test",
		UserStories: []engine.UserStory{},
	}
	data, err := json.MarshalIndent(prd, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filename), data, 0644); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func chdirTo(t *testing.T, dir string) {
	t.Helper()

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("failed to chdir to temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
	})
}

func readPRDBranchName(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read PRD %s: %v", path, err)
	}

	var prd engine.PRD
	if err := json.Unmarshal(data, &prd); err != nil {
		t.Fatalf("failed to parse PRD %s: %v", path, err)
	}

	return prd.BranchName
}

func promptResponseWithBranch(t *testing.T, branch string) string {
	t.Helper()

	payload := engine.PRD{
		Project:     "test",
		BranchName:  branch,
		Description: "desc",
		UserStories: []engine.UserStory{},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal prompt response: %v", err)
	}

	return string(data)
}

func TestConvertWithEngine_UsesOutputFallbackWhenStreamRequiresFile(t *testing.T) {
	tmpDir := t.TempDir()
	chdirTo(t, tmpDir)

	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	mdPath := filepath.Join(halDir, "prd-new.md")
	writeFile(t, mdPath, "# PRD: New Feature")

	outPath := filepath.Join(halDir, template.PRDFile)
	eng := &mockEngine{
		promptError: engine.NewOutputFallbackRequiredError(fmt.Errorf("prompt failed")),
		promptHook: func() error {
			writeFile(t, outPath, promptResponseWithBranch(t, "hal/new-feature"))
			return nil
		},
	}

	var buf bytes.Buffer
	display := engine.NewDisplay(&buf)
	if err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{}, display); err != nil {
		t.Fatalf("ConvertWithEngine() error = %v, want nil", err)
	}
	if got := readPRDBranchName(t, outPath); got != "hal/new-feature" {
		t.Fatalf("output branchName = %q, want %q", got, "hal/new-feature")
	}
}

func TestResolveMarkdownBranchName(t *testing.T) {
	tests := []struct {
		name      string
		mdContent string
		mdPath    string
		want      string
	}{
		{
			name: "prefers explicit branch name field",
			mdContent: `---
branchName: hal/explicit-feature
---

# PRD: Ignored Title`,
			mdPath: filepath.Join(template.HalDir, "prd-fallback.md"),
			want:   "hal/explicit-feature",
		},
		{
			name: "ignores inline frontmatter comments after explicit branch name",
			mdContent: `---
branchName: hal/auth # existing branch
---

# PRD: Ignored Title`,
			want: "hal/auth",
		},
		{
			name: "ignores numeric inline frontmatter comments after explicit branch name",
			mdContent: `---
branchName: hal/auth #123
---

# PRD: Ignored Title`,
			want: "hal/auth",
		},
		{
			name: "normalizes explicit branch label without prefix",
			mdContent: `# PRD: Ignored Title

**Branch Name:** exact-feature`,
			want: "hal/exact-feature",
		},
		{
			name: "ignores trailing parenthetical notes after explicit branch label",
			mdContent: `# PRD: Ignored Title

**Branch Name:** hal/auth (legacy)`,
			want: "hal/auth",
		},
		{
			name: "preserves hash content in body branch labels",
			mdContent: `# PRD: Ignored Title

**Branch Name:** Feature #1`,
			want: "hal/feature-1",
		},
		{
			name: "ignores inline body comments after explicit branch label",
			mdContent: `# PRD: Ignored Title

**Branch Name:** hal/auth # existing branch`,
			want: "hal/auth",
		},
		{
			name: "ignores numeric inline body comments after explicit branch label",
			mdContent: `# PRD: Ignored Title

**Branch Name:** hal/auth #1`,
			want: "hal/auth",
		},
		{
			name: "normalizes explicit branch label with non-hal prefix",
			mdContent: `---
branchName: feature/foo
---

# PRD: Ignored Title`,
			want: "hal/feature/foo",
		},
		{
			name: "preserves hal prefix when slugifying explicit branch names with spaces",
			mdContent: `---
branchName: hal/Auth Refresh
---

# PRD: Ignored Title`,
			want: "hal/auth-refresh",
		},
		{
			name: "preserves slash-separated explicit branch paths when slugifying spaced segments",
			mdContent: `---
branchName: feature/auth refresh
---

# PRD: Ignored Title`,
			want: "hal/feature/auth-refresh",
		},
		{
			name: "ignores bare branch alias in frontmatter",
			mdContent: `---
branch: develop
---

# PRD: Feature Title`,
			want: "hal/feature-title",
		},
		{
			name: "skips YAML frontmatter comments before deriving branch from h1",
			mdContent: `---
# generated by template
owner: product
---

# PRD: Feature Title`,
			want: "hal/feature-title",
		},
		{
			name: "ignores bare branch alias in body metadata",
			mdContent: `# PRD: Feature Title

**Branch:** main`,
			want: "hal/feature-title",
		},
		{
			name: "ignores explicit branch labels outside the top section",
			mdContent: `# PRD: Feature Title

## Notes

**Branch Name:** hal/example-branch`,
			want: "hal/feature-title",
		},
		{
			name: "ignores non-h1 headings before title",
			mdContent: `## Overview

# PRD: Feature Title`,
			want: "hal/feature-title",
		},
		{
			name:      "ignores headings inside code fences before title",
			mdContent: "```md\n# Example Heading\n```\n\n# PRD: Feature Title",
			want:      "hal/feature-title",
		},
		{
			name:      "derives branch from markdown title",
			mdContent: "# PRD: TechOps Playbook Routing MVP Backport",
			want:      "hal/techops-playbook-routing-mvp-backport",
		},
		{
			name:      "falls back to filename slug when heading is generic",
			mdContent: "# PRD",
			mdPath:    filepath.Join(template.HalDir, "prd-filename-fallback.md"),
			want:      "hal/filename-fallback",
		},
		{
			name:      "title-derived slug takes precedence over filename fallback",
			mdContent: "# PRD: Title Wins",
			mdPath:    filepath.Join(template.HalDir, "prd-filename-loses.md"),
			want:      "hal/title-wins",
		},
		{
			name: "metadata takes precedence over title and filename fallback",
			mdContent: `---
branchName: hal/metadata-wins
---

# PRD: Title Loses`,
			mdPath: filepath.Join(template.HalDir, "prd-filename-loses.md"),
			want:   "hal/metadata-wins",
		},
		{
			name:      "returns empty when metadata title and filename are generic",
			mdContent: "# PRD",
			mdPath:    filepath.Join(template.HalDir, "prd.md"),
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveMarkdownBranchName(tt.mdContent, tt.mdPath); got != tt.want {
				t.Fatalf("ResolveMarkdownBranchName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConvertWithEngine_ArchiveOptInArchivesExistingState(t *testing.T) {
	tmpDir := t.TempDir()
	chdirTo(t, tmpDir)
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	writePRDJSON(t, halDir, template.PRDFile, "hal/old")
	writeFile(t, filepath.Join(halDir, template.ProgressFile), "progress")

	mdPath := filepath.Join(halDir, "prd-new.md")
	writeFile(t, mdPath, "# PRD")

	outPath := filepath.Join(halDir, template.PRDFile)
	eng := &mockEngine{
		promptResponse: `{"project":"test","branchName":"hal/new","description":"desc","userStories":[]}`,
	}

	if err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{Archive: true}, nil); err != nil {
		t.Fatalf("ConvertWithEngine failed: %v", err)
	}

	if _, err := os.Stat(mdPath); err != nil {
		t.Fatalf("expected markdown PRD to remain, got error: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output prd.json: %v", err)
	}
	var prd engine.PRD
	if err := json.Unmarshal(data, &prd); err != nil {
		t.Fatalf("failed to parse output prd.json: %v", err)
	}
	if prd.BranchName != "hal/new" {
		t.Fatalf("unexpected output branchName: %s", prd.BranchName)
	}

	archives, err := archive.List(halDir)
	if err != nil {
		t.Fatalf("failed to list archives: %v", err)
	}
	found := false
	var auto archive.ArchiveInfo
	for _, entry := range archives {
		if strings.Contains(entry.Name, "auto-saved") {
			found = true
			auto = entry
			break
		}
	}
	if !found {
		t.Fatal("expected auto-saved archive")
	}

	if _, err := os.Stat(filepath.Join(auto.Dir, filepath.Base(mdPath))); err == nil {
		t.Fatal("expected markdown PRD to be excluded from archive")
	}
	if _, err := os.Stat(filepath.Join(auto.Dir, template.ProgressFile)); err != nil {
		t.Fatalf("expected progress.txt archived, got error: %v", err)
	}
}

func TestConvertWithEngine_DefaultRunDoesNotArchiveExistingState(t *testing.T) {
	tmpDir := t.TempDir()
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	writePRDJSON(t, halDir, template.PRDFile, "hal/new")
	writeFile(t, filepath.Join(halDir, template.ProgressFile), "progress")
	mdPath := filepath.Join(halDir, "prd-new.md")
	writeFile(t, mdPath, "# PRD")

	outPath := filepath.Join(halDir, template.PRDFile)
	eng := &mockEngine{
		promptResponse: `{"project":"test","branchName":"hal/new","description":"desc","userStories":[]}`,
	}

	if err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{}, nil); err != nil {
		t.Fatalf("ConvertWithEngine failed: %v", err)
	}

	archives, err := archive.List(halDir)
	if err != nil {
		t.Fatalf("failed to list archives: %v", err)
	}
	if len(archives) != 0 {
		t.Fatalf("expected no archives for default convert, got %d", len(archives))
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output prd.json: %v", err)
	}
	var prd engine.PRD
	if err := json.Unmarshal(data, &prd); err != nil {
		t.Fatalf("failed to parse output prd.json: %v", err)
	}
	if prd.BranchName != "hal/new" {
		t.Fatalf("unexpected output branchName: %s", prd.BranchName)
	}
}

func TestConvertWithEngine_CustomOutputWithoutArchiveSkipsArchiveSideEffects(t *testing.T) {
	tmpDir := t.TempDir()
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	writePRDJSON(t, halDir, template.PRDFile, "hal/old")
	writeFile(t, filepath.Join(halDir, template.ProgressFile), "progress")
	mdPath := filepath.Join(halDir, "prd-custom.md")
	writeFile(t, mdPath, "# PRD")

	outPath := filepath.Join(tmpDir, "custom-prd.json")
	eng := &mockEngine{
		promptResponse: `{"project":"test","branchName":"hal/new","description":"desc","userStories":[]}`,
	}

	if err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{}, nil); err != nil {
		t.Fatalf("ConvertWithEngine failed: %v", err)
	}

	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected custom output to be written, got error: %v", err)
	}
	archives, err := archive.List(halDir)
	if err != nil {
		t.Fatalf("failed to list archives: %v", err)
	}
	if len(archives) != 0 {
		t.Fatalf("expected no archives for custom output default run, got %d", len(archives))
	}
}

func TestConvertWithEngine_CanonicalOutputUsesResolvedBranchAndPreservesMismatchGuard(t *testing.T) {
	tmpDir := t.TempDir()
	chdirTo(t, tmpDir)
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(halDir, template.PRDFile)
	writePRDJSON(t, halDir, template.PRDFile, "hal/unified-cookie-web-authentication")

	mdPath := filepath.Join(halDir, "prd-new.md")
	writeFile(t, mdPath, "# PRD: TechOps Playbook Routing MVP Backport")

	eng := &mockEngine{
		promptResponse: promptResponseWithBranch(t, "hal/something-else"),
	}

	err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{}, nil)
	if err == nil {
		t.Fatal("expected branch mismatch error")
	}

	want := "branch changed from hal/unified-cookie-web-authentication to hal/techops-playbook-routing-mvp-backport; run 'hal convert --archive' or 'hal archive' first, or use --force"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := readPRDBranchName(t, outPath); got != "hal/unified-cookie-web-authentication" {
		t.Fatalf("expected canonical PRD to remain unchanged, got branch %q", got)
	}
	if !strings.Contains(eng.lastPrompt, "Use this exact branchName: hal/techops-playbook-routing-mvp-backport.") {
		t.Fatalf("prompt did not pin resolved markdown branchName:\n%s", eng.lastPrompt)
	}
}

func TestConvertWithEngine_ResolvedBranchPinsOutputAndPrompt(t *testing.T) {
	tmpDir := t.TempDir()
	chdirTo(t, tmpDir)
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(halDir, template.PRDFile)
	mdPath := filepath.Join(halDir, "prd-new.md")
	writeFile(t, mdPath, "# PRD: TechOps Playbook Routing MVP Backport")

	eng := &mockEngine{
		promptResponse: promptResponseWithBranch(t, "hal/wrong-feature"),
	}

	if err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{}, nil); err != nil {
		t.Fatalf("ConvertWithEngine failed: %v", err)
	}

	if got := readPRDBranchName(t, outPath); got != "hal/techops-playbook-routing-mvp-backport" {
		t.Fatalf("output branchName = %q, want %q", got, "hal/techops-playbook-routing-mvp-backport")
	}
	if !strings.Contains(eng.lastPrompt, "Use this exact branchName: hal/techops-playbook-routing-mvp-backport.") {
		t.Fatalf("prompt did not pin exact branchName:\n%s", eng.lastPrompt)
	}
}

func TestConvertWithEngine_OptionBranchNamePinsOutputAndPrompt(t *testing.T) {
	tmpDir := t.TempDir()
	chdirTo(t, tmpDir)
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(halDir, template.PRDFile)
	mdPath := filepath.Join(halDir, "prd-new.md")
	writeFile(t, mdPath, `---
branchName: hal/from-markdown
---

# PRD: Ignored Title`)

	eng := &mockEngine{
		promptResponse: promptResponseWithBranch(t, "hal/wrong-feature"),
	}

	if err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{BranchName: "hal/from-flag"}, nil); err != nil {
		t.Fatalf("ConvertWithEngine failed: %v", err)
	}

	if got := readPRDBranchName(t, outPath); got != "hal/from-flag" {
		t.Fatalf("output branchName = %q, want %q", got, "hal/from-flag")
	}
	if !strings.Contains(eng.lastPrompt, "Use this exact branchName: hal/from-flag.") {
		t.Fatalf("prompt did not pin explicit option branchName:\n%s", eng.lastPrompt)
	}
}

func TestConvertWithEngine_GranularOptionAddsTaskGuidanceToPrompt(t *testing.T) {
	tmpDir := t.TempDir()
	chdirTo(t, tmpDir)
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	mdPath := filepath.Join(halDir, "prd-new.md")
	writeFile(t, mdPath, "# PRD")
	outPath := filepath.Join(tmpDir, "out.json")

	eng := &mockEngine{
		promptResponse: promptResponseWithBranch(t, "hal/new-feature"),
	}

	if err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{Granular: true}, nil); err != nil {
		t.Fatalf("ConvertWithEngine failed: %v", err)
	}

	checks := []string{
		"Decompose into 8-15 atomic tasks, each completable in ONE agent iteration",
		"IDs are sequential (T-001, T-002, etc.)",
		"\"id\": \"T-001\"",
	}
	for _, want := range checks {
		if !strings.Contains(eng.lastPrompt, want) {
			t.Fatalf("granular prompt missing %q:\n%s", want, eng.lastPrompt)
		}
	}
}

func TestConvertWithEngine_ExplicitBranchAnnotationsPinOutputAndPrompt(t *testing.T) {
	tmpDir := t.TempDir()
	chdirTo(t, tmpDir)
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(halDir, template.PRDFile)
	mdPath := filepath.Join(halDir, "prd-new.md")
	writeFile(t, mdPath, `---
branchName: hal/auth # existing branch
---

# PRD: Ignored Title`)

	eng := &mockEngine{
		promptResponse: promptResponseWithBranch(t, "hal/wrong-feature"),
	}

	if err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{}, nil); err != nil {
		t.Fatalf("ConvertWithEngine failed: %v", err)
	}

	if got := readPRDBranchName(t, outPath); got != "hal/auth" {
		t.Fatalf("output branchName = %q, want %q", got, "hal/auth")
	}
	if !strings.Contains(eng.lastPrompt, "Use this exact branchName: hal/auth.") {
		t.Fatalf("prompt did not pin exact branchName:\n%s", eng.lastPrompt)
	}
}

func TestConvertWithEngine_ExplicitBranchPathWithSpacesPinsOutputAndPrompt(t *testing.T) {
	tmpDir := t.TempDir()
	chdirTo(t, tmpDir)
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(halDir, template.PRDFile)
	mdPath := filepath.Join(halDir, "prd-new.md")
	writeFile(t, mdPath, `---
branchName: feature/auth refresh
---

# PRD: Ignored Title`)

	eng := &mockEngine{
		promptResponse: promptResponseWithBranch(t, "hal/wrong-feature"),
	}

	if err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{}, nil); err != nil {
		t.Fatalf("ConvertWithEngine failed: %v", err)
	}

	if got := readPRDBranchName(t, outPath); got != "hal/feature/auth-refresh" {
		t.Fatalf("output branchName = %q, want %q", got, "hal/feature/auth-refresh")
	}
	if !strings.Contains(eng.lastPrompt, "Use this exact branchName: hal/feature/auth-refresh.") {
		t.Fatalf("prompt did not pin exact branchName:\n%s", eng.lastPrompt)
	}
}

func TestConvertWithEngine_ExplicitMarkdownBranchMismatchStillFails(t *testing.T) {
	tmpDir := t.TempDir()
	chdirTo(t, tmpDir)
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(halDir, template.PRDFile)
	writePRDJSON(t, halDir, template.PRDFile, "hal/old-feature")

	mdPath := filepath.Join(halDir, "prd-new.md")
	writeFile(t, mdPath, `---
branchName: hal/new-feature
---

# PRD: Ignored Title`)

	eng := &mockEngine{
		promptResponse: promptResponseWithBranch(t, "hal/something-else"),
	}

	err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{}, nil)
	if err == nil {
		t.Fatal("expected branch mismatch error")
	}

	want := "branch changed from hal/old-feature to hal/new-feature; run 'hal convert --archive' or 'hal archive' first, or use --force"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := readPRDBranchName(t, outPath); got != "hal/old-feature" {
		t.Fatalf("expected canonical PRD to remain unchanged, got branch %q", got)
	}
	if !strings.Contains(eng.lastPrompt, "Use this exact branchName: hal/new-feature.") {
		t.Fatalf("prompt did not pin explicit branchName:\n%s", eng.lastPrompt)
	}
}

func TestConvertWithEngine_BranchlessMarkdownFallsBackToFilename(t *testing.T) {
	tmpDir := t.TempDir()
	chdirTo(t, tmpDir)
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(halDir, template.PRDFile)
	writePRDJSON(t, halDir, template.PRDFile, "hal/old-feature")

	mdPath := filepath.Join(halDir, "prd-new-feature.md")
	writeFile(t, mdPath, "# PRD")

	eng := &mockEngine{
		promptResponse: promptResponseWithBranch(t, "hal/something-else"),
	}

	err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{}, nil)
	if err == nil {
		t.Fatal("expected branch mismatch error")
	}

	want := "branch changed from hal/old-feature to hal/new-feature; run 'hal convert --archive' or 'hal archive' first, or use --force"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := readPRDBranchName(t, outPath); got != "hal/old-feature" {
		t.Fatalf("expected canonical PRD to remain unchanged, got branch %q", got)
	}
	if !strings.Contains(eng.lastPrompt, "Use this exact branchName: hal/new-feature.") {
		t.Fatalf("prompt did not pin filename-derived branchName:\n%s", eng.lastPrompt)
	}
}

func TestConvertWithEngine_UnresolvedBranchNameReturnsBlockingError(t *testing.T) {
	tmpDir := t.TempDir()
	chdirTo(t, tmpDir)
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	mdPath := filepath.Join(halDir, "prd.md")
	writeFile(t, mdPath, "# PRD")

	outPath := filepath.Join(tmpDir, "out.json")
	eng := &mockEngine{
		promptResponse: promptResponseWithBranch(t, "hal/engine-branch"),
	}

	err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{}, nil)
	if err == nil {
		t.Fatal("expected unresolved branchName error")
	}
	want := "unable to resolve branchName from markdown metadata, title, or filename; pass --branch"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("unexpected error: %v", err)
	}
	if eng.lastPrompt != "" {
		t.Fatalf("expected engine prompt not to run, got %q", eng.lastPrompt)
	}
}

func TestConvertWithEngine_ArchiveRequiresCanonicalOutput(t *testing.T) {
	tmpDir := t.TempDir()
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	writePRDJSON(t, halDir, template.PRDFile, "hal/old")
	writeFile(t, filepath.Join(halDir, template.ProgressFile), "progress")
	mdPath := filepath.Join(halDir, "prd-new.md")
	writeFile(t, mdPath, "# PRD")

	outPath := filepath.Join(tmpDir, "custom-prd.json")
	eng := &mockEngine{
		promptResponse: `{"project":"test","branchName":"hal/new","description":"desc","userStories":[]}`,
	}

	err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{Archive: true}, nil)
	if err == nil {
		t.Fatal("expected error for --archive with non-canonical output path")
	}
	if !strings.Contains(err.Error(), "--archive is only supported when output is .hal/prd.json") {
		t.Fatalf("unexpected error: %v", err)
	}
	if eng.lastPrompt != "" {
		t.Fatalf("expected engine not to run when --archive guard fails, got prompt %q", eng.lastPrompt)
	}

	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected no output file to be written, stat error: %v", statErr)
	}
	archives, listErr := archive.List(halDir)
	if listErr != nil {
		t.Fatalf("failed to list archives: %v", listErr)
	}
	if len(archives) != 0 {
		t.Fatalf("expected no archive side effects, got %d archives", len(archives))
	}
}

func TestConvertWithEngine_ArchiveRejectsAbsoluteExternalHalOutput(t *testing.T) {
	tmpDir := t.TempDir()
	chdirTo(t, tmpDir)
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	writePRDJSON(t, halDir, template.PRDFile, "hal/old")
	writeFile(t, filepath.Join(halDir, template.ProgressFile), "progress")
	mdPath := filepath.Join(halDir, "prd-new.md")
	writeFile(t, mdPath, "# PRD")

	externalDir := t.TempDir()
	outPath := filepath.Join(externalDir, template.HalDir, template.PRDFile)
	eng := &mockEngine{
		promptResponse: `{"project":"test","branchName":"hal/new","description":"desc","userStories":[]}`,
	}

	err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{Archive: true}, nil)
	if err == nil {
		t.Fatal("expected error for --archive with external absolute .hal/prd.json output path")
	}
	if !strings.Contains(err.Error(), "--archive is only supported when output is .hal/prd.json") {
		t.Fatalf("unexpected error: %v", err)
	}
	if eng.lastPrompt != "" {
		t.Fatalf("expected engine not to run when --archive guard fails, got prompt %q", eng.lastPrompt)
	}
}

func TestConvertWithEngine_ArchiveRejectsNestedHalOutput(t *testing.T) {
	tmpDir := t.TempDir()
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	writePRDJSON(t, halDir, template.PRDFile, "hal/old")
	writeFile(t, filepath.Join(halDir, template.ProgressFile), "progress")
	mdPath := filepath.Join(halDir, "prd-new.md")
	writeFile(t, mdPath, "# PRD")

	outPath := filepath.Join("nested", template.HalDir, template.PRDFile)
	eng := &mockEngine{
		promptResponse: `{"project":"test","branchName":"hal/new","description":"desc","userStories":[]}`,
	}

	err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{Archive: true}, nil)
	if err == nil {
		t.Fatal("expected error for --archive with nested .hal output path")
	}
	if !strings.Contains(err.Error(), "--archive is only supported when output is .hal/prd.json") {
		t.Fatalf("unexpected error: %v", err)
	}
	if eng.lastPrompt != "" {
		t.Fatalf("expected engine not to run when --archive guard fails, got prompt %q", eng.lastPrompt)
	}

	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected no output file to be written, stat error: %v", statErr)
	}
	archives, listErr := archive.List(halDir)
	if listErr != nil {
		t.Fatalf("failed to list archives: %v", listErr)
	}
	if len(archives) != 0 {
		t.Fatalf("expected no archive side effects, got %d archives", len(archives))
	}
}

func TestConvertWithEngine_CanonicalBranchMismatchWithoutFlagsFailsBeforeWrite(t *testing.T) {
	tmpDir := t.TempDir()
	chdirTo(t, tmpDir)
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(halDir, template.PRDFile)
	writePRDJSON(t, halDir, template.PRDFile, "hal/old-feature")

	mdPath := filepath.Join(halDir, "prd-new.md")
	writeFile(t, mdPath, `---
branchName: hal/new-feature
---

# PRD`)

	eng := &mockEngine{
		promptResponse: promptResponseWithBranch(t, "hal/new-feature"),
	}

	err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{}, nil)
	if err == nil {
		t.Fatal("expected branch mismatch error")
	}

	want := "branch changed from hal/old-feature to hal/new-feature; run 'hal convert --archive' or 'hal archive' first, or use --force"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := readPRDBranchName(t, outPath); got != "hal/old-feature" {
		t.Fatalf("expected canonical PRD to remain unchanged, got branch %q", got)
	}

	archives, listErr := archive.List(halDir)
	if listErr != nil {
		t.Fatalf("failed to list archives: %v", listErr)
	}
	if len(archives) != 0 {
		t.Fatalf("expected no archive side effects, got %d archives", len(archives))
	}
}

func TestConvertWithEngine_CanonicalBranchMismatchFallbackDirectWriteRollsBack(t *testing.T) {
	tmpDir := t.TempDir()
	chdirTo(t, tmpDir)
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(halDir, template.PRDFile)
	writePRDJSON(t, halDir, template.PRDFile, "hal/old-feature")

	mdPath := filepath.Join(halDir, "prd-new.md")
	writeFile(t, mdPath, `---
branchName: hal/new-feature
---

# PRD`)

	eng := &mockEngine{
		promptResponse: "not-json",
		promptHook: func() error {
			return os.WriteFile(outPath, []byte(promptResponseWithBranch(t, "hal/new-feature")), 0644)
		},
	}

	err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{}, nil)
	if err == nil {
		t.Fatal("expected branch mismatch error")
	}

	want := "branch changed from hal/old-feature to hal/new-feature; run 'hal convert --archive' or 'hal archive' first, or use --force"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := readPRDBranchName(t, outPath); got != "hal/old-feature" {
		t.Fatalf("expected canonical PRD rollback to old branch, got %q", got)
	}
}

func TestConvertWithEngine_CanonicalBranchMismatchParseableResponseDirectWriteRollsBack(t *testing.T) {
	tmpDir := t.TempDir()
	chdirTo(t, tmpDir)
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(halDir, template.PRDFile)
	writePRDJSON(t, halDir, template.PRDFile, "hal/old-feature")

	mdPath := filepath.Join(halDir, "prd-new.md")
	writeFile(t, mdPath, `---
branchName: hal/new-feature
---

# PRD`)

	newBranchPRD := promptResponseWithBranch(t, "hal/new-feature")
	eng := &mockEngine{
		promptResponse: newBranchPRD,
		promptHook: func() error {
			return os.WriteFile(outPath, []byte(newBranchPRD), 0644)
		},
	}

	err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{}, nil)
	if err == nil {
		t.Fatal("expected branch mismatch error")
	}

	want := "branch changed from hal/old-feature to hal/new-feature; run 'hal convert --archive' or 'hal archive' first, or use --force"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := readPRDBranchName(t, outPath); got != "hal/old-feature" {
		t.Fatalf("expected canonical PRD rollback to old branch, got %q", got)
	}
}

func TestConvertWithEngine_CanonicalBranchMismatchWithForceWritesWithoutArchive(t *testing.T) {
	tmpDir := t.TempDir()
	chdirTo(t, tmpDir)
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(halDir, template.PRDFile)
	writePRDJSON(t, halDir, template.PRDFile, "hal/old-feature")
	writeFile(t, filepath.Join(halDir, template.ProgressFile), "progress")

	mdPath := filepath.Join(halDir, "prd-new.md")
	writeFile(t, mdPath, "# PRD: New Feature")

	eng := &mockEngine{
		promptResponse: promptResponseWithBranch(t, "hal/new-feature"),
	}

	if err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{Force: true}, nil); err != nil {
		t.Fatalf("ConvertWithEngine failed: %v", err)
	}

	if got := readPRDBranchName(t, outPath); got != "hal/new-feature" {
		t.Fatalf("unexpected output branchName: %s", got)
	}

	archives, listErr := archive.List(halDir)
	if listErr != nil {
		t.Fatalf("failed to list archives: %v", listErr)
	}
	if len(archives) != 0 {
		t.Fatalf("expected no archives when --force is used, got %d", len(archives))
	}
}

func TestConvertWithEngine_CanonicalBranchMismatchWithArchiveArchivesThenWrites(t *testing.T) {
	tmpDir := t.TempDir()
	chdirTo(t, tmpDir)
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(halDir, template.PRDFile)
	writePRDJSON(t, halDir, template.PRDFile, "hal/old-feature")
	writeFile(t, filepath.Join(halDir, template.ProgressFile), "progress")

	mdPath := filepath.Join(halDir, "prd-new.md")
	writeFile(t, mdPath, "# PRD: New Feature")

	eng := &mockEngine{
		promptResponse: promptResponseWithBranch(t, "hal/new-feature"),
	}

	if err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{Archive: true}, nil); err != nil {
		t.Fatalf("ConvertWithEngine failed: %v", err)
	}

	if got := readPRDBranchName(t, outPath); got != "hal/new-feature" {
		t.Fatalf("unexpected output branchName: %s", got)
	}

	archives, err := archive.List(halDir)
	if err != nil {
		t.Fatalf("failed to list archives: %v", err)
	}
	if len(archives) != 1 {
		t.Fatalf("expected one archive entry, got %d", len(archives))
	}

	archivedPRDPath := filepath.Join(archives[0].Dir, template.PRDFile)
	if got := readPRDBranchName(t, archivedPRDPath); got != "hal/old-feature" {
		t.Fatalf("expected archived PRD to retain old branch, got %q", got)
	}
}

func TestConvertWithEngine_BranchGuardSkipsNonBlockingCases(t *testing.T) {
	tests := []struct {
		name           string
		outPathFn      func(tmpDir, halDir string) string
		existingBranch *string
		mdContent      string
		wantBranch     string
	}{
		{
			name: "non-canonical output bypasses mismatch guard",
			outPathFn: func(tmpDir, halDir string) string {
				return filepath.Join(tmpDir, "custom-prd.json")
			},
			existingBranch: strPtr("hal/old-feature"),
			mdContent:      "# PRD: New Feature",
			wantBranch:     "hal/new-feature",
		},
		{
			name: "matching branch proceeds on canonical output",
			outPathFn: func(tmpDir, halDir string) string {
				return filepath.Join(halDir, template.PRDFile)
			},
			existingBranch: strPtr("hal/same-feature"),
			mdContent:      "# PRD: Same Feature",
			wantBranch:     "hal/same-feature",
		},
		{
			name: "missing canonical output proceeds",
			outPathFn: func(tmpDir, halDir string) string {
				return filepath.Join(halDir, template.PRDFile)
			},
			existingBranch: nil,
			mdContent:      "# PRD: New Feature",
			wantBranch:     "hal/new-feature",
		},
		{
			name: "empty existing branch proceeds",
			outPathFn: func(tmpDir, halDir string) string {
				return filepath.Join(halDir, template.PRDFile)
			},
			existingBranch: strPtr(""),
			mdContent:      "# PRD: New Feature",
			wantBranch:     "hal/new-feature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			chdirTo(t, tmpDir)
			halDir := filepath.Join(tmpDir, template.HalDir)
			if err := os.MkdirAll(halDir, 0755); err != nil {
				t.Fatal(err)
			}

			if tt.existingBranch != nil {
				writePRDJSON(t, halDir, template.PRDFile, *tt.existingBranch)
			}

			mdPath := filepath.Join(halDir, "prd-new.md")
			writeFile(t, mdPath, tt.mdContent)

			outPath := tt.outPathFn(tmpDir, halDir)
			eng := &mockEngine{
				promptResponse: promptResponseWithBranch(t, "hal/ignored-by-branch-pinning"),
			}

			if err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{}, nil); err != nil {
				t.Fatalf("ConvertWithEngine failed: %v", err)
			}

			if got := readPRDBranchName(t, outPath); got != tt.wantBranch {
				t.Fatalf("output branchName = %q, want %q", got, tt.wantBranch)
			}
		})
	}
}

func strPtr(s string) *string {
	return &s
}

func TestFindNewestMarkdown(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, halDir string)
		wantBase string
		wantErr  string
	}{
		{
			name: "selects newest by modified time",
			setup: func(t *testing.T, halDir string) {
				t.Helper()
				newer := filepath.Join(halDir, "prd-newer.md")
				older := filepath.Join(halDir, "prd-older.md")
				writeFile(t, newer, "# newer")
				writeFile(t, older, "# older")

				base := time.Date(2026, time.February, 23, 0, 0, 0, 0, time.UTC)
				if err := os.Chtimes(older, base, base); err != nil {
					t.Fatalf("failed to set mtime for %s: %v", older, err)
				}
				if err := os.Chtimes(newer, base.Add(time.Hour), base.Add(time.Hour)); err != nil {
					t.Fatalf("failed to set mtime for %s: %v", newer, err)
				}
			},
			wantBase: "prd-newer.md",
		},
		{
			name: "uses lexicographic tie-break for equal modified times",
			setup: func(t *testing.T, halDir string) {
				t.Helper()
				alpha := filepath.Join(halDir, "prd-alpha.md")
				zeta := filepath.Join(halDir, "prd-zeta.md")
				writeFile(t, alpha, "# alpha")
				writeFile(t, zeta, "# zeta")

				tie := time.Date(2026, time.February, 23, 1, 0, 0, 0, time.UTC)
				if err := os.Chtimes(alpha, tie, tie); err != nil {
					t.Fatalf("failed to set mtime for %s: %v", alpha, err)
				}
				if err := os.Chtimes(zeta, tie, tie); err != nil {
					t.Fatalf("failed to set mtime for %s: %v", zeta, err)
				}
			},
			wantBase: "prd-alpha.md",
		},
		{
			name: "returns actionable error when no markdown sources exist",
			setup: func(t *testing.T, halDir string) {
				t.Helper()
				if err := os.MkdirAll(halDir, 0755); err != nil {
					t.Fatalf("failed to create hal dir: %v", err)
				}
			},
			wantErr: "run `hal plan` or pass an explicit markdown path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			halDir := filepath.Join(tmpDir, template.HalDir)
			if tt.setup != nil {
				tt.setup(t, halDir)
			}

			got, err := FindNewestMarkdown(halDir)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if filepath.Base(got) != tt.wantBase {
				t.Fatalf("selected %q, want %q", filepath.Base(got), tt.wantBase)
			}
		})
	}
}

func TestConvertWithEngine_UsingSourceMessage(t *testing.T) {
	tests := []struct {
		name               string
		setup              func(t *testing.T, tmpDir string) string
		mdPath             string
		wantSource         string
		wantPromptContains string
	}{
		{
			name: "auto-discovered source prints selected path",
			setup: func(t *testing.T, tmpDir string) string {
				t.Helper()
				halDir := filepath.Join(tmpDir, template.HalDir)
				writeFile(t, filepath.Join(halDir, "prd-auto.md"), "# AUTO SOURCE")
				return filepath.Join(tmpDir, "out-auto.json")
			},
			mdPath:             "",
			wantSource:         filepath.Join(template.HalDir, "prd-auto.md"),
			wantPromptContains: "# AUTO SOURCE",
		},
		{
			name: "explicit source prints provided path",
			setup: func(t *testing.T, tmpDir string) string {
				t.Helper()
				writeFile(t, filepath.Join(tmpDir, "docs", "prd-explicit.md"), "# EXPLICIT SOURCE")
				return filepath.Join(tmpDir, "out-explicit.json")
			},
			mdPath:             filepath.Join("docs", "prd-explicit.md"),
			wantSource:         filepath.Join("docs", "prd-explicit.md"),
			wantPromptContains: "# EXPLICIT SOURCE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			origDir, err := os.Getwd()
			if err != nil {
				t.Fatalf("failed to get working directory: %v", err)
			}
			if err := os.Chdir(tmpDir); err != nil {
				t.Fatalf("failed to chdir to temp dir: %v", err)
			}
			t.Cleanup(func() {
				_ = os.Chdir(origDir)
			})

			outPath := tt.setup(t, tmpDir)
			eng := &mockEngine{
				promptResponse: `{"project":"test","branchName":"hal/new","description":"desc","userStories":[]}`,
			}

			var output bytes.Buffer
			display := engine.NewDisplay(&output)

			if err := ConvertWithEngine(context.Background(), eng, tt.mdPath, outPath, ConvertOptions{}, display); err != nil {
				t.Fatalf("ConvertWithEngine failed: %v", err)
			}

			if !strings.Contains(output.String(), "Using source: "+tt.wantSource) {
				t.Fatalf("output %q does not contain source message for %q", output.String(), tt.wantSource)
			}
			if !strings.Contains(eng.lastPrompt, tt.wantPromptContains) {
				t.Fatalf("prompt did not include expected markdown content %q", tt.wantPromptContains)
			}
		})
	}
}

func TestConvertWithEngine_NoSourceMarkdownReturnsActionableError(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir to temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
	})

	eng := &mockEngine{
		promptResponse: `{"project":"test","branchName":"hal/new","description":"desc","userStories":[]}`,
	}

	err = ConvertWithEngine(context.Background(), eng, "", filepath.Join(tmpDir, "out.json"), ConvertOptions{}, nil)
	if err == nil {
		t.Fatal("expected error when no markdown source exists")
	}
	if !strings.Contains(err.Error(), "run `hal plan` or pass an explicit markdown path") {
		t.Fatalf("unexpected error: %v", err)
	}
	if eng.lastPrompt != "" {
		t.Fatalf("expected engine not to be called, got prompt %q", eng.lastPrompt)
	}
}
