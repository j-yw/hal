package prd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/archive"
	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/template"
)

type mockEngine struct {
	promptResponse string
	promptError    error
}

func (m *mockEngine) Name() string {
	return "mock"
}

func (m *mockEngine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	return engine.Result{}
}

func (m *mockEngine) Prompt(ctx context.Context, prompt string) (string, error) {
	return m.promptResponse, m.promptError
}

func (m *mockEngine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
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

func TestConvertWithEngine_AutoArchivesExistingState(t *testing.T) {
	tmpDir := t.TempDir()
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

	if err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, nil); err != nil {
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

func TestConvertWithEngine_SkipsAutoArchiveWhenOnlyMarkdown(t *testing.T) {
	tmpDir := t.TempDir()
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	mdPath := filepath.Join(halDir, "prd-only.md")
	writeFile(t, mdPath, "# PRD")

	outPath := filepath.Join(halDir, template.PRDFile)
	eng := &mockEngine{
		promptResponse: `{"project":"test","branchName":"hal/new","description":"desc","userStories":[]}`,
	}

	if err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, nil); err != nil {
		t.Fatalf("ConvertWithEngine failed: %v", err)
	}

	if _, err := os.Stat(mdPath); err != nil {
		t.Fatalf("expected markdown PRD to remain, got error: %v", err)
	}

	archives, err := archive.List(halDir)
	if err != nil {
		t.Fatalf("failed to list archives: %v", err)
	}
	if len(archives) != 0 {
		t.Fatalf("expected no archives, got %d", len(archives))
	}
}
