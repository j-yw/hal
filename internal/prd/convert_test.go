package prd

import (
	"bytes"
	"context"
	"encoding/json"
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

	if err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{}, nil); err != nil {
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

	if err := ConvertWithEngine(context.Background(), eng, mdPath, outPath, ConvertOptions{}, nil); err != nil {
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

func TestConvertWithEngine_ArchiveRequiresCanonicalOutput(t *testing.T) {
	tmpDir := t.TempDir()
	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

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

	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected no output file to be written, stat error: %v", statErr)
	}
}

func TestFindLatestPRDMarkdown(t *testing.T) {
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

			got, err := findLatestPRDMarkdown(halDir)
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
