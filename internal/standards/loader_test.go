package standards

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeStandard(t *testing.T, dir, relPath, content string) {
	t.Helper()
	full := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatalf("failed to create dir for %s: %v", relPath, err)
	}
	if err := os.WriteFile(full, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write %s: %v", relPath, err)
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, halDir string)
		wantEmpty  bool
		wantSubstr []string
		wantErr    string
	}{
		{
			name:      "no standards directory",
			setup:     func(t *testing.T, halDir string) {},
			wantEmpty: true,
		},
		{
			name: "empty standards directory",
			setup: func(t *testing.T, halDir string) {
				if err := os.MkdirAll(filepath.Join(halDir, "standards"), 0755); err != nil {
					t.Fatalf("failed to create standards dir: %v", err)
				}
			},
			wantEmpty: true,
		},
		{
			name: "single standard file",
			setup: func(t *testing.T, halDir string) {
				writeStandard(t, halDir, "standards/global/naming.md", "# Naming\n\nUse camelCase.")
			},
			wantSubstr: []string{
				"## Project Standards",
				"### global/naming",
				"Use camelCase",
			},
		},
		{
			name: "multiple standards sorted",
			setup: func(t *testing.T, halDir string) {
				writeStandard(t, halDir, "standards/testing/table-driven.md", "Use table-driven tests.")
				writeStandard(t, halDir, "standards/engine/adapter.md", "Engines self-register via init().")
				writeStandard(t, halDir, "standards/config/constants.md", "Use template constants.")
			},
			wantSubstr: []string{
				"### config/constants",
				"### engine/adapter",
				"### testing/table-driven",
			},
		},
		{
			name: "skips non-md files",
			setup: func(t *testing.T, halDir string) {
				writeStandard(t, halDir, "standards/index.yml", "engine:\n  adapter:\n    description: test")
				writeStandard(t, halDir, "standards/engine/adapter.md", "Adapter content.")
			},
			wantSubstr: []string{"### engine/adapter"},
		},
		{
			name: "skips empty md files",
			setup: func(t *testing.T, halDir string) {
				writeStandard(t, halDir, "standards/empty.md", "   \n\n  ")
				writeStandard(t, halDir, "standards/real.md", "Real content.")
			},
			wantSubstr: []string{"### real"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			halDir := filepath.Join(t.TempDir(), ".hal")
			if err := os.MkdirAll(halDir, 0755); err != nil {
				t.Fatalf("failed to create halDir: %v", err)
			}
			tt.setup(t, halDir)

			got, err := Load(halDir)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantEmpty {
				if got != "" {
					t.Errorf("expected empty string, got %q", got)
				}
				return
			}

			for _, substr := range tt.wantSubstr {
				if !strings.Contains(got, substr) {
					t.Errorf("output missing %q.\nGot:\n%s", substr, got)
				}
			}
		})
	}
}

func TestLoadSortOrder(t *testing.T) {
	halDir := filepath.Join(t.TempDir(), ".hal")
	writeStandard(t, halDir, "standards/z-last/thing.md", "Z content")
	writeStandard(t, halDir, "standards/a-first/thing.md", "A content")
	writeStandard(t, halDir, "standards/m-middle/thing.md", "M content")

	got, err := Load(halDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	aIdx := strings.Index(got, "a-first")
	mIdx := strings.Index(got, "m-middle")
	zIdx := strings.Index(got, "z-last")

	if aIdx > mIdx || mIdx > zIdx {
		t.Errorf("standards not sorted: a=%d m=%d z=%d", aIdx, mIdx, zIdx)
	}
}

func TestCount(t *testing.T) {
	halDir := filepath.Join(t.TempDir(), ".hal")

	// No directory
	count, err := Count(halDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}

	// With files
	writeStandard(t, halDir, "standards/a.md", "content")
	writeStandard(t, halDir, "standards/b/c.md", "content")
	writeStandard(t, halDir, "standards/index.yml", "not counted")

	count, err = Count(halDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2, got %d", count)
	}
}

func TestListIndex(t *testing.T) {
	halDir := filepath.Join(t.TempDir(), ".hal")

	// No index
	got, err := ListIndex(halDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}

	// With index
	indexContent := "engine:\n  adapter:\n    description: test\n"
	writeStandard(t, halDir, "standards/index.yml", indexContent)

	got, err = ListIndex(halDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != indexContent {
		t.Errorf("expected %q, got %q", indexContent, got)
	}
}
