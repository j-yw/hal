package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/template"
)

// writePRD writes a minimal prd.json with the given branch name into dir.
func writePRD(t *testing.T, dir, branchName string) {
	t.Helper()
	prd := engine.PRD{BranchName: branchName}
	data, err := json.Marshal(prd)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, template.PRDFile), data, 0644); err != nil {
		t.Fatal(err)
	}
}

// writeFile creates a file with the given content in dir.
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestRunArchiveCreate(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, halDir string)
		nameFlag   string
		stdinInput string
		wantErr    string
		wantOutput string
	}{
		{
			name: "name flag bypasses prompt",
			setup: func(t *testing.T, halDir string) {
				os.MkdirAll(filepath.Join(halDir, "archive"), 0755)
				writePRD(t, halDir, "hal/my-feature")
			},
			nameFlag:   "my-feature",
			stdinInput: "",
			wantOutput: "archived",
		},
		{
			name: "prd branchName derives default shown in prompt",
			setup: func(t *testing.T, halDir string) {
				os.MkdirAll(filepath.Join(halDir, "archive"), 0755)
				writePRD(t, halDir, "hal/cool-feature")
			},
			nameFlag:   "",
			stdinInput: "\n",
			wantOutput: "Archive name [cool-feature]:",
		},
		{
			name: "empty input uses derived default name",
			setup: func(t *testing.T, halDir string) {
				os.MkdirAll(filepath.Join(halDir, "archive"), 0755)
				writePRD(t, halDir, "hal/derived-name")
			},
			nameFlag:   "",
			stdinInput: "\n",
			wantOutput: "derived-name",
		},
		{
			name:       "error when halDir does not exist",
			setup:      func(t *testing.T, halDir string) {},
			nameFlag:   "test",
			stdinInput: "",
			wantErr:    ".hal/ not found",
		},
		{
			name: "error when no feature state files exist",
			setup: func(t *testing.T, halDir string) {
				os.MkdirAll(filepath.Join(halDir, "archive"), 0755)
				// No prd.json or auto-prd.json
			},
			nameFlag:   "test",
			stdinInput: "",
			wantErr:    "no feature state to archive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			halDir := filepath.Join(tmpDir, ".hal")

			if tt.setup != nil {
				// Only create halDir if setup will use it
				if tt.wantErr != ".hal/ not found" {
					os.MkdirAll(halDir, 0755)
				}
				tt.setup(t, halDir)
			}

			in := strings.NewReader(tt.stdinInput)
			var out bytes.Buffer

			err := runArchiveCreate(halDir, tt.nameFlag, in, &out)

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

			if tt.wantOutput != "" && !strings.Contains(out.String(), tt.wantOutput) {
				t.Errorf("output %q does not contain %q", out.String(), tt.wantOutput)
			}
		})
	}
}

func TestRunArchiveListFn(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T, halDir string)
		verbose     bool
		wantErr     string
		wantOutput  []string
		wantMissing []string
	}{
		{
			name: "default output contains NAME DATE PROGRESS headers",
			setup: func(t *testing.T, halDir string) {
				archDir := filepath.Join(halDir, "archive", "2026-01-15-test-feature")
				os.MkdirAll(archDir, 0755)
				writePRD(t, archDir, "hal/test-feature")
			},
			verbose:     false,
			wantOutput:  []string{"NAME", "DATE", "PROGRESS"},
			wantMissing: []string{"BRANCH", "PATH"},
		},
		{
			name: "verbose output contains all column headers",
			setup: func(t *testing.T, halDir string) {
				archDir := filepath.Join(halDir, "archive", "2026-01-15-test-feature")
				os.MkdirAll(archDir, 0755)
				writePRD(t, archDir, "hal/test-feature")
			},
			verbose:    true,
			wantOutput: []string{"NAME", "DATE", "PROGRESS", "BRANCH", "PATH"},
		},
		{
			name: "empty archive prints no archives found",
			setup: func(t *testing.T, halDir string) {
				os.MkdirAll(filepath.Join(halDir, "archive"), 0755)
			},
			verbose:    false,
			wantOutput: []string{"No archives found."},
		},
		{
			name:    "error when halDir does not exist",
			setup:   func(t *testing.T, halDir string) {},
			verbose: false,
			wantErr: ".hal/ not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			halDir := filepath.Join(tmpDir, ".hal")

			if tt.wantErr != ".hal/ not found" {
				os.MkdirAll(halDir, 0755)
			}
			if tt.setup != nil {
				tt.setup(t, halDir)
			}

			var out bytes.Buffer
			err := runArchiveListFn(halDir, tt.verbose, &out)

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

			output := out.String()
			for _, want := range tt.wantOutput {
				if !strings.Contains(output, want) {
					t.Errorf("output %q does not contain %q", output, want)
				}
			}
			for _, missing := range tt.wantMissing {
				if strings.Contains(output, missing) {
					t.Errorf("output %q should not contain %q", output, missing)
				}
			}
		})
	}
}
