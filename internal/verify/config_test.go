package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.Checks) != 0 {
		t.Fatalf("Checks length = %d, want 0", len(cfg.Checks))
	}
}

func TestLoadConfigMissingFileReturnsDefaults(t *testing.T) {
	cfg, err := LoadConfig(t.TempDir())
	if err != nil {
		t.Fatalf("LoadConfig() unexpected error: %v", err)
	}
	if len(cfg.Checks) != 0 {
		t.Fatalf("Checks length = %d, want 0", len(cfg.Checks))
	}
}

func TestLoadConfigShellChecks(t *testing.T) {
	dir := t.TempDir()
	writeVerifyConfig(t, dir, `verify:
  checks:
    - id: test
      name: Unit tests
      command: go test ./...
    - id: lint
      name: Lint
      command: make lint
      workDir: tools
      timeoutSeconds: 45
      required: false
    - id: vet
      name: Vet
      command: go vet ./...
      workDir: ""
`)

	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig() unexpected error: %v", err)
	}
	if len(cfg.Checks) != 3 {
		t.Fatalf("Checks length = %d, want 3", len(cfg.Checks))
	}

	first := cfg.Checks[0]
	if first.ID != "test" {
		t.Errorf("first.ID = %q, want test", first.ID)
	}
	if first.Name != "Unit tests" {
		t.Errorf("first.Name = %q, want Unit tests", first.Name)
	}
	if first.Command != "go test ./..." {
		t.Errorf("first.Command = %q, want go test ./...", first.Command)
	}
	if first.WorkDir != dir {
		t.Errorf("first.WorkDir = %q, want project root %q", first.WorkDir, dir)
	}
	if first.TimeoutSeconds != DefaultTimeoutSeconds {
		t.Errorf("first.TimeoutSeconds = %d, want %d", first.TimeoutSeconds, DefaultTimeoutSeconds)
	}
	if !first.Required {
		t.Error("first.Required = false, want true when omitted")
	}

	second := cfg.Checks[1]
	if second.ID != "lint" {
		t.Errorf("second.ID = %q, want lint", second.ID)
	}
	if second.WorkDir != filepath.Join(dir, "tools") {
		t.Errorf("second.WorkDir = %q, want %q", second.WorkDir, filepath.Join(dir, "tools"))
	}
	if second.TimeoutSeconds != 45 {
		t.Errorf("second.TimeoutSeconds = %d, want 45", second.TimeoutSeconds)
	}
	if second.Required {
		t.Error("second.Required = true, want false")
	}

	third := cfg.Checks[2]
	if third.WorkDir != dir {
		t.Errorf("third.WorkDir = %q, want project root %q", third.WorkDir, dir)
	}
	if !third.Required {
		t.Error("third.Required = false, want true when omitted")
	}
}

func TestLoadConfigPreservesAbsoluteWorkDir(t *testing.T) {
	dir := t.TempDir()
	absWorkDir := filepath.Join(t.TempDir(), "workspace")
	writeVerifyConfig(t, dir, `verify:
  checks:
    - id: abs
      name: Absolute workdir
      command: make test
      workDir: `+absWorkDir+`
`)

	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig() unexpected error: %v", err)
	}
	if got := cfg.Checks[0].WorkDir; got != absWorkDir {
		t.Fatalf("WorkDir = %q, want %q", got, absWorkDir)
	}
}

func TestLoadConfigValidationErrors(t *testing.T) {
	tests := []struct {
		name       string
		yaml       string
		wantErrSub string
	}{
		{
			name: "missing id",
			yaml: `verify:
  checks:
    - name: Unit tests
      command: go test ./...
`,
			wantErrSub: "verify.checks[0].id must not be empty",
		},
		{
			name: "missing name",
			yaml: `verify:
  checks:
    - id: test
      command: go test ./...
`,
			wantErrSub: "verify.checks[0].name must not be empty",
		},
		{
			name: "missing command",
			yaml: `verify:
  checks:
    - id: test
      name: Unit tests
`,
			wantErrSub: "verify.checks[0].command must not be empty",
		},
		{
			name: "zero timeout",
			yaml: `verify:
  checks:
    - id: test
      name: Unit tests
      command: go test ./...
      timeoutSeconds: 0
`,
			wantErrSub: "verify.checks[0].timeoutSeconds must be greater than 0",
		},
		{
			name: "negative timeout",
			yaml: `verify:
  checks:
    - id: test
      name: Unit tests
      command: go test ./...
      timeoutSeconds: -1
`,
			wantErrSub: "verify.checks[0].timeoutSeconds must be greater than 0",
		},
		{
			name:       "invalid yaml",
			yaml:       ":::not yaml",
			wantErrSub: "cannot unmarshal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeVerifyConfig(t, dir, tt.yaml)

			_, err := LoadConfig(dir)
			if err == nil {
				t.Fatal("LoadConfig() expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErrSub)
			}
		})
	}
}

func writeVerifyConfig(t *testing.T, dir, content string) {
	t.Helper()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(content), 0644); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}
}
