package compound

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultAutoConfig(t *testing.T) {
	cfg := DefaultAutoConfig()

	if cfg.ReportsDir != ".hal/reports" {
		t.Errorf("ReportsDir = %q, want %q", cfg.ReportsDir, ".hal/reports")
	}
	if cfg.BranchPrefix != "compound/" {
		t.Errorf("BranchPrefix = %q, want %q", cfg.BranchPrefix, "compound/")
	}
	if cfg.MaxIterations != 25 {
		t.Errorf("MaxIterations = %d, want %d", cfg.MaxIterations, 25)
	}
	if len(cfg.QualityChecks) != 0 {
		t.Errorf("QualityChecks length = %d, want 0", len(cfg.QualityChecks))
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	defaults := DefaultAutoConfig()

	t.Run("non-existent directory returns defaults", func(t *testing.T) {
		cfg, err := LoadConfig(filepath.Join(t.TempDir(), "does-not-exist"))
		if err != nil {
			t.Fatalf("LoadConfig() unexpected error: %v", err)
		}
		assertConfigMatchesDefaults(t, cfg, &defaults)
	})

	t.Run("directory exists but no config.yaml returns defaults", func(t *testing.T) {
		dir := t.TempDir()
		cfg, err := LoadConfig(dir)
		if err != nil {
			t.Fatalf("LoadConfig() unexpected error: %v", err)
		}
		assertConfigMatchesDefaults(t, cfg, &defaults)
	})
}

func assertConfigMatchesDefaults(t *testing.T, got, want *AutoConfig) {
	t.Helper()
	if got.ReportsDir != want.ReportsDir {
		t.Errorf("ReportsDir = %q, want %q", got.ReportsDir, want.ReportsDir)
	}
	if got.BranchPrefix != want.BranchPrefix {
		t.Errorf("BranchPrefix = %q, want %q", got.BranchPrefix, want.BranchPrefix)
	}
	if got.MaxIterations != want.MaxIterations {
		t.Errorf("MaxIterations = %d, want %d", got.MaxIterations, want.MaxIterations)
	}
	if len(got.QualityChecks) != len(want.QualityChecks) {
		t.Errorf("QualityChecks length = %d, want %d", len(got.QualityChecks), len(want.QualityChecks))
	}
}

func TestLoadConfig_ValidYAML(t *testing.T) {
	defaults := DefaultAutoConfig()

	tests := []struct {
		name         string
		yaml         string
		wantDir      string
		wantPrefix   string
		wantMaxIter  int
		wantQCCount  int
	}{
		{
			name: "full config overrides all defaults",
			yaml: `auto:
  reportsDir: "custom/reports"
  branchPrefix: "feature/"
  maxIterations: 10
  qualityChecks:
    - "make test"
    - "make lint"
`,
			wantDir:     "custom/reports",
			wantPrefix:  "feature/",
			wantMaxIter: 10,
			wantQCCount: 2,
		},
		{
			name: "partial config merges with defaults",
			yaml: `auto:
  reportsDir: "my/reports"
`,
			wantDir:     "my/reports",
			wantPrefix:  defaults.BranchPrefix,
			wantMaxIter: defaults.MaxIterations,
			wantQCCount: 0,
		},
		{
			name:         "empty auto section uses all defaults",
			yaml:         "auto:\n",
			wantDir:      defaults.ReportsDir,
			wantPrefix:   defaults.BranchPrefix,
			wantMaxIter:  defaults.MaxIterations,
			wantQCCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			halDir := filepath.Join(dir, ".hal")
			if err := os.MkdirAll(halDir, 0755); err != nil {
				t.Fatalf("Failed to create .hal dir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(tt.yaml), 0644); err != nil {
				t.Fatalf("Failed to write config.yaml: %v", err)
			}

			cfg, err := LoadConfig(dir)
			if err != nil {
				t.Fatalf("LoadConfig() unexpected error: %v", err)
			}

			if cfg.ReportsDir != tt.wantDir {
				t.Errorf("ReportsDir = %q, want %q", cfg.ReportsDir, tt.wantDir)
			}
			if cfg.BranchPrefix != tt.wantPrefix {
				t.Errorf("BranchPrefix = %q, want %q", cfg.BranchPrefix, tt.wantPrefix)
			}
			if cfg.MaxIterations != tt.wantMaxIter {
				t.Errorf("MaxIterations = %d, want %d", cfg.MaxIterations, tt.wantMaxIter)
			}
			if len(cfg.QualityChecks) != tt.wantQCCount {
				t.Errorf("QualityChecks length = %d, want %d", len(cfg.QualityChecks), tt.wantQCCount)
			}
		})
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	tests := []struct {
		name       string
		yaml       string
		wantErrSub string
	}{
		{
			name:       "invalid YAML syntax",
			yaml:       ":::not yaml",
			wantErrSub: "",
		},
		{
			name: "maxIterations negative triggers validation",
			yaml: `auto:
  maxIterations: -1
`,
			wantErrSub: "maxIterations",
		},
		{
			name: "explicit empty reportsDir triggers validation",
			yaml: `auto:
  reportsDir: ""
`,
			wantErrSub: "reportsDir",
		},
		{
			name: "explicit empty branchPrefix triggers validation",
			yaml: `auto:
  branchPrefix: ""
`,
			wantErrSub: "branchPrefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			halDir := filepath.Join(dir, ".hal")
			if err := os.MkdirAll(halDir, 0755); err != nil {
				t.Fatalf("Failed to create .hal dir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(tt.yaml), 0644); err != nil {
				t.Fatalf("Failed to write config.yaml: %v", err)
			}

			_, err := LoadConfig(dir)
			if err == nil {
				t.Fatal("LoadConfig() expected error, got nil")
			}
			if tt.wantErrSub != "" && !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErrSub)
			}
		})
	}
}
