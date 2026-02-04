package compound

import (
	"path/filepath"
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
