package compound

import (
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
