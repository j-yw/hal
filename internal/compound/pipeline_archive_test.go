package compound

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/template"
)

func TestRunArchiveStep_ExcludesLatestReportFromArchive(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)

	latestReportRel := filepath.Join(template.HalDir, "reports", "review-latest.md")
	latestReportAbs := filepath.Join(dir, latestReportRel)
	olderReportAbs := filepath.Join(halDir, "reports", "review-older.md")

	writeCompoundFile(t, filepath.Join(halDir, template.PRDFile), `{"project":"archive","branchName":"hal/archive-report","userStories":[]}`)
	writeCompoundFile(t, filepath.Join(halDir, template.ProgressFile), "progress")
	writeCompoundFile(t, filepath.Join(halDir, template.AutoStateFile), `{"step":"archive"}`)
	writeCompoundFile(t, latestReportAbs, "# latest report")
	writeCompoundFile(t, olderReportAbs, "# older report")

	cfg := DefaultAutoConfig()
	var out bytes.Buffer
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(&out), dir)

	state := &PipelineState{
		Step:       StepArchive,
		BranchName: "hal/archive-report",
		ReportPath: latestReportRel,
		StartedAt:  time.Now(),
	}

	if err := pipeline.runArchiveStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("runArchiveStep returned error: %v", err)
	}

	if state.Step != StepDone {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepDone)
	}
	if pipeline.HasState() {
		t.Fatal("pipeline state should be cleared after archive step")
	}

	if _, err := os.Stat(latestReportAbs); err != nil {
		t.Fatalf("expected excluded report to remain at %s: %v", latestReportAbs, err)
	}
	if _, err := os.Stat(olderReportAbs); !os.IsNotExist(err) {
		t.Fatalf("expected non-excluded report to be archived, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(halDir, template.PRDFile)); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be archived, stat err=%v", template.PRDFile, err)
	}
	if _, err := os.Stat(filepath.Join(halDir, template.ProgressFile)); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be archived, stat err=%v", template.ProgressFile, err)
	}

	archiveEntries, err := os.ReadDir(filepath.Join(halDir, "archive"))
	if err != nil {
		t.Fatalf("read archive dir: %v", err)
	}
	if len(archiveEntries) != 1 {
		t.Fatalf("archive entry count = %d, want 1", len(archiveEntries))
	}
	archiveDir := filepath.Join(halDir, "archive", archiveEntries[0].Name())

	if _, err := os.Stat(filepath.Join(archiveDir, template.PRDFile)); err != nil {
		t.Fatalf("expected archived %s: %v", template.PRDFile, err)
	}
	if _, err := os.Stat(filepath.Join(archiveDir, template.ProgressFile)); err != nil {
		t.Fatalf("expected archived %s: %v", template.ProgressFile, err)
	}
	if _, err := os.Stat(filepath.Join(archiveDir, "reports", "review-older.md")); err != nil {
		t.Fatalf("expected archived non-excluded report: %v", err)
	}
	if _, err := os.Stat(filepath.Join(archiveDir, "reports", "review-latest.md")); !os.IsNotExist(err) {
		t.Fatalf("excluded report should not be archived, stat err=%v", err)
	}
}

func writeCompoundFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
