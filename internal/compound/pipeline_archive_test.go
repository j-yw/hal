package compound

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/archive"
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

	origStatus := workingTreeChangesInDirFn
	workingTreeChangesInDirFn = func(string) ([]string, error) {
		return nil, nil
	}
	t.Cleanup(func() {
		workingTreeChangesInDirFn = origStatus
	})

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
	wantArchivePath := filepath.ToSlash(filepath.Join(template.HalDir, "archive", archiveEntries[0].Name()))
	if got := pipeline.LastArchivePath(); got != wantArchivePath {
		t.Fatalf("LastArchivePath() = %q, want %q", got, wantArchivePath)
	}

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

func TestRunArchiveStep_RecordsCollisionResolvedArchivePath(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	archiveName := time.Now().Format("2006-01-02") + "-collision"
	writeCompoundFile(t, filepath.Join(halDir, template.PRDFile), `{"project":"archive","branchName":"hal/collision","userStories":[]}`)
	writeCompoundFile(t, filepath.Join(halDir, template.ProgressFile), "progress")
	if err := os.MkdirAll(filepath.Join(halDir, "archive", archiveName), 0o755); err != nil {
		t.Fatalf("create colliding archive directory: %v", err)
	}

	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(io.Discard), dir)
	origStatus := workingTreeChangesInDirFn
	workingTreeChangesInDirFn = func(string) ([]string, error) { return nil, nil }
	t.Cleanup(func() { workingTreeChangesInDirFn = origStatus })

	state := &PipelineState{
		Step:       StepArchive,
		BranchName: "hal/collision",
		StartedAt:  time.Now(),
	}
	if err := pipeline.runArchiveStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("runArchiveStep returned error: %v", err)
	}

	want := filepath.ToSlash(filepath.Join(template.HalDir, "archive", archiveName+"-2"))
	if got := pipeline.LastArchivePath(); got != want {
		t.Fatalf("LastArchivePath() = %q, want exact collision-resolved path %q", got, want)
	}
}

func TestRunArchiveStep_BlocksWhenWorkingTreeDirty(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()
	var out bytes.Buffer
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(&out), dir)
	state := &PipelineState{
		Step:       StepArchive,
		BranchName: "hal/archive-dirty",
		StartedAt:  time.Now(),
	}

	origStatus := workingTreeChangesInDirFn
	workingTreeChangesInDirFn = func(string) ([]string, error) {
		return []string{"dirty.txt"}, nil
	}
	t.Cleanup(func() {
		workingTreeChangesInDirFn = origStatus
	})

	origArchive := createArchiveWithOptions
	createArchiveWithOptions = func(halDir, name string, out io.Writer, opts archive.CreateOptions) (string, error) {
		t.Fatal("createArchiveWithOptions should not be called when working tree is dirty")
		return "", nil
	}
	t.Cleanup(func() {
		createArchiveWithOptions = origArchive
	})

	err := pipeline.runArchiveStep(context.Background(), state, RunOptions{})
	if err == nil {
		t.Fatal("expected dirty worktree to block archive step")
	}
	if !strings.Contains(err.Error(), "archive gate blocked") {
		t.Fatalf("error = %q, want archive gate blocked", err)
	}
	if !strings.Contains(err.Error(), "dirty.txt") {
		t.Fatalf("error = %q, want dirty path details", err)
	}
	if state.Step != StepArchive {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepArchive)
	}
}

func TestRunArchiveStep_CheckpointsFactoryStateAfterSkippedReviewAndReport(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	writeCompoundFile(t, filepath.Join(halDir, template.PRDFile), `{"project":"archive","branchName":"hal/archive-checkpoint","userStories":[]}`)
	writeCompoundFile(t, filepath.Join(halDir, template.ProgressFile), "factory progress")
	reportPath := filepath.Join(halDir, "reports", "review-latest.md")
	writeCompoundFile(t, reportPath, "# Review")

	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(io.Discard), dir)
	state := &PipelineState{
		Step:       StepReview,
		BaseBranch: "main",
		BranchName: "hal/archive-checkpoint",
		StartedAt:  time.Now(),
	}
	opts := RunOptions{
		SkipReview:         true,
		RuntimeStatePolicy: RuntimeStatePolicyCheckpointFactoryState,
	}
	if err := pipeline.runReviewStep(context.Background(), state, opts); err != nil {
		t.Fatalf("runReviewStep returned error: %v", err)
	}
	if state.Review == nil || state.Review.Status != "skipped" {
		t.Fatalf("review state = %#v, want skipped", state.Review)
	}

	origReport := runReportWithEngine
	runReportWithEngine = func(context.Context, engine.Engine, *engine.Display, string, ReviewOptions) (*ReviewResult, error) {
		return &ReviewResult{ReportPath: reportPath}, nil
	}
	t.Cleanup(func() {
		runReportWithEngine = origReport
	})
	state.Step = StepReport
	if err := pipeline.runReportStep(context.Background(), state, opts); err != nil {
		t.Fatalf("runReportStep returned error: %v", err)
	}
	if state.Step != StepArchive {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepArchive)
	}

	origStatus := workingTreeChangesInDirFn
	statusCalls := 0
	workingTreeChangesInDirFn = func(string) ([]string, error) {
		statusCalls++
		if statusCalls == 1 {
			return []string{
				filepath.ToSlash(filepath.Join(template.HalDir, template.PRDFile)),
				filepath.ToSlash(filepath.Join(template.HalDir, template.ProgressFile)),
			}, nil
		}
		return nil, nil
	}
	t.Cleanup(func() {
		workingTreeChangesInDirFn = origStatus
	})

	addCalled := false
	origAdd := gitAddAllInDirFn
	gitAddAllInDirFn = func(context.Context, string) error {
		addCalled = true
		return nil
	}
	t.Cleanup(func() {
		gitAddAllInDirFn = origAdd
	})
	commitCalled := false
	origCommit := gitCommitInDirFn
	gitCommitInDirFn = func(_ context.Context, gotDir, message string) error {
		commitCalled = true
		if gotDir != dir {
			t.Fatalf("commit dir = %q, want %q", gotDir, dir)
		}
		if message != "chore: checkpoint Hal factory runtime state" {
			t.Fatalf("commit message = %q", message)
		}
		return nil
	}
	t.Cleanup(func() {
		gitCommitInDirFn = origCommit
	})

	if err := pipeline.runArchiveStep(context.Background(), state, opts); err != nil {
		t.Fatalf("runArchiveStep returned error: %v", err)
	}
	if !addCalled || !commitCalled {
		t.Fatalf("checkpoint add/commit = %t/%t, want true/true", addCalled, commitCalled)
	}
	if statusCalls != 2 {
		t.Fatalf("working tree checks = %d, want checkpoint then archive gate", statusCalls)
	}
	if state.Step != StepDone {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepDone)
	}
}

func TestRunArchiveStep_CheckpointsSandboxAutoStateAfterSkippedReview(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	writeCompoundFile(t, filepath.Join(halDir, template.PRDFile), `{"project":"archive","branchName":"hal/archive-sandbox-auto","userStories":[]}`)
	writeCompoundFile(t, filepath.Join(halDir, template.ProgressFile), "sandbox auto progress")

	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(io.Discard), dir)
	state := &PipelineState{
		Step:       StepArchive,
		BaseBranch: "main",
		BranchName: "hal/archive-sandbox-auto",
		StartedAt:  time.Now(),
	}

	origStatus := workingTreeChangesInDirFn
	statusCalls := 0
	workingTreeChangesInDirFn = func(string) ([]string, error) {
		statusCalls++
		if statusCalls == 1 {
			return []string{
				filepath.ToSlash(filepath.Join(template.HalDir, template.PRDFile)),
				filepath.ToSlash(filepath.Join(template.HalDir, template.ProgressFile)),
			}, nil
		}
		return nil, nil
	}
	t.Cleanup(func() {
		workingTreeChangesInDirFn = origStatus
	})

	addCalled := false
	origAdd := gitAddAllInDirFn
	gitAddAllInDirFn = func(context.Context, string) error {
		addCalled = true
		return nil
	}
	t.Cleanup(func() {
		gitAddAllInDirFn = origAdd
	})
	commitCalled := false
	origCommit := gitCommitInDirFn
	gitCommitInDirFn = func(_ context.Context, gotDir, message string) error {
		commitCalled = true
		if gotDir != dir {
			t.Fatalf("commit dir = %q, want %q", gotDir, dir)
		}
		if message != "chore: checkpoint Hal runtime state" {
			t.Fatalf("commit message = %q, want sandbox auto checkpoint message", message)
		}
		return nil
	}
	t.Cleanup(func() {
		gitCommitInDirFn = origCommit
	})

	err := pipeline.runArchiveStep(context.Background(), state, RunOptions{RuntimeStatePolicy: RuntimeStatePolicyCheckpointHalState})
	if err != nil {
		t.Fatalf("runArchiveStep returned error: %v", err)
	}
	if !addCalled || !commitCalled {
		t.Fatalf("checkpoint add/commit = %t/%t, want true/true", addCalled, commitCalled)
	}
	if statusCalls != 2 {
		t.Fatalf("working tree checks = %d, want checkpoint then archive gate", statusCalls)
	}
	if state.Step != StepDone {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepDone)
	}
}

func TestSandboxAutoRuntimeCheckpointRejectsUnexpectedSourceAndConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(io.Discard), dir)

	origStatus := workingTreeChangesInDirFn
	workingTreeChangesInDirFn = func(string) ([]string, error) {
		return []string{
			filepath.ToSlash(filepath.Join(template.HalDir, template.PRDFile)),
			"src/game.ts",
			filepath.ToSlash(filepath.Join(template.HalDir, template.ConfigFile)),
		}, nil
	}
	t.Cleanup(func() {
		workingTreeChangesInDirFn = origStatus
	})
	origAdd := gitAddAllInDirFn
	gitAddAllInDirFn = func(context.Context, string) error {
		t.Fatal("unexpected files must not be staged")
		return nil
	}
	t.Cleanup(func() {
		gitAddAllInDirFn = origAdd
	})

	err := pipeline.checkpointRuntimeStateForFinalVerification(context.Background(), RunOptions{RuntimeStatePolicy: RuntimeStatePolicyCheckpointHalState})
	if err == nil {
		t.Fatal("checkpointRuntimeStateForFinalVerification error = nil, want unexpected dirty files")
	}
	for _, want := range []string{"unexpected dirty files", "src/game.ts", ".hal/config.yaml"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("checkpoint error = %q, want %q", err, want)
		}
	}
}

func TestRunArchiveStep_FactoryCheckpointRejectsUnexpectedSourceAndConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(io.Discard), dir)
	state := &PipelineState{
		Step:       StepArchive,
		BranchName: "hal/archive-unexpected",
		StartedAt:  time.Now(),
	}

	origStatus := workingTreeChangesInDirFn
	workingTreeChangesInDirFn = func(string) ([]string, error) {
		return []string{"src/game.ts", filepath.ToSlash(filepath.Join(template.HalDir, template.ConfigFile))}, nil
	}
	t.Cleanup(func() {
		workingTreeChangesInDirFn = origStatus
	})
	origAdd := gitAddAllInDirFn
	gitAddAllInDirFn = func(context.Context, string) error {
		t.Fatal("unexpected files must not be staged")
		return nil
	}
	t.Cleanup(func() {
		gitAddAllInDirFn = origAdd
	})
	origArchive := createArchiveWithOptions
	createArchiveWithOptions = func(string, string, io.Writer, archive.CreateOptions) (string, error) {
		t.Fatal("archive must not run with unexpected dirty files")
		return "", nil
	}
	t.Cleanup(func() {
		createArchiveWithOptions = origArchive
	})

	err := pipeline.runArchiveStep(context.Background(), state, RunOptions{RuntimeStatePolicy: RuntimeStatePolicyCheckpointFactoryState})
	if err == nil {
		t.Fatal("runArchiveStep error = nil, want unexpected dirty files")
	}
	for _, want := range []string{"archive gate blocked", "unexpected dirty files", "src/game.ts", ".hal/config.yaml"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("runArchiveStep error = %q, want %q", err, want)
		}
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
