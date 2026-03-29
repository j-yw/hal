package compound

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
)

func TestRun_DryRunFollowsSingleStepGraph_ReportDiscoveryEntry(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.md")
	if err := os.WriteFile(reportPath, []byte("# report\n"), 0644); err != nil {
		t.Fatalf("write report: %v", err)
	}

	var out bytes.Buffer
	display := engine.NewDisplay(&out)
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, display, dir)

	err := pipeline.Run(context.Background(), RunOptions{DryRun: true, ReportPath: reportPath})
	if err != nil {
		t.Fatalf("pipeline.Run dry-run failed: %v\noutput:\n%s", err, out.String())
	}

	gotSteps := extractPipelineStepSequence(out.String())
	wantSteps := []string{StepAnalyze, StepSpec, StepBranch, StepConvert, StepValidate, StepRun, StepReview, StepReport, StepCI, StepArchive}
	if !reflect.DeepEqual(gotSteps, wantSteps) {
		t.Fatalf("dry-run steps = %v, want %v\noutput:\n%s", gotSteps, wantSteps, out.String())
	}

	assertNoLegacyStepNames(t, gotSteps)
}

func TestRun_DryRunFollowsSingleStepGraph_MarkdownEntry(t *testing.T) {
	dir := t.TempDir()
	mdPath := filepath.Join(dir, "prd-single-graph.md")
	if err := os.WriteFile(mdPath, []byte("# PRD: Single Graph Guard\n"), 0644); err != nil {
		t.Fatalf("write markdown: %v", err)
	}

	var out bytes.Buffer
	display := engine.NewDisplay(&out)
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, display, dir)

	err := pipeline.Run(context.Background(), RunOptions{DryRun: true, SourceMarkdown: mdPath})
	if err != nil {
		t.Fatalf("pipeline.Run dry-run failed: %v\noutput:\n%s", err, out.String())
	}

	gotSteps := extractPipelineStepSequence(out.String())
	wantSteps := []string{StepBranch, StepConvert, StepValidate, StepRun, StepReview, StepReport, StepCI, StepArchive}
	if !reflect.DeepEqual(gotSteps, wantSteps) {
		t.Fatalf("dry-run steps = %v, want %v\noutput:\n%s", gotSteps, wantSteps, out.String())
	}

	assertNoLegacyStepNames(t, gotSteps)
}

func extractPipelineStepSequence(output string) []string {
	steps := make([]string, 0)
	for _, line := range strings.Split(output, "\n") {
		idx := strings.Index(line, "Step: ")
		if idx < 0 {
			continue
		}
		stepText := strings.TrimSpace(line[idx+len("Step: "):])
		if stepText == "" {
			continue
		}
		fields := strings.Fields(stepText)
		if len(fields) == 0 {
			continue
		}
		steps = append(steps, fields[0])
	}
	return steps
}

func assertNoLegacyStepNames(t *testing.T, steps []string) {
	t.Helper()

	legacy := map[string]struct{}{
		"prd":     {},
		"explode": {},
		"loop":    {},
		"pr":      {},
	}

	for _, step := range steps {
		if _, ok := legacy[step]; ok {
			t.Fatalf("unexpected legacy step name %q in runtime step sequence %v", step, steps)
		}
	}
}
