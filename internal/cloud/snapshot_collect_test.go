package cloud

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// mockCollectRunner is a test runner that returns preconfigured exec results.
type mockCollectRunner struct {
	// execFn handles Exec calls. If nil, returns an error.
	execFn func(ctx context.Context, sandboxID string, req *runner.ExecRequest) (*runner.ExecResult, error)
}

func (m *mockCollectRunner) CreateSandbox(_ context.Context, _ *runner.CreateSandboxRequest) (*runner.Sandbox, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockCollectRunner) Exec(ctx context.Context, sandboxID string, req *runner.ExecRequest) (*runner.ExecResult, error) {
	if m.execFn != nil {
		return m.execFn(ctx, sandboxID, req)
	}
	return nil, fmt.Errorf("no execFn configured")
}

func (m *mockCollectRunner) StreamLogs(_ context.Context, _ string) (io.ReadCloser, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockCollectRunner) DestroySandbox(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockCollectRunner) Health(_ context.Context) (*runner.HealthStatus, error) {
	return nil, fmt.Errorf("not implemented")
}

// sandboxFS maps absolute sandbox paths to their file contents.
type sandboxFS map[string]string

// newMockCollectRunner builds a mock runner backed by a virtual sandbox filesystem.
func newMockCollectRunner(fs sandboxFS) *mockCollectRunner {
	return &mockCollectRunner{
		execFn: func(_ context.Context, _ string, req *runner.ExecRequest) (*runner.ExecResult, error) {
			cmd := req.Command

			// Handle find command.
			if strings.HasPrefix(cmd, "find /workspace/.hal") {
				var lines []string
				for path := range fs {
					lines = append(lines, path)
				}
				if len(lines) == 0 {
					return &runner.ExecResult{ExitCode: 1, Stderr: "No such file or directory"}, nil
				}
				return &runner.ExecResult{
					ExitCode: 0,
					Stdout:   strings.Join(lines, "\n") + "\n",
				}, nil
			}

			// Handle base64 command.
			if strings.HasPrefix(cmd, "base64 ") {
				// Extract path from: base64 -w0 '/workspace/<relPath>'
				// The path is shell-quoted by ShellQuote.
				pathPart := strings.TrimPrefix(cmd, "base64 -w0 ")
				// Remove ShellQuote wrapping (single quotes).
				absPath := strings.Trim(pathPart, "'")
				// Handle escaped quotes inside ShellQuote output.
				absPath = strings.ReplaceAll(absPath, "'\\''", "'")

				content, ok := fs[absPath]
				if !ok {
					return &runner.ExecResult{
						ExitCode: 1,
						Stderr:   fmt.Sprintf("base64: %s: No such file or directory", absPath),
					}, nil
				}
				encoded := base64.StdEncoding.EncodeToString([]byte(content))
				return &runner.ExecResult{
					ExitCode: 0,
					Stdout:   encoded,
				}, nil
			}

			return &runner.ExecResult{ExitCode: 127, Stderr: "unknown command"}, nil
		},
	}
}

func TestCollectSandboxBundle_RunWorkflow(t *testing.T) {
	fs := sandboxFS{
		"/workspace/.hal/prd.json":                  `{"project":"test"}`,
		"/workspace/.hal/progress.txt":              "progress content",
		"/workspace/.hal/auto-prd.json":             `{"auto":true}`,
		"/workspace/.hal/auto-state.json":           `{"step":"done"}`,
		"/workspace/.hal/prompt.md":                 "# prompt",
		"/workspace/.hal/config.yaml":               "engine: claude",
		"/workspace/.hal/standards/coding.md":       "# standards",
		"/workspace/.hal/reports/review.md":         "# review report",
		"/workspace/.hal/skills/commit/commit.yaml": "name: commit",
		"/workspace/.hal/archive/old/prd.json":      `{"old":true}`,
	}

	r := newMockCollectRunner(fs)
	ctx := context.Background()

	records, err := CollectSandboxBundle(ctx, r, "sandbox-1", WorkflowKindRun)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// WorkflowKindRun produces state artifacts only — not reports.
	collected := make(map[string]bool)
	for _, rec := range records {
		collected[rec.Path] = true
	}

	// State files should be included.
	wantIncluded := []string{
		".hal/prd.json",
		".hal/progress.txt",
		".hal/auto-prd.json",
		".hal/auto-state.json",
		".hal/prompt.md",
		".hal/config.yaml",
		".hal/standards/coding.md",
	}
	for _, path := range wantIncluded {
		if !collected[path] {
			t.Errorf("expected %s to be collected for run workflow, but it was not", path)
		}
	}

	// Reports should NOT be included for run workflow.
	wantExcluded := []string{
		".hal/reports/review.md",
		".hal/skills/commit/commit.yaml",
		".hal/archive/old/prd.json",
	}
	for _, path := range wantExcluded {
		if collected[path] {
			t.Errorf("expected %s to be excluded for run workflow, but it was collected", path)
		}
	}
}

func TestCollectSandboxBundle_AutoWorkflow(t *testing.T) {
	fs := sandboxFS{
		"/workspace/.hal/prd.json":          `{"project":"test"}`,
		"/workspace/.hal/progress.txt":      "progress content",
		"/workspace/.hal/reports/review.md": "# review report",
		"/workspace/.hal/skills/commit.yaml": "name: commit",
	}

	r := newMockCollectRunner(fs)
	ctx := context.Background()

	records, err := CollectSandboxBundle(ctx, r, "sandbox-1", WorkflowKindAuto)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	collected := make(map[string]bool)
	for _, rec := range records {
		collected[rec.Path] = true
	}

	// Auto workflow produces state + reports.
	wantIncluded := []string{
		".hal/prd.json",
		".hal/progress.txt",
		".hal/reports/review.md",
	}
	for _, path := range wantIncluded {
		if !collected[path] {
			t.Errorf("expected %s to be collected for auto workflow, but it was not", path)
		}
	}

	// Skills should still be excluded.
	if collected[".hal/skills/commit.yaml"] {
		t.Errorf("expected .hal/skills/commit.yaml to be excluded for auto workflow")
	}
}

func TestCollectSandboxBundle_ReviewWorkflow(t *testing.T) {
	fs := sandboxFS{
		"/workspace/.hal/prd.json":           `{"project":"test"}`,
		"/workspace/.hal/reports/summary.md": "# summary",
	}

	r := newMockCollectRunner(fs)
	ctx := context.Background()

	records, err := CollectSandboxBundle(ctx, r, "sandbox-1", WorkflowKindReview)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	collected := make(map[string]bool)
	for _, rec := range records {
		collected[rec.Path] = true
	}

	// Review workflow includes state + reports (same as auto).
	if !collected[".hal/prd.json"] {
		t.Error("expected .hal/prd.json to be collected for review workflow")
	}
	if !collected[".hal/reports/summary.md"] {
		t.Error("expected .hal/reports/summary.md to be collected for review workflow")
	}
}

func TestCollectSandboxBundle_EmptyWorkspace(t *testing.T) {
	// Empty filesystem — find returns non-zero.
	r := newMockCollectRunner(sandboxFS{})
	ctx := context.Background()

	records, err := CollectSandboxBundle(ctx, r, "sandbox-1", WorkflowKindRun)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if records != nil {
		t.Errorf("expected nil records for empty workspace, got %d", len(records))
	}
}

func TestCollectSandboxBundle_NoMatchingFiles(t *testing.T) {
	// Files exist but none match artifact patterns.
	fs := sandboxFS{
		"/workspace/.hal/skills/commit/commit.yaml": "name: commit",
		"/workspace/.hal/archive/old/prd.json":      `{"old":true}`,
	}

	r := newMockCollectRunner(fs)
	ctx := context.Background()

	records, err := CollectSandboxBundle(ctx, r, "sandbox-1", WorkflowKindRun)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if records != nil {
		t.Errorf("expected nil records when no files match, got %d", len(records))
	}
}

func TestCollectSandboxBundle_ListError(t *testing.T) {
	r := &mockCollectRunner{
		execFn: func(_ context.Context, _ string, _ *runner.ExecRequest) (*runner.ExecResult, error) {
			return nil, fmt.Errorf("network timeout")
		},
	}
	ctx := context.Background()

	_, err := CollectSandboxBundle(ctx, r, "sandbox-1", WorkflowKindRun)
	if err == nil {
		t.Fatal("expected error for runner failure, got nil")
	}
	if !strings.Contains(err.Error(), "listing sandbox .hal files") {
		t.Errorf("error should mention listing: %v", err)
	}
	if !strings.Contains(err.Error(), "network timeout") {
		t.Errorf("error should include underlying cause: %v", err)
	}
}

func TestCollectSandboxBundle_WorkspaceRelativePaths(t *testing.T) {
	fs := sandboxFS{
		"/workspace/.hal/prd.json": `{"project":"test"}`,
	}

	r := newMockCollectRunner(fs)
	ctx := context.Background()

	records, err := CollectSandboxBundle(ctx, r, "sandbox-1", WorkflowKindRun)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Path != ".hal/prd.json" {
		t.Errorf("expected workspace-relative path .hal/prd.json, got %q", records[0].Path)
	}
	if string(records[0].Content) != `{"project":"test"}` {
		t.Errorf("unexpected content: %q", string(records[0].Content))
	}
}
