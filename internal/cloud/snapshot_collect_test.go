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

			// Handle base64 command (matches the base64Cmd variable).
			if strings.HasPrefix(cmd, "base64 ") {
				// Extract path from: base64 -w0 '/workspace/<relPath>'
				// The path is shell-quoted by ShellQuote.
				pathPart := strings.TrimPrefix(cmd, base64Cmd+" ")
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
		"/workspace/.hal/prd.json":           `{"project":"test"}`,
		"/workspace/.hal/progress.txt":       "progress content",
		"/workspace/.hal/reports/review.md":  "# review report",
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

func TestCollectSandboxBundle_MultilineTextContent(t *testing.T) {
	multiline := "line one\nline two\nline three\n\twith tabs\nand trailing newline\n"
	fs := sandboxFS{
		"/workspace/.hal/progress.txt": multiline,
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
	if string(records[0].Content) != multiline {
		t.Errorf("multiline content mismatch:\n  got:  %q\n  want: %q", string(records[0].Content), multiline)
	}
}

func TestCollectSandboxBundle_BinarySafeContent(t *testing.T) {
	// Binary content with null bytes, high bytes, and non-UTF8 sequences.
	binaryContent := string([]byte{0x00, 0x01, 0xFF, 0xFE, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})
	fs := sandboxFS{
		"/workspace/.hal/prd.json": binaryContent,
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
	if string(records[0].Content) != binaryContent {
		t.Errorf("binary content mismatch:\n  got:  %x\n  want: %x", records[0].Content, []byte(binaryContent))
	}
}

func TestCollectSandboxBundle_WrappedBase64Output(t *testing.T) {
	// Simulate a base64 implementation that wraps output at 76 chars
	// despite -w0 being requested. The stripBase64Whitespace function
	// should handle this gracefully.
	longContent := strings.Repeat("Hello, World! This is a longer string to produce wrapped base64 output. ", 5)

	// Custom runner that returns wrapped base64 output (76-char lines).
	r := &mockCollectRunner{
		execFn: func(_ context.Context, _ string, req *runner.ExecRequest) (*runner.ExecResult, error) {
			cmd := req.Command
			if strings.HasPrefix(cmd, "find ") {
				return &runner.ExecResult{
					ExitCode: 0,
					Stdout:   "/workspace/.hal/progress.txt\n",
				}, nil
			}
			if strings.HasPrefix(cmd, "base64 ") {
				raw := base64.StdEncoding.EncodeToString([]byte(longContent))
				// Insert newlines every 76 characters to simulate wrapped output.
				var wrapped strings.Builder
				for i := 0; i < len(raw); i += 76 {
					end := i + 76
					if end > len(raw) {
						end = len(raw)
					}
					wrapped.WriteString(raw[i:end])
					wrapped.WriteByte('\n')
				}
				return &runner.ExecResult{
					ExitCode: 0,
					Stdout:   wrapped.String(),
				}, nil
			}
			return &runner.ExecResult{ExitCode: 127, Stderr: "unknown command"}, nil
		},
	}

	ctx := context.Background()
	records, err := CollectSandboxBundle(ctx, r, "sandbox-1", WorkflowKindRun)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if string(records[0].Content) != longContent {
		t.Errorf("content mismatch with wrapped base64 output:\n  got len:  %d\n  want len: %d", len(records[0].Content), len(longContent))
	}
}

func TestCollectSandboxBundle_DecodeFailure(t *testing.T) {
	// Simulate a runner that returns invalid base64 output.
	r := &mockCollectRunner{
		execFn: func(_ context.Context, _ string, req *runner.ExecRequest) (*runner.ExecResult, error) {
			cmd := req.Command
			if strings.HasPrefix(cmd, "find ") {
				return &runner.ExecResult{
					ExitCode: 0,
					Stdout:   "/workspace/.hal/prd.json\n",
				}, nil
			}
			if strings.HasPrefix(cmd, "base64 ") {
				return &runner.ExecResult{
					ExitCode: 0,
					Stdout:   "!!!not-valid-base64!!!",
					Stderr:   "corruption detected",
				}, nil
			}
			return &runner.ExecResult{ExitCode: 127, Stderr: "unknown command"}, nil
		},
	}

	ctx := context.Background()
	_, err := CollectSandboxBundle(ctx, r, "sandbox-1", WorkflowKindRun)
	if err == nil {
		t.Fatal("expected error for invalid base64 output, got nil")
	}
	// Error must include the file path.
	if !strings.Contains(err.Error(), ".hal/prd.json") {
		t.Errorf("error should include file path: %v", err)
	}
	// Error must include stderr from the command.
	if !strings.Contains(err.Error(), "corruption detected") {
		t.Errorf("error should include stderr: %v", err)
	}
	// Error must indicate decode failure.
	if !strings.Contains(err.Error(), "base64 decode failed") {
		t.Errorf("error should indicate decode failure: %v", err)
	}
}

func TestStripBase64Whitespace(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no whitespace", "SGVsbG8=", "SGVsbG8="},
		{"trailing newline", "SGVsbG8=\n", "SGVsbG8="},
		{"wrapped lines", "SGVs\nbG8=\n", "SGVsbG8="},
		{"tabs and spaces", "SG Vs\tbG8=", "SGVsbG8="},
		{"carriage return", "SGVs\r\nbG8=\r\n", "SGVsbG8="},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripBase64Whitespace(tt.input)
			if got != tt.want {
				t.Errorf("stripBase64Whitespace(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
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
