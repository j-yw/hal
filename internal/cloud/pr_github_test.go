package cloud

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// mockPRRunner is a minimal runner for PR creator tests that returns
// pre-configured results.
type mockPRRunner struct {
	execResult *runner.ExecResult
	execErr    error
	lastReq    *runner.ExecRequest
}

func (m *mockPRRunner) Exec(_ context.Context, _ string, req *runner.ExecRequest) (*runner.ExecResult, error) {
	m.lastReq = req
	return m.execResult, m.execErr
}

func (m *mockPRRunner) CreateSandbox(context.Context, *runner.CreateSandboxRequest) (*runner.Sandbox, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockPRRunner) StreamLogs(context.Context, string) (io.ReadCloser, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockPRRunner) DestroySandbox(context.Context, string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockPRRunner) Health(context.Context) (*runner.HealthStatus, error) {
	return nil, fmt.Errorf("not implemented")
}

func testPRRequest() *PRCreateRequest {
	return &PRCreateRequest{
		RunID:     "run-123",
		AttemptID: "att-456",
		Title:     "feat: add login page",
		Body:      "This PR adds a login page.",
		Head:      "hal/cloud/run-123",
		Base:      "main",
		Repo:      "org/repo",
	}
}

func TestGitHubPRCreator_Success(t *testing.T) {
	mock := &mockPRRunner{
		execResult: &runner.ExecResult{
			ExitCode: 0,
			Stdout:   "https://github.com/org/repo/pull/42\n",
		},
	}

	creator := GitHubPRCreator(mock, "sandbox-1", "/home/user/.auth")
	prRef, err := creator(context.Background(), testPRRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if prRef != "https://github.com/org/repo/pull/42" {
		t.Errorf("expected PR URL, got %q", prRef)
	}

	// Verify the command was executed in /workspace.
	if mock.lastReq.WorkDir != "/workspace" {
		t.Errorf("expected WorkDir /workspace, got %q", mock.lastReq.WorkDir)
	}
}

func TestGitHubPRCreator_ExecutesGHPRCreate(t *testing.T) {
	mock := &mockPRRunner{
		execResult: &runner.ExecResult{
			ExitCode: 0,
			Stdout:   "https://github.com/org/repo/pull/1\n",
		},
	}

	creator := GitHubPRCreator(mock, "sandbox-1", "/home/user/.auth")
	_, err := creator(context.Background(), testPRRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmd := mock.lastReq.Command
	if !strings.Contains(cmd, "gh pr create") {
		t.Errorf("expected command to contain 'gh pr create', got %q", cmd)
	}
}

func TestGitHubPRCreator_NonZeroExit(t *testing.T) {
	mock := &mockPRRunner{
		execResult: &runner.ExecResult{
			ExitCode: 1,
			Stderr:   "pull request already exists",
		},
	}

	creator := GitHubPRCreator(mock, "sandbox-1", "/home/user/.auth")
	_, err := creator(context.Background(), testPRRequest())
	if err == nil {
		t.Fatal("expected error for non-zero exit")
	}
	if !strings.Contains(err.Error(), "exit 1") {
		t.Errorf("error should contain exit code, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "pull request already exists") {
		t.Errorf("error should contain stderr, got %q", err.Error())
	}
}

func TestGitHubPRCreator_RunnerError(t *testing.T) {
	mock := &mockPRRunner{
		execErr: fmt.Errorf("connection refused"),
	}

	creator := GitHubPRCreator(mock, "sandbox-1", "/home/user/.auth")
	_, err := creator(context.Background(), testPRRequest())
	if err == nil {
		t.Fatal("expected error for runner failure")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error should contain underlying error, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "executing gh pr create") {
		t.Errorf("error should contain operation context, got %q", err.Error())
	}
}

func TestGitHubPRCreator_TokenSourcing(t *testing.T) {
	mock := &mockPRRunner{
		execResult: &runner.ExecResult{
			ExitCode: 0,
			Stdout:   "https://github.com/org/repo/pull/1\n",
		},
	}

	authDir := "/home/user/.auth"
	creator := GitHubPRCreator(mock, "sandbox-1", authDir)
	_, err := creator(context.Background(), testPRRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmd := mock.lastReq.Command
	expectedToken := fmt.Sprintf("export GITHUB_TOKEN=$(cat %s)", ShellQuote(authDir+"/credentials"))
	if !strings.Contains(cmd, expectedToken) {
		t.Errorf("expected token sourcing %q in command, got %q", expectedToken, cmd)
	}
}

func TestGitHubPRCreator_ShellEscaping(t *testing.T) {
	mock := &mockPRRunner{
		execResult: &runner.ExecResult{
			ExitCode: 0,
			Stdout:   "https://github.com/org/repo/pull/1\n",
		},
	}

	req := &PRCreateRequest{
		RunID:     "run-123",
		AttemptID: "att-456",
		Title:     "feat: it's a test",
		Body:      "Body with 'quotes'",
		Head:      "hal/cloud/run-123",
		Base:      "main",
		Repo:      "org/repo",
	}

	creator := GitHubPRCreator(mock, "sandbox-1", "/home/user/.auth")
	_, err := creator(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmd := mock.lastReq.Command
	if !strings.Contains(cmd, ShellQuote("feat: it's a test")) {
		t.Errorf("expected escaped title in command, got %q", cmd)
	}
	if !strings.Contains(cmd, ShellQuote("Body with 'quotes'")) {
		t.Errorf("expected escaped body in command, got %q", cmd)
	}
}

func TestGitHubPRCreator_QuoteHeavyArguments(t *testing.T) {
	mock := &mockPRRunner{
		execResult: &runner.ExecResult{
			ExitCode: 0,
			Stdout:   "https://github.com/org/repo/pull/1\n",
		},
	}

	// Use quote-heavy values in all five user-controlled arguments.
	req := &PRCreateRequest{
		RunID:     "run-999",
		AttemptID: "att-888",
		Title:     "fix: handle O'Brien's \"edge\" case",
		Body:      "This fixes the user's issue where `cmd='val'` broke.\nLine2: more 'quotes' here.",
		Head:      "hal/cloud/user's-branch",
		Base:      "main-'v2'",
		Repo:      "org/it's-a-repo",
	}

	creator := GitHubPRCreator(mock, "sandbox-1", "/home/user/.auth")
	_, err := creator(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmd := mock.lastReq.Command

	// Verify all five user-controlled arguments are shell-quoted.
	quoteChecks := []struct {
		label string
		value string
	}{
		{"title", req.Title},
		{"body", req.Body},
		{"head", req.Head},
		{"base", req.Base},
		{"repo", req.Repo},
	}
	for _, qc := range quoteChecks {
		quoted := ShellQuote(qc.value)
		if !strings.Contains(cmd, quoted) {
			t.Errorf("expected ShellQuote(%s) = %q in command, got %q", qc.label, quoted, cmd)
		}
	}
}

func TestGitHubPRCreator_TokenSourcingFromAuthDir(t *testing.T) {
	mock := &mockPRRunner{
		execResult: &runner.ExecResult{
			ExitCode: 0,
			Stdout:   "https://github.com/org/repo/pull/1\n",
		},
	}

	// Use an authDir with special characters to verify escaping.
	authDir := "/workspace/.auth/o'connor"
	creator := GitHubPRCreator(mock, "sandbox-1", authDir)
	_, err := creator(context.Background(), testPRRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmd := mock.lastReq.Command

	// Verify the command sources GITHUB_TOKEN from ${authDir}/credentials.
	expectedCredFile := authDir + "/credentials"
	expectedExport := fmt.Sprintf("export GITHUB_TOKEN=$(cat %s)", ShellQuote(expectedCredFile))
	if !strings.Contains(cmd, expectedExport) {
		t.Errorf("expected token sourcing %q in command, got %q", expectedExport, cmd)
	}

	// Verify the token export appears before gh pr create.
	exportIdx := strings.Index(cmd, "export GITHUB_TOKEN")
	ghIdx := strings.Index(cmd, "gh pr create")
	if exportIdx < 0 || ghIdx < 0 || exportIdx >= ghIdx {
		t.Errorf("expected token export before gh pr create in command %q", cmd)
	}
}

func TestGitHubPRCreator_EmptyBody(t *testing.T) {
	mock := &mockPRRunner{
		execResult: &runner.ExecResult{
			ExitCode: 0,
			Stdout:   "https://github.com/org/repo/pull/1\n",
		},
	}

	req := testPRRequest()
	req.Body = ""

	creator := GitHubPRCreator(mock, "sandbox-1", "/home/user/.auth")
	_, err := creator(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmd := mock.lastReq.Command
	if !strings.Contains(cmd, "--body ''") {
		t.Errorf("expected empty body flag, got %q", cmd)
	}
}

func TestParseGHPROutput(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		want   string
	}{
		{
			name:   "simple URL",
			stdout: "https://github.com/org/repo/pull/42\n",
			want:   "https://github.com/org/repo/pull/42",
		},
		{
			name:   "multi-line output with URL last",
			stdout: "Creating pull request...\nhttps://github.com/org/repo/pull/42\n",
			want:   "https://github.com/org/repo/pull/42",
		},
		{
			name:   "trailing whitespace",
			stdout: "https://github.com/org/repo/pull/42\n\n",
			want:   "https://github.com/org/repo/pull/42",
		},
		{
			name:   "empty output",
			stdout: "",
			want:   "",
		},
		{
			name:   "whitespace only",
			stdout: "  \n  \n",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseGHPROutput(tt.stdout)
			if got != tt.want {
				t.Errorf("parseGHPROutput(%q) = %q, want %q", tt.stdout, got, tt.want)
			}
		})
	}
}

func TestBuildGHPRCreateCommand(t *testing.T) {
	req := testPRRequest()
	cmd := buildGHPRCreateCommand(req, "/home/user/.auth")

	// Verify all expected parts are present.
	expectedParts := []string{
		"export GITHUB_TOKEN=$(cat",
		"gh pr create",
		"--title",
		"--head",
		"--base",
		"--repo",
		"--body",
	}
	for _, part := range expectedParts {
		if !strings.Contains(cmd, part) {
			t.Errorf("expected command to contain %q, got %q", part, cmd)
		}
	}

	// Verify arguments are shell-quoted.
	if !strings.Contains(cmd, ShellQuote(req.Title)) {
		t.Errorf("expected shell-quoted title in command")
	}
	if !strings.Contains(cmd, ShellQuote(req.Head)) {
		t.Errorf("expected shell-quoted head in command")
	}
	if !strings.Contains(cmd, ShellQuote(req.Base)) {
		t.Errorf("expected shell-quoted base in command")
	}
	if !strings.Contains(cmd, ShellQuote(req.Repo)) {
		t.Errorf("expected shell-quoted repo in command")
	}
}
