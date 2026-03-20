package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestBuildCreateArgs_Basic(t *testing.T) {
	args := buildCreateArgs("my-sandbox", nil)
	want := []string{"create", "--snapshot", "hal", "--name", "my-sandbox"}
	if len(args) != len(want) {
		t.Fatalf("got %d args, want %d: %v", len(args), len(want), args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("args[%d] = %q, want %q", i, args[i], want[i])
		}
	}
}

func TestBuildCreateArgs_WithEnvVars(t *testing.T) {
	env := map[string]string{
		"GIT_TOKEN":    "ghp_abc",
		"API_KEY":      "sk-123",
		"TAILSCALE_KEY": "tskey-xxx",
	}
	args := buildCreateArgs("test-sb", env)

	// Verify base args
	if args[0] != "create" {
		t.Errorf("args[0] = %q, want %q", args[0], "create")
	}
	if args[1] != "--snapshot" || args[2] != "hal" {
		t.Errorf("expected --snapshot hal, got %v", args[1:3])
	}
	if args[3] != "--name" || args[4] != "test-sb" {
		t.Errorf("expected --name test-sb, got %v", args[3:5])
	}

	// Verify env flags — sorted alphabetically by key
	envArgs := args[5:]
	wantEnv := []string{
		"-e", "API_KEY=sk-123",
		"-e", "GIT_TOKEN=ghp_abc",
		"-e", "TAILSCALE_KEY=tskey-xxx",
	}
	if len(envArgs) != len(wantEnv) {
		t.Fatalf("env args: got %d, want %d: %v", len(envArgs), len(wantEnv), envArgs)
	}
	for i := range wantEnv {
		if envArgs[i] != wantEnv[i] {
			t.Errorf("envArgs[%d] = %q, want %q", i, envArgs[i], wantEnv[i])
		}
	}
}

func TestBuildCreateArgs_EmptyEnv(t *testing.T) {
	args := buildCreateArgs("sb", map[string]string{})
	want := []string{"create", "--snapshot", "hal", "--name", "sb"}
	if len(args) != len(want) {
		t.Fatalf("got %d args, want %d: %v", len(args), len(want), args)
	}
}

func TestDaytonaProvider_Create_Success(t *testing.T) {
	var capturedArgs []string

	dp := &DaytonaProvider{
		APIKey: "test-key",
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			capturedArgs = append([]string{name}, args...)
			// Use a real command that succeeds
			return exec.CommandContext(ctx, "echo", "sandbox created")
		},
	}

	var out bytes.Buffer
	env := map[string]string{
		"GIT_TOKEN": "ghp_abc",
		"API_KEY":   "sk-123",
	}
	result, err := dp.Create(context.Background(), "my-sandbox", env, &out)
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}

	// Verify result
	if result.Name != "my-sandbox" {
		t.Errorf("result.Name = %q, want %q", result.Name, "my-sandbox")
	}

	// Verify captured command args
	if capturedArgs[0] != "daytona" {
		t.Errorf("command = %q, want %q", capturedArgs[0], "daytona")
	}

	argsStr := strings.Join(capturedArgs[1:], " ")
	for _, want := range []string{"--snapshot", "hal", "--name", "my-sandbox", "-e", "API_KEY=sk-123", "GIT_TOKEN=ghp_abc"} {
		if !strings.Contains(argsStr, want) {
			t.Errorf("args %q missing expected %q", argsStr, want)
		}
	}

	// Verify output was streamed
	if !strings.Contains(out.String(), "sandbox created") {
		t.Errorf("output = %q, want to contain %q", out.String(), "sandbox created")
	}
}

func TestDaytonaProvider_Create_Failure(t *testing.T) {
	dp := &DaytonaProvider{
		APIKey: "test-key",
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			// Use a command that exits with non-zero
			return exec.CommandContext(ctx, "sh", "-c", "echo 'error: quota exceeded' >&2; exit 1")
		},
	}

	var out bytes.Buffer
	result, err := dp.Create(context.Background(), "my-sandbox", nil, &out)
	if err == nil {
		t.Fatal("Create() expected error, got nil")
	}
	if result != nil {
		t.Errorf("expected nil result on failure, got %+v", result)
	}

	// Verify error mentions exit code
	if !strings.Contains(err.Error(), "exit code") {
		t.Errorf("error %q should mention exit code", err.Error())
	}
	if !strings.Contains(err.Error(), "daytona create failed") {
		t.Errorf("error %q should mention 'daytona create failed'", err.Error())
	}
}

func TestDaytonaProvider_Create_AllEnvFlags(t *testing.T) {
	var capturedArgs []string

	dp := &DaytonaProvider{
		APIKey: "key",
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			capturedArgs = append([]string{name}, args...)
			return exec.CommandContext(ctx, "true")
		},
	}

	env := map[string]string{
		"VAR_A": "val-a",
		"VAR_B": "val-b",
		"VAR_C": "val-c",
	}

	var out bytes.Buffer
	_, err := dp.Create(context.Background(), "sb", env, &out)
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}

	// Count -e flags
	args := capturedArgs[1:] // skip "daytona"
	eCount := 0
	for i, arg := range args {
		if arg == "-e" {
			eCount++
			// Next arg should be K=V
			if i+1 >= len(args) {
				t.Errorf("-e flag at position %d has no value", i)
			}
		}
	}
	if eCount != 3 {
		t.Errorf("expected 3 -e flags, got %d in args: %v", eCount, args)
	}

	// Verify all env vars are present
	argsStr := strings.Join(args, " ")
	for k, v := range env {
		want := fmt.Sprintf("%s=%s", k, v)
		if !strings.Contains(argsStr, want) {
			t.Errorf("args missing env var %q", want)
		}
	}
}

func TestDaytonaProvider_Create_DefaultCmdContext(t *testing.T) {
	// Verify that a DaytonaProvider without cmdContext set uses exec.CommandContext
	dp := &DaytonaProvider{APIKey: "key"}
	cmd := dp.commandContext(context.Background(), "echo", "test")
	if cmd == nil {
		t.Fatal("commandContext returned nil")
	}
	if cmd.Path == "" {
		t.Error("commandContext returned cmd with empty Path")
	}
}
