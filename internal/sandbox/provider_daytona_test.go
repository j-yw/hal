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
	var capturedCmd *exec.Cmd

	dp := &DaytonaProvider{
		APIKey:    "test-key",
		ServerURL: "https://custom.daytona.local/api",
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			capturedArgs = append([]string{name}, args...)
			// Use a real command that succeeds
			capturedCmd = exec.CommandContext(ctx, "echo", "sandbox created")
			return capturedCmd
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
	if capturedCmd == nil {
		t.Fatal("expected command to be captured")
	}
	envStr := strings.Join(capturedCmd.Env, "\n")
	if !strings.Contains(envStr, "DAYTONA_API_KEY=test-key") {
		t.Errorf("command env missing DAYTONA_API_KEY: %q", envStr)
	}
	if !strings.Contains(envStr, "DAYTONA_SERVER_URL=https://custom.daytona.local/api") {
		t.Errorf("command env missing DAYTONA_SERVER_URL: %q", envStr)
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

func TestDaytonaProvider_Create_RequiresAPIKey(t *testing.T) {
	called := false
	dp := &DaytonaProvider{
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			called = true
			return exec.CommandContext(ctx, "true")
		},
	}

	var out bytes.Buffer
	result, err := dp.Create(context.Background(), "my-sandbox", nil, &out)
	if err == nil {
		t.Fatal("Create() expected error when API key is missing, got nil")
	}
	if result != nil {
		t.Errorf("expected nil result on missing API key, got %+v", result)
	}
	if !strings.Contains(err.Error(), "daytona API key is required") {
		t.Errorf("error %q should mention missing daytona API key", err.Error())
	}
	if called {
		t.Fatal("expected command not to run when API key is missing")
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

func TestDaytonaProvider_Stop_Success(t *testing.T) {
	var capturedArgs []string
	dp := &DaytonaProvider{
		APIKey: "test-key",
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			capturedArgs = append([]string{name}, args...)
			return exec.CommandContext(ctx, "echo", "stopped")
		},
	}

	var out bytes.Buffer
	err := dp.Stop(context.Background(), "my-sandbox", &out)
	if err != nil {
		t.Fatalf("Stop() unexpected error: %v", err)
	}

	// Verify command: daytona stop my-sandbox
	wantArgs := []string{"daytona", "stop", "my-sandbox"}
	if len(capturedArgs) != len(wantArgs) {
		t.Fatalf("got args %v, want %v", capturedArgs, wantArgs)
	}
	for i, want := range wantArgs {
		if capturedArgs[i] != want {
			t.Errorf("args[%d] = %q, want %q", i, capturedArgs[i], want)
		}
	}

	if !strings.Contains(out.String(), "stopped") {
		t.Errorf("output = %q, want to contain %q", out.String(), "stopped")
	}
}

func TestDaytonaProvider_Stop_Failure(t *testing.T) {
	dp := &DaytonaProvider{
		APIKey: "test-key",
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			return exec.CommandContext(ctx, "sh", "-c", "exit 1")
		},
	}

	var out bytes.Buffer
	err := dp.Stop(context.Background(), "my-sandbox", &out)
	if err == nil {
		t.Fatal("Stop() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "daytona stop failed") {
		t.Errorf("error %q should contain 'daytona stop failed'", err.Error())
	}
	if !strings.Contains(err.Error(), "exit code") {
		t.Errorf("error %q should mention exit code", err.Error())
	}
}

func TestDaytonaProvider_Delete_Success(t *testing.T) {
	var capturedArgs []string
	dp := &DaytonaProvider{
		APIKey: "test-key",
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			capturedArgs = append([]string{name}, args...)
			return exec.CommandContext(ctx, "echo", "deleted")
		},
	}

	var out bytes.Buffer
	err := dp.Delete(context.Background(), "my-sandbox", &out)
	if err != nil {
		t.Fatalf("Delete() unexpected error: %v", err)
	}

	// Verify command: daytona delete my-sandbox --yes
	wantArgs := []string{"daytona", "delete", "my-sandbox", "--yes"}
	if len(capturedArgs) != len(wantArgs) {
		t.Fatalf("got args %v, want %v", capturedArgs, wantArgs)
	}
	for i, want := range wantArgs {
		if capturedArgs[i] != want {
			t.Errorf("args[%d] = %q, want %q", i, capturedArgs[i], want)
		}
	}

	if !strings.Contains(out.String(), "deleted") {
		t.Errorf("output = %q, want to contain %q", out.String(), "deleted")
	}
}

func TestDaytonaProvider_Delete_Failure(t *testing.T) {
	dp := &DaytonaProvider{
		APIKey: "test-key",
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			return exec.CommandContext(ctx, "sh", "-c", "exit 2")
		},
	}

	var out bytes.Buffer
	err := dp.Delete(context.Background(), "my-sandbox", &out)
	if err == nil {
		t.Fatal("Delete() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "daytona delete failed") {
		t.Errorf("error %q should contain 'daytona delete failed'", err.Error())
	}
	if !strings.Contains(err.Error(), "exit code") {
		t.Errorf("error %q should mention exit code", err.Error())
	}
}

func TestDaytonaProvider_Status_Success(t *testing.T) {
	var capturedArgs []string
	dp := &DaytonaProvider{
		APIKey: "test-key",
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			capturedArgs = append([]string{name}, args...)
			return exec.CommandContext(ctx, "echo", "running")
		},
	}

	var out bytes.Buffer
	err := dp.Status(context.Background(), "my-sandbox", &out)
	if err != nil {
		t.Fatalf("Status() unexpected error: %v", err)
	}

	// Verify command: daytona info my-sandbox
	wantArgs := []string{"daytona", "info", "my-sandbox"}
	if len(capturedArgs) != len(wantArgs) {
		t.Fatalf("got args %v, want %v", capturedArgs, wantArgs)
	}
	for i, want := range wantArgs {
		if capturedArgs[i] != want {
			t.Errorf("args[%d] = %q, want %q", i, capturedArgs[i], want)
		}
	}

	if !strings.Contains(out.String(), "running") {
		t.Errorf("output = %q, want to contain %q", out.String(), "running")
	}
}

func TestDaytonaProvider_Status_Failure(t *testing.T) {
	dp := &DaytonaProvider{
		APIKey: "test-key",
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			return exec.CommandContext(ctx, "sh", "-c", "exit 1")
		},
	}

	var out bytes.Buffer
	err := dp.Status(context.Background(), "my-sandbox", &out)
	if err == nil {
		t.Fatal("Status() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "daytona info failed") {
		t.Errorf("error %q should contain 'daytona info failed'", err.Error())
	}
}

func TestDaytonaProvider_SSH(t *testing.T) {
	dp := &DaytonaProvider{APIKey: "key"}
	cmd, err := dp.SSH("my-sandbox")
	if err != nil {
		t.Fatalf("SSH() unexpected error: %v", err)
	}

	wantArgs := []string{"daytona", "ssh", "my-sandbox"}
	if len(cmd.Args) != len(wantArgs) {
		t.Fatalf("got args %v, want %v", cmd.Args, wantArgs)
	}
	for i, want := range wantArgs {
		if cmd.Args[i] != want {
			t.Errorf("Args[%d] = %q, want %q", i, cmd.Args[i], want)
		}
	}

	// Verify stdio is attached
	if cmd.Stdin == nil {
		t.Error("Stdin should be set (os.Stdin)")
	}
	if cmd.Stdout == nil {
		t.Error("Stdout should be set (os.Stdout)")
	}
	if cmd.Stderr == nil {
		t.Error("Stderr should be set (os.Stderr)")
	}
}

func TestDaytonaProvider_Exec(t *testing.T) {
	dp := &DaytonaProvider{APIKey: "key"}
	cmd, err := dp.Exec("my-sandbox", []string{"ls", "-la"})
	if err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}

	wantArgs := []string{"daytona", "ssh", "my-sandbox", "--", "ls", "-la"}
	if len(cmd.Args) != len(wantArgs) {
		t.Fatalf("got args %v, want %v", cmd.Args, wantArgs)
	}
	for i, want := range wantArgs {
		if cmd.Args[i] != want {
			t.Errorf("Args[%d] = %q, want %q", i, cmd.Args[i], want)
		}
	}

	// Verify stdio is attached
	if cmd.Stdin == nil {
		t.Error("Stdin should be set (os.Stdin)")
	}
	if cmd.Stdout == nil {
		t.Error("Stdout should be set (os.Stdout)")
	}
	if cmd.Stderr == nil {
		t.Error("Stderr should be set (os.Stderr)")
	}
}

func TestDaytonaProvider_Exec_EmptyArgs(t *testing.T) {
	dp := &DaytonaProvider{APIKey: "key"}
	cmd, err := dp.Exec("sb", []string{})
	if err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}

	// With empty args, should still have the -- separator
	wantArgs := []string{"daytona", "ssh", "sb", "--"}
	if len(cmd.Args) != len(wantArgs) {
		t.Fatalf("got args %v, want %v", cmd.Args, wantArgs)
	}
	for i, want := range wantArgs {
		if cmd.Args[i] != want {
			t.Errorf("Args[%d] = %q, want %q", i, cmd.Args[i], want)
		}
	}
}
