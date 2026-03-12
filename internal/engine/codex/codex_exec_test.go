package codex

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/engine"
)

func TestExecute_AllowsNonZeroAfterSuccessfulResult(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	binDir := t.TempDir()
	writeFakeCodex(t, binDir, `#!/bin/sh
printf '{"type":"thread.started"}\n'
printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'
exit 1
`)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	eng := New(&engine.EngineConfig{Timeout: 2 * time.Second})
	var buf bytes.Buffer
	display := engine.NewDisplay(&buf)

	result := eng.Execute(context.Background(), "test prompt", display)
	if result.Error != nil {
		t.Fatalf("Execute() error = %v, want nil", result.Error)
	}
	if !result.Success {
		t.Fatal("Execute() success = false, want true")
	}
}

func TestExecute_DoesNotRecoverFromStaleSuccessfulResult(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	binDir := t.TempDir()
	writeFakeCodex(t, binDir, `#!/bin/sh
printf '{"type":"thread.started"}\n'
printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'
printf '{"type":"event_msg","payload":{"type":"task_started"}}\n'
exit 1
`)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	eng := New(&engine.EngineConfig{Timeout: 2 * time.Second})
	var buf bytes.Buffer
	display := engine.NewDisplay(&buf)

	result := eng.Execute(context.Background(), "test prompt", display)
	if result.Error == nil {
		t.Fatal("Execute() error = nil, want failure after stale successful result")
	}
	if result.Success {
		t.Fatal("Execute() success = true, want false after stale successful result")
	}
}

func TestRecoverExecuteResult_PrefersSuccessfulTerminalResultOverTimeout(t *testing.T) {
	eng := New(nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()

	result, recovered := eng.recoverExecuteResult(
		ctx,
		100*time.Millisecond,
		`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`,
		25*time.Millisecond,
	)
	if !recovered {
		t.Fatal("recoverExecuteResult() recovered = false, want true")
	}
	if result.Error != nil {
		t.Fatalf("recoverExecuteResult() error = %v, want nil", result.Error)
	}
	if !result.Success {
		t.Fatal("recoverExecuteResult() success = false, want true")
	}
}

func TestExecute_PreservesCanceledContextError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	binDir := t.TempDir()
	writeFakeCodex(t, binDir, `#!/bin/sh
printf '{"type":"thread.started"}\n'
printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'
sleep 5
exit 1
`)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	eng := New(&engine.EngineConfig{Timeout: 10 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	var buf bytes.Buffer
	display := engine.NewDisplay(&buf)
	result := eng.Execute(ctx, "test prompt", display)

	if result.Error == nil {
		t.Fatal("Execute() expected cancellation error, got nil")
	}
	if !errors.Is(result.Error, context.Canceled) {
		t.Fatalf("Execute() error = %v, want context.Canceled", result.Error)
	}
	if result.Success {
		t.Fatal("Execute() success = true, want false when canceled")
	}
}

func TestStreamPrompt_AllowsNonZeroAfterSuccessfulResult(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	binDir := t.TempDir()
	writeFakeCodex(t, binDir, `#!/bin/sh
printf '{"type":"thread.started"}\n'
printf '{"type":"item.completed","item":{"type":"agent_message","text":"streamed response"}}\n'
printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'
exit 1
`)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	eng := New(&engine.EngineConfig{Timeout: 2 * time.Second})
	resp, err := eng.StreamPrompt(context.Background(), "test prompt", nil)
	if err != nil {
		t.Fatalf("StreamPrompt() error = %v, want nil", err)
	}
	if resp != "streamed response" {
		t.Fatalf("StreamPrompt() response = %q, want %q", resp, "streamed response")
	}
}

func TestStreamPrompt_RequiresOutputFallbackOnEmptySuccessfulStream(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	binDir := t.TempDir()
	writeFakeCodex(t, binDir, `#!/bin/sh
printf '{"type":"thread.started"}\n'
printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'
exit 1
`)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	eng := New(&engine.EngineConfig{Timeout: 2 * time.Second})
	resp, err := eng.StreamPrompt(context.Background(), "test prompt", nil)
	if err == nil {
		t.Fatal("StreamPrompt() error = nil, want output fallback error")
	}
	if !engine.RequiresOutputFallback(err) {
		t.Fatalf("StreamPrompt() error = %v, want output fallback error", err)
	}
	if resp != "" {
		t.Fatalf("StreamPrompt() response = %q, want empty response", resp)
	}
}

func TestRecoverPromptError_PrefersSuccessfulTerminalResultOverTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()

	resp, err, recovered := recoverPromptError(
		ctx,
		100*time.Millisecond,
		10*time.Minute,
		context.DeadlineExceeded,
		func() (bool, bool) { return true, true },
		"streamed response",
		"",
	)
	if !recovered {
		t.Fatal("recoverPromptError() recovered = false, want true")
	}
	if err != nil {
		t.Fatalf("recoverPromptError() error = %v, want nil", err)
	}
	if resp != "streamed response" {
		t.Fatalf("recoverPromptError() response = %q, want %q", resp, "streamed response")
	}
}

func TestRecoverPromptError_PrefersSuccessfulTerminalResultOverStall(t *testing.T) {
	resp, err, recovered := recoverPromptError(
		context.Background(),
		100*time.Millisecond,
		10*time.Minute,
		fmt.Errorf("%w: no output for %s", errStreamStalled, 10*time.Minute),
		func() (bool, bool) { return true, true },
		"streamed response",
		"",
	)
	if !recovered {
		t.Fatal("recoverPromptError() recovered = false, want true")
	}
	if err != nil {
		t.Fatalf("recoverPromptError() error = %v, want nil", err)
	}
	if resp != "streamed response" {
		t.Fatalf("recoverPromptError() response = %q, want %q", resp, "streamed response")
	}
}

func TestRecoverPromptError_RequiresOutputFallbackForEmptySuccessfulStream(t *testing.T) {
	resp, err, recovered := recoverPromptError(
		context.Background(),
		100*time.Millisecond,
		10*time.Minute,
		fmt.Errorf("exit status 1"),
		func() (bool, bool) { return true, true },
		"",
		"",
	)
	if !recovered {
		t.Fatal("recoverPromptError() recovered = false, want true")
	}
	if !engine.RequiresOutputFallback(err) {
		t.Fatalf("recoverPromptError() error = %v, want output fallback error", err)
	}
	if resp != "" {
		t.Fatalf("recoverPromptError() response = %q, want empty response", resp)
	}
}

func TestStreamPrompt_PreservesCanceledContextError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	binDir := t.TempDir()
	writeFakeCodex(t, binDir, `#!/bin/sh
printf '{"type":"thread.started"}\n'
printf '{"type":"item.completed","item":{"type":"agent_message","text":"streamed response"}}\n'
printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'
sleep 5
exit 1
`)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	eng := New(&engine.EngineConfig{Timeout: 10 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	resp, err := eng.StreamPrompt(ctx, "test prompt", nil)
	if err == nil {
		t.Fatal("StreamPrompt() expected cancellation error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("StreamPrompt() error = %v, want context.Canceled", err)
	}
	if resp != "" {
		t.Fatalf("StreamPrompt() response = %q, want empty when canceled", resp)
	}
}

func writeFakeCodex(t *testing.T, dir, script string) {
	t.Helper()

	path := filepath.Join(dir, "codex")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}
