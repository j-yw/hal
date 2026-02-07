package claude

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/engine"
)

func TestExecute_PreservesCanceledContextError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	binDir := t.TempDir()
	writeFakeClaude(t, binDir, "#!/bin/sh\nprintf '{\"type\":\"result\",\"subtype\":\"success\",\"duration_ms\":1}\\n'\nsleep 5\nexit 1\n")
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

func TestPrompt_PreservesCanceledContextError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	binDir := t.TempDir()
	writeFakeClaude(t, binDir, "#!/bin/sh\nprintf 'partial response'\nsleep 5\nexit 1\n")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	eng := New(&engine.EngineConfig{Timeout: 10 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	resp, err := eng.Prompt(ctx, "test prompt")
	if err == nil {
		t.Fatal("Prompt() expected cancellation error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Prompt() error = %v, want context.Canceled", err)
	}
	if resp != "" {
		t.Fatalf("Prompt() response = %q, want empty when canceled", resp)
	}
}

func TestPrompt_AllowsNonZeroWithStdoutAndNoStderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	binDir := t.TempDir()
	writeFakeClaude(t, binDir, "#!/bin/sh\nprintf 'partial response'\nexit 1\n")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	eng := New(&engine.EngineConfig{Timeout: 2 * time.Second})
	resp, err := eng.Prompt(context.Background(), "test prompt")
	if err != nil {
		t.Fatalf("Prompt() error = %v, want nil", err)
	}
	if resp != "partial response" {
		t.Fatalf("Prompt() response = %q, want %q", resp, "partial response")
	}
}

func TestStreamPrompt_PreservesCanceledContextError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	binDir := t.TempDir()
	writeFakeClaude(t, binDir, "#!/bin/sh\nprintf '{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"partial\"}]}}\\n'\nprintf '{\"type\":\"result\",\"subtype\":\"success\",\"duration_ms\":1}\\n'\nsleep 5\nexit 1\n")
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

func writeFakeClaude(t *testing.T, dir, script string) {
	t.Helper()

	path := filepath.Join(dir, "claude")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}
