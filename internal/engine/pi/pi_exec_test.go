package pi

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

func TestExecute_AllowsNonZeroAfterSuccessfulResult(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	binDir := t.TempDir()
	writeFakePi(t, binDir, `#!/bin/sh
printf '{"type":"session"}\n'
printf '{"type":"agent_end","messages":[{"role":"assistant","content":[{"type":"text","text":"done"}]}]}\n'
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

func TestRecoverExecuteResult_PrefersSuccessfulTerminalResultOverTimeout(t *testing.T) {
	eng := New(nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()

	result, recovered := eng.recoverExecuteResult(
		ctx,
		100*time.Millisecond,
		`{"type":"agent_end","messages":[{"role":"assistant","content":[{"type":"text","text":"done"}]}]}`,
		25*time.Millisecond,
		42,
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
	if result.Tokens != 42 {
		t.Fatalf("recoverExecuteResult() tokens = %d, want 42", result.Tokens)
	}
}

func TestExecute_PreservesCanceledContextError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	binDir := t.TempDir()
	writeFakePi(t, binDir, `#!/bin/sh
printf '{"type":"session"}\n'
printf '{"type":"agent_end","messages":[{"role":"assistant","content":[{"type":"text","text":"done"}]}]}\n'
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

func TestPrompt_ReturnsErrorOnNonZeroWithStdoutAndNoStderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	binDir := t.TempDir()
	writeFakePi(t, binDir, "#!/bin/sh\nprintf 'partial response'\nexit 1\n")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	eng := New(&engine.EngineConfig{Timeout: 2 * time.Second})
	resp, err := eng.Prompt(context.Background(), "test prompt")
	if err == nil {
		t.Fatalf("Prompt() error = nil, want non-nil (resp=%q)", resp)
	}
	if resp != "" {
		t.Fatalf("Prompt() response = %q, want empty string", resp)
	}
}

func TestStreamPrompt_RequiresOutputFallbackOnEmptySuccessfulStream(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	binDir := t.TempDir()
	writeFakePi(t, binDir, `#!/bin/sh
printf '{"type":"session"}\n'
printf '{"type":"agent_end","messages":[]}\n'
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

func TestRecoverStreamPrompt_PrefersSuccessfulTerminalResultOverTimeout(t *testing.T) {
	eng := New(nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()

	resp, err, recovered := eng.recoverStreamPrompt(
		ctx,
		100*time.Millisecond,
		context.DeadlineExceeded,
		`{"type":"agent_end","messages":[{"role":"assistant","content":[{"type":"text","text":"done"}]}]}`,
		"done",
		"",
	)
	if !recovered {
		t.Fatal("recoverStreamPrompt() recovered = false, want true")
	}
	if err != nil {
		t.Fatalf("recoverStreamPrompt() error = %v, want nil", err)
	}
	if resp != "done" {
		t.Fatalf("recoverStreamPrompt() response = %q, want %q", resp, "done")
	}
}

func TestRecoverStreamPrompt_RequiresOutputFallbackForEmptySuccessfulStream(t *testing.T) {
	eng := New(nil)

	resp, err, recovered := eng.recoverStreamPrompt(
		context.Background(),
		100*time.Millisecond,
		errors.New("exit status 1"),
		`{"type":"agent_end","messages":[]}`,
		"",
		"",
	)
	if !recovered {
		t.Fatal("recoverStreamPrompt() recovered = false, want true")
	}
	if !engine.RequiresOutputFallback(err) {
		t.Fatalf("recoverStreamPrompt() error = %v, want output fallback error", err)
	}
	if resp != "" {
		t.Fatalf("recoverStreamPrompt() response = %q, want empty response", resp)
	}
}

func TestStreamPrompt_PreservesCanceledContextError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	binDir := t.TempDir()
	writeFakePi(t, binDir, `#!/bin/sh
printf '{"type":"session"}\n'
printf '{"type":"agent_end","messages":[{"role":"assistant","content":[{"type":"text","text":"done"}]}]}\n'
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

func writeFakePi(t *testing.T, dir, script string) {
	t.Helper()

	path := filepath.Join(dir, "pi")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}
