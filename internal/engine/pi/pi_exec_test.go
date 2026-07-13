package pi

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

	eng := New(&engine.EngineConfig{Timeout: 10 * time.Second})
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

func TestExecute_AllowsRecoveredPiErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	tests := []struct {
		name   string
		events string
	}{
		{
			name: "assistant transport error",
			events: `printf '{"type":"message_end","message":{"role":"assistant","content":[],"stopReason":"error","errorMessage":"WebSocket connection failed: sk-live-test-secret"}}\n'
printf '{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"recovered"}],"stopReason":"stop"}}\n'
printf '{"type":"agent_end","messages":[{"role":"assistant","content":[],"stopReason":"error","errorMessage":"WebSocket connection failed: sk-live-test-secret"},{"role":"assistant","content":[{"type":"text","text":"recovered"}],"stopReason":"stop"}]}\n'`,
		},
		{
			name: "tool execution error",
			events: `printf '{"type":"tool_execution_end","toolCallId":"tool1","toolName":"bash","result":{"content":[{"type":"text","text":"command exited 1"}]},"isError":true}\n'
printf '{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"used a fallback"}],"stopReason":"stop"}}\n'
printf '{"type":"agent_end","messages":[{"role":"assistant","content":[{"type":"toolCall","id":"tool1","name":"bash"}],"stopReason":"toolUse"},{"role":"toolResult","content":[{"type":"text","text":"command exited 1"}],"isError":true},{"role":"assistant","content":[{"type":"text","text":"used a fallback"}],"stopReason":"stop"}]}\n'`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binDir := t.TempDir()
			writeFakePi(t, binDir, "#!/bin/sh\nprintf '{\"type\":\"session\"}\\n'\n"+tt.events+"exit 1\n")
			t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

			eng := New(&engine.EngineConfig{Timeout: 10 * time.Second})
			var buf bytes.Buffer
			result := eng.Execute(context.Background(), "test prompt", engine.NewDisplay(&buf))

			if result.Error != nil {
				t.Fatalf("Execute() error = %v, want nil", result.Error)
			}
			if !result.Success {
				t.Fatal("Execute() success = false after Pi recovered")
			}
			if strings.Contains(buf.String(), "sk-live-test-secret") {
				t.Fatalf("display output leaked credential: %q", buf.String())
			}
		})
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

	eng := New(&engine.EngineConfig{Timeout: 10 * time.Second})
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

	eng := New(&engine.EngineConfig{Timeout: 10 * time.Second})
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

func TestStreamPrompt_ReturnsSanitizedTerminalAssistantErrorOnZeroExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	secret := "sk-live-secret-value"
	binDir := t.TempDir()
	writeFakePi(t, binDir, `#!/bin/sh
printf '{"type":"session"}\n'
printf '{"type":"message_end","message":{"role":"assistant","content":[],"stopReason":"error","errorMessage":"No API key found: `+secret+`"}}\n'
printf '{"type":"agent_end","messages":[{"role":"assistant","content":[],"stopReason":"error","errorMessage":"No API key found: `+secret+`"}]}\n'
exit 0
`)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	eng := New(&engine.EngineConfig{Timeout: 10 * time.Second})
	resp, err := eng.StreamPrompt(context.Background(), "test prompt", nil)
	if err == nil {
		t.Fatal("StreamPrompt() error = nil, want terminal assistant error")
	}
	if engine.RequiresOutputFallback(err) {
		t.Fatalf("StreamPrompt() error = %v, terminal failures must not request output fallback", err)
	}
	if got := err.Error(); !strings.Contains(got, "pi authentication failed") || strings.Contains(got, secret) {
		t.Fatalf("StreamPrompt() error = %q, want sanitized authentication guidance", got)
	}
	if resp != "" {
		t.Fatalf("StreamPrompt() response = %q, want empty response", resp)
	}
}

func TestPrompt_SanitizesProviderError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	secret := "sk-live-secret-value"
	binDir := t.TempDir()
	writeFakePi(t, binDir, "#!/bin/sh\nprintf 'No API key found: "+secret+"' >&2\nexit 1\n")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	eng := New(&engine.EngineConfig{Timeout: 10 * time.Second})
	resp, err := eng.Prompt(context.Background(), "test prompt")
	if err == nil {
		t.Fatal("Prompt() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "pi authentication failed") || strings.Contains(got, secret) {
		t.Fatalf("Prompt() error = %q, want sanitized authentication guidance", got)
	}
	if resp != "" {
		t.Fatalf("Prompt() response = %q, want empty response", resp)
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
