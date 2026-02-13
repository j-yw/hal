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

func TestStreamPrompt_DeduplicatesMultiTurnText(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	// Simulate Claude doing multi-turn: first an assistant event with draft text,
	// then a tool use (no text), then a final assistant event with the real response.
	// Only the last assistant event's text should be returned.
	script := "#!/bin/sh\n" +
		`echo '{"type":"system","subtype":"init","model":"claude-sonnet-4-20250514"}'` + "\n" +
		`echo '{"type":"assistant","message":{"content":[{"type":"text","text":"Draft PRD content here"},{"type":"tool_use","name":"Read","input":{"file_path":"go.mod"}}]}}'` + "\n" +
		`echo '{"type":"assistant","message":{"content":[{"type":"text","text":"Final PRD content here"}]}}'` + "\n" +
		`echo '{"type":"result","subtype":"success","duration_ms":5000}'` + "\n"

	binDir := t.TempDir()
	writeFakeClaude(t, binDir, script)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	eng := New(&engine.EngineConfig{Timeout: 5 * time.Second})
	resp, err := eng.StreamPrompt(context.Background(), "test prompt", nil)
	if err != nil {
		t.Fatalf("StreamPrompt() error = %v", err)
	}

	expected := "Final PRD content here"
	if resp != expected {
		t.Errorf("StreamPrompt() returned %q, want %q", resp, expected)
	}
}

func TestStreamPrompt_SingleAssistantEvent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	// Single assistant event should work as before.
	script := `#!/bin/sh
printf '{"type":"system","subtype":"init","model":"claude-sonnet-4-20250514"}\n'
printf '{"type":"assistant","message":{"content":[{"type":"text","text":"Hello, world!"}]}}\n'
printf '{"type":"result","subtype":"success","duration_ms":1000}\n'
`
	binDir := t.TempDir()
	writeFakeClaude(t, binDir, script)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	eng := New(&engine.EngineConfig{Timeout: 5 * time.Second})
	resp, err := eng.StreamPrompt(context.Background(), "test prompt", nil)
	if err != nil {
		t.Fatalf("StreamPrompt() error = %v", err)
	}

	if resp != "Hello, world!" {
		t.Errorf("StreamPrompt() returned %q, want %q", resp, "Hello, world!")
	}
}

func TestStreamPrompt_ToolOnlyTurnPreservesText(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}

	// If the last assistant event has only tool_use (no text), the previous
	// text should be preserved.
	script := `#!/bin/sh
printf '{"type":"system","subtype":"init","model":"claude-sonnet-4-20250514"}\n'
printf '{"type":"assistant","message":{"content":[{"type":"text","text":"Here is the response."}]}}\n'
printf '{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"echo done"}}]}}\n'
printf '{"type":"result","subtype":"success","duration_ms":1000}\n'
`
	binDir := t.TempDir()
	writeFakeClaude(t, binDir, script)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	eng := New(&engine.EngineConfig{Timeout: 5 * time.Second})
	resp, err := eng.StreamPrompt(context.Background(), "test prompt", nil)
	if err != nil {
		t.Fatalf("StreamPrompt() error = %v", err)
	}

	if resp != "Here is the response." {
		t.Errorf("StreamPrompt() returned %q, want %q", resp, "Here is the response.")
	}
}

func TestCollectAssistantTextFromStream_LastEventWins(t *testing.T) {
	// Multi-turn stream: only the last assistant event's text should be returned.
	stream := `{"type":"system","subtype":"init","model":"claude-sonnet-4-20250514"}
{"type":"assistant","message":{"content":[{"type":"text","text":"Draft version"}]}}
{"type":"assistant","message":{"content":[{"type":"text","text":"Final version"}]}}
{"type":"result","subtype":"success","duration_ms":1000}
`
	got := collectAssistantTextFromStream(stream)
	if got != "Final version" {
		t.Errorf("collectAssistantTextFromStream() = %q, want %q", got, "Final version")
	}
}

func TestCollectAssistantTextFromStream_SkipsToolOnlyEvents(t *testing.T) {
	stream := `{"type":"assistant","message":{"content":[{"type":"text","text":"The response"}]}}
{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Read","input":{}}]}}
{"type":"result","subtype":"success","duration_ms":1000}
`
	got := collectAssistantTextFromStream(stream)
	if got != "The response" {
		t.Errorf("collectAssistantTextFromStream() = %q, want %q", got, "The response")
	}
}

func writeFakeClaude(t *testing.T, dir, script string) {
	t.Helper()

	path := filepath.Join(dir, "claude")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}
