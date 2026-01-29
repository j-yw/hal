package codex

import (
	"testing"

	"github.com/jywlabs/goralph/internal/engine"
)

func TestNew(t *testing.T) {
	e := New()
	if e == nil {
		t.Fatal("New() returned nil")
	}
	if e.Timeout != engine.DefaultTimeout {
		t.Errorf("expected Timeout=%v, got %v", engine.DefaultTimeout, e.Timeout)
	}
}

func TestName(t *testing.T) {
	e := New()
	if e.Name() != "codex" {
		t.Errorf("expected Name()=\"codex\", got %q", e.Name())
	}
}

func TestCLICommand(t *testing.T) {
	e := New()
	if e.CLICommand() != "codex" {
		t.Errorf("expected CLICommand()=\"codex\", got %q", e.CLICommand())
	}
}

func TestBuildArgs(t *testing.T) {
	e := New()
	prompt := "test prompt"
	args := e.BuildArgs(prompt)

	expected := []string{
		"exec",
		"--dangerously-bypass-approvals-and-sandbox",
		"--json",
		"test prompt",
	}

	if len(args) != len(expected) {
		t.Fatalf("expected %d args, got %d: %v", len(expected), len(args), args)
	}

	for i, arg := range args {
		if arg != expected[i] {
			t.Errorf("arg[%d]: expected %q, got %q", i, expected[i], arg)
		}
	}
}

func TestEngineRegistration(t *testing.T) {
	e, err := engine.New("codex")
	if err != nil {
		t.Fatalf("engine.New(\"codex\") failed: %v", err)
	}
	if e == nil {
		t.Fatal("engine.New(\"codex\") returned nil")
	}
	if e.Name() != "codex" {
		t.Errorf("expected Name()=\"codex\", got %q", e.Name())
	}
}

// Parser tests

func TestParser_ParseLine_Empty(t *testing.T) {
	p := NewParser()
	event := p.ParseLine([]byte(""))
	if event != nil {
		t.Errorf("expected nil for empty line, got %+v", event)
	}

	event = p.ParseLine([]byte("   "))
	if event != nil {
		t.Errorf("expected nil for whitespace line, got %+v", event)
	}
}

func TestParser_ParseLine_InvalidJSON(t *testing.T) {
	p := NewParser()
	event := p.ParseLine([]byte("not json"))
	if event != nil {
		t.Errorf("expected nil for invalid JSON, got %+v", event)
	}
}

func TestParser_ParseLine_ThreadStarted(t *testing.T) {
	p := NewParser()
	line := `{"type":"thread.started"}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventInit {
		t.Errorf("expected Type=EventInit, got %v", event.Type)
	}
	if event.Data.Model != "codex" {
		t.Errorf("expected Model=\"codex\", got %q", event.Data.Model)
	}
}

func TestParser_ParseLine_CommandExecution_InProgress(t *testing.T) {
	p := NewParser()
	line := `{"type":"item.started","item":{"type":"command_execution","command":"/usr/bin/bash -lc 'echo hello'","status":"in_progress"}}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventTool {
		t.Errorf("expected Type=EventTool, got %v", event.Type)
	}
	if event.Tool != "run" {
		t.Errorf("expected Tool=\"run\", got %q", event.Tool)
	}
	// Should have extracted command and added "..."
	if event.Detail != "echo hello..." {
		t.Errorf("expected Detail=\"echo hello...\", got %q", event.Detail)
	}
}

func TestParser_ParseLine_CommandExecution_Completed(t *testing.T) {
	p := NewParser()
	line := `{"type":"item.completed","item":{"type":"command_execution","command":"/usr/bin/bash -lc 'echo hello'","exit_code":0}}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventTool {
		t.Errorf("expected Type=EventTool, got %v", event.Type)
	}
	if event.Tool != "run" {
		t.Errorf("expected Tool=\"run\", got %q", event.Tool)
	}
	if event.Detail != "echo hello" {
		t.Errorf("expected Detail=\"echo hello\", got %q", event.Detail)
	}
}

func TestParser_ParseLine_CommandExecution_Failed(t *testing.T) {
	p := NewParser()
	line := `{"type":"item.completed","item":{"type":"command_execution","command":"false","exit_code":1}}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventError {
		t.Errorf("expected Type=EventError, got %v", event.Type)
	}
	if event.Data.Message != "command failed" {
		t.Errorf("expected Message=\"command failed\", got %q", event.Data.Message)
	}
}

func TestParser_ParseLine_AgentMessage(t *testing.T) {
	p := NewParser()
	line := `{"type":"item.completed","item":{"type":"agent_message","text":"Hello, world!"}}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventText {
		t.Errorf("expected Type=EventText, got %v", event.Type)
	}
	if event.Detail != "Hello, world!" {
		t.Errorf("expected Detail=\"Hello, world!\", got %q", event.Detail)
	}
}

func TestParser_ParseLine_Reasoning(t *testing.T) {
	p := NewParser()
	line := `{"type":"item.completed","item":{"type":"reasoning","text":"Thinking about this..."}}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventText {
		t.Errorf("expected Type=EventText, got %v", event.Type)
	}
	if event.Tool != "thinking" {
		t.Errorf("expected Tool=\"thinking\", got %q", event.Tool)
	}
	if event.Detail != "Thinking about this..." {
		t.Errorf("expected Detail=\"Thinking about this...\", got %q", event.Detail)
	}
}

func TestParser_ParseLine_TurnCompleted(t *testing.T) {
	p := NewParser()
	line := `{"type":"turn.completed","usage":{"input_tokens":100,"output_tokens":50,"cached_input_tokens":10}}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventResult {
		t.Errorf("expected Type=EventResult, got %v", event.Type)
	}
	if !event.Data.Success {
		t.Error("expected Success=true, got false")
	}
	if event.Data.Tokens != 160 {
		t.Errorf("expected Tokens=160, got %d", event.Data.Tokens)
	}
}

func TestParser_ParseLine_TurnCompleted_NoUsage(t *testing.T) {
	p := NewParser()
	line := `{"type":"turn.completed"}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventResult {
		t.Errorf("expected Type=EventResult, got %v", event.Type)
	}
	if !event.Data.Success {
		t.Error("expected Success=true, got false")
	}
	if event.Data.Tokens != 0 {
		t.Errorf("expected Tokens=0, got %d", event.Data.Tokens)
	}
}

func TestParser_ParseLine_UnknownEventType(t *testing.T) {
	p := NewParser()
	line := `{"type":"unknown.event"}`

	event := p.ParseLine([]byte(line))
	if event != nil {
		t.Errorf("expected nil for unknown event type, got %+v", event)
	}
}

func TestParser_ParseLine_UnknownItemType(t *testing.T) {
	p := NewParser()
	line := `{"type":"item.completed","item":{"type":"unknown"}}`

	event := p.ParseLine([]byte(line))
	if event != nil {
		t.Errorf("expected nil for unknown item type, got %+v", event)
	}
}

// Helper function tests

func TestExtractCommand(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/usr/bin/bash -lc 'echo hello'", "echo hello"},
		{"/bin/bash -lc 'ls -la'", "ls -la"},
		{"/usr/bin/bash -c 'git status'", "git status"},
		{"echo hello", "echo hello"}, // No wrapper
		{"/usr/bin/bash -lc ''", "/usr/bin/bash -lc ''"}, // Empty command - no extraction possible (start > end)
		{"/usr/bin/bash -lc 'single'", "single"},
	}

	for _, tc := range tests {
		result := extractCommand(tc.input)
		if result != tc.expected {
			t.Errorf("extractCommand(%q): expected %q, got %q", tc.input, tc.expected, result)
		}
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		max      int
		expected string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "he..."},
		{"hi", 5, "hi"},
		{"", 5, ""},
	}

	for _, tc := range tests {
		result := truncate(tc.input, tc.max)
		if result != tc.expected {
			t.Errorf("truncate(%q, %d): expected %q, got %q", tc.input, tc.max, tc.expected, result)
		}
	}
}

func TestTrimSpace(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "hello"},
		{"  hello  ", "hello"},
		{"\thello\n", "hello"},
		{" \t\r\n ", ""},
		{"", ""},
	}

	for _, tc := range tests {
		result := trimSpace([]byte(tc.input))
		if string(result) != tc.expected {
			t.Errorf("trimSpace(%q): expected %q, got %q", tc.input, tc.expected, string(result))
		}
	}
}
