package pi

import (
	"testing"

	"github.com/jywlabs/hal/internal/engine"
)

func TestNew(t *testing.T) {
	e := New(nil)
	if e == nil {
		t.Fatal("New(nil) returned nil")
	}
	if e.Timeout != engine.DefaultTimeout {
		t.Errorf("expected Timeout=%v, got %v", engine.DefaultTimeout, e.Timeout)
	}
	if e.model != "" {
		t.Errorf("expected empty model, got %q", e.model)
	}
	if e.provider != "" {
		t.Errorf("expected empty provider, got %q", e.provider)
	}
}

func TestNewWithConfig(t *testing.T) {
	cfg := &engine.EngineConfig{
		Model:    "gemini-2.5-pro",
		Provider: "google",
	}
	e := New(cfg)
	if e.model != "gemini-2.5-pro" {
		t.Errorf("expected model=%q, got %q", "gemini-2.5-pro", e.model)
	}
	if e.provider != "google" {
		t.Errorf("expected provider=%q, got %q", "google", e.provider)
	}
}

func TestName(t *testing.T) {
	e := New(nil)
	if e.Name() != "pi" {
		t.Errorf("expected Name()=\"pi\", got %q", e.Name())
	}
}

func TestCLICommand(t *testing.T) {
	e := New(nil)
	if e.CLICommand() != "pi" {
		t.Errorf("expected CLICommand()=\"pi\", got %q", e.CLICommand())
	}
}

func TestBuildArgs_Defaults(t *testing.T) {
	e := New(nil)
	args := e.BuildArgs()

	// Prompt is now piped via stdin, not included in args
	expected := []string{"-p", "--no-session", "--mode", "json"}
	if len(args) != len(expected) {
		t.Fatalf("expected %d args, got %d: %v", len(expected), len(args), args)
	}
	for i, arg := range args {
		if arg != expected[i] {
			t.Errorf("arg[%d]: expected %q, got %q", i, expected[i], arg)
		}
	}
}

func TestBuildArgs_WithConfig(t *testing.T) {
	e := New(&engine.EngineConfig{
		Provider: "google",
		Model:    "gemini-2.5-pro",
	})
	args := e.BuildArgs()

	expected := []string{"-p", "--no-session", "--mode", "json", "--provider", "google", "--model", "gemini-2.5-pro"}
	if len(args) != len(expected) {
		t.Fatalf("expected %d args, got %d: %v", len(expected), len(args), args)
	}
	for i, arg := range args {
		if arg != expected[i] {
			t.Errorf("arg[%d]: expected %q, got %q", i, expected[i], arg)
		}
	}
}

func TestBuildArgsSimple_Defaults(t *testing.T) {
	e := New(nil)
	args := e.BuildArgsSimple()

	expected := []string{"-p", "--no-session"}
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
	e, err := engine.New("pi")
	if err != nil {
		t.Fatalf("engine.New(\"pi\") failed: %v", err)
	}
	if e == nil {
		t.Fatal("engine.New(\"pi\") returned nil")
	}
	if e.Name() != "pi" {
		t.Errorf("expected Name()=\"pi\", got %q", e.Name())
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

func TestParser_ParseLine_Session(t *testing.T) {
	p := NewParser()
	line := `{"type":"session","version":3,"id":"abc-123","timestamp":"2026-02-06T01:59:55.262Z","cwd":"/home/user/project"}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventInit {
		t.Errorf("expected Type=EventInit, got %v", event.Type)
	}
	if event.Data.Model != "" {
		t.Errorf("expected Model=\"\", got %q", event.Data.Model)
	}
}

func TestParser_ParseLine_MessageStart_ExtractsModel(t *testing.T) {
	p := NewParser()
	line := `{"type":"message_start","message":{"role":"assistant","content":[],"model":"claude-opus-4-6","usage":{"input":100,"output":0}}}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventInit {
		t.Errorf("expected Type=EventInit, got %v", event.Type)
	}
	if event.Data.Model != "claude-opus-4-6" {
		t.Errorf("expected Model=\"claude-opus-4-6\", got %q", event.Data.Model)
	}
}

func TestParser_ParseLine_MessageStart_OnlyFirstModel(t *testing.T) {
	p := NewParser()

	// First assistant message sets model
	line1 := `{"type":"message_start","message":{"role":"assistant","content":[],"model":"claude-opus-4-6"}}`
	event1 := p.ParseLine([]byte(line1))
	if event1 == nil || event1.Data.Model != "claude-opus-4-6" {
		t.Fatal("first message should extract model")
	}

	// Second assistant message should not re-emit init
	line2 := `{"type":"message_start","message":{"role":"assistant","content":[],"model":"claude-opus-4-6"}}`
	event2 := p.ParseLine([]byte(line2))
	if event2 != nil {
		t.Errorf("expected nil for subsequent assistant message_start, got %+v", event2)
	}
}

func TestParser_ParseLine_MessageStart_UserIgnored(t *testing.T) {
	p := NewParser()
	line := `{"type":"message_start","message":{"role":"user","content":[{"type":"text","text":"hello"}]}}`

	event := p.ParseLine([]byte(line))
	if event != nil {
		t.Errorf("expected nil for user message_start, got %+v", event)
	}
}

func TestParser_ParseLine_ToolCallEnd_Bash(t *testing.T) {
	p := NewParser()
	line := `{"type":"message_update","assistantMessageEvent":{"type":"toolcall_end","contentIndex":0,"toolCall":{"type":"toolCall","id":"tool1","name":"bash","arguments":{"command":"echo hello world"}}}}`

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
	if event.Detail != "echo hello world" {
		t.Errorf("expected Detail=\"echo hello world\", got %q", event.Detail)
	}
}

func TestParser_ParseLine_ToolCallEnd_Read(t *testing.T) {
	p := NewParser()
	line := `{"type":"message_update","assistantMessageEvent":{"type":"toolcall_end","contentIndex":0,"toolCall":{"type":"toolCall","id":"tool1","name":"read","arguments":{"path":"internal/engine/pi/pi.go"}}}}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventTool {
		t.Errorf("expected Type=EventTool, got %v", event.Type)
	}
	if event.Tool != "read" {
		t.Errorf("expected Tool=\"read\", got %q", event.Tool)
	}
	if event.Detail != ".../pi/pi.go" {
		t.Errorf("expected Detail=\".../pi/pi.go\", got %q", event.Detail)
	}
}

func TestParser_ParseLine_ToolCallEnd_Write(t *testing.T) {
	p := NewParser()
	line := `{"type":"message_update","assistantMessageEvent":{"type":"toolcall_end","contentIndex":0,"toolCall":{"type":"toolCall","id":"tool1","name":"write","arguments":{"path":"output.json"}}}}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Tool != "write" {
		t.Errorf("expected Tool=\"write\", got %q", event.Tool)
	}
	if event.Detail != "output.json" {
		t.Errorf("expected Detail=\"output.json\", got %q", event.Detail)
	}
}

func TestParser_ParseLine_ToolCallEnd_Edit(t *testing.T) {
	p := NewParser()
	line := `{"type":"message_update","assistantMessageEvent":{"type":"toolcall_end","contentIndex":0,"toolCall":{"type":"toolCall","id":"tool1","name":"edit","arguments":{"path":"src/main.go"}}}}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Tool != "edit" {
		t.Errorf("expected Tool=\"edit\", got %q", event.Tool)
	}
	if event.Detail != "src/main.go" {
		t.Errorf("expected Detail=\"src/main.go\", got %q", event.Detail)
	}
}

func TestParser_ParseLine_TextEnd_CollectsText(t *testing.T) {
	p := NewParser()
	line := `{"type":"message_update","assistantMessageEvent":{"type":"text_end","contentIndex":0,"content":"Hello, world!"}}`

	event := p.ParseLine([]byte(line))
	// text_end does not emit a display event
	if event != nil {
		t.Errorf("expected nil for text_end, got %+v", event)
	}

	if p.CollectedText() != "Hello, world!" {
		t.Errorf("expected collected text=\"Hello, world!\", got %q", p.CollectedText())
	}
}

func TestParser_ParseLine_TextEnd_AccumulatesText(t *testing.T) {
	p := NewParser()
	line1 := `{"type":"message_update","assistantMessageEvent":{"type":"text_end","contentIndex":0,"content":"Hello, "}}`
	line2 := `{"type":"message_update","assistantMessageEvent":{"type":"text_end","contentIndex":0,"content":"world!"}}`

	p.ParseLine([]byte(line1))
	p.ParseLine([]byte(line2))

	if p.CollectedText() != "Hello, world!" {
		t.Errorf("expected collected text=\"Hello, world!\", got %q", p.CollectedText())
	}
}

func TestParser_ParseLine_ToolExecutionEnd_Error(t *testing.T) {
	p := NewParser()
	line := `{"type":"tool_execution_end","toolCallId":"tool1","toolName":"bash","result":{"content":[{"type":"text","text":"command not found: foobar"}]},"isError":true}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventError {
		t.Errorf("expected Type=EventError, got %v", event.Type)
	}
	if event.Data.Message != "command not found: foobar" {
		t.Errorf("expected Message=\"command not found: foobar\", got %q", event.Data.Message)
	}
	if !p.HasFailure() {
		t.Error("expected parser failure to be set")
	}
}

func TestParser_ParseLine_ToolExecutionEnd_Success(t *testing.T) {
	p := NewParser()
	line := `{"type":"tool_execution_end","toolCallId":"tool1","toolName":"bash","result":{"content":[{"type":"text","text":"ok"}]},"isError":false}`

	event := p.ParseLine([]byte(line))
	if event != nil {
		t.Errorf("expected nil for successful tool execution, got %+v", event)
	}
	if p.HasFailure() {
		t.Error("expected no failure")
	}
}

func TestParser_ParseLine_AgentEnd(t *testing.T) {
	p := NewParser()
	line := `{"type":"agent_end","messages":[]}`

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
}

func TestParser_ParseLine_AgentEnd_RecoversTextFromMessages(t *testing.T) {
	p := NewParser()
	line := `{"type":"agent_end","messages":[{"role":"user","content":[{"type":"text","text":"hello"}]},{"role":"assistant","content":[{"type":"thinking","thinking":"internal"},{"type":"text","text":"final answer"}]}]}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if got := p.CollectedText(); got != "final answer" {
		t.Errorf("expected collected text %q, got %q", "final answer", got)
	}
}

func TestParser_ParseLine_AgentEnd_WithFailure(t *testing.T) {
	p := NewParser()

	// Trigger a failure first
	errorLine := `{"type":"tool_execution_end","toolCallId":"tool1","toolName":"bash","result":{"content":[{"type":"text","text":"error"}]},"isError":true}`
	p.ParseLine([]byte(errorLine))

	endLine := `{"type":"agent_end","messages":[]}`
	event := p.ParseLine([]byte(endLine))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Data.Success {
		t.Error("expected Success=false after tool error, got true")
	}
}

func TestParser_ParseLine_TurnEnd_AccumulatesTokens(t *testing.T) {
	p := NewParser()

	// Simulate message_end with usage
	msgLine := `{"type":"message_end","message":{"role":"assistant","content":[],"model":"claude-opus-4-6","usage":{"input":100,"output":50,"cacheRead":0,"cacheWrite":0,"totalTokens":150}}}`
	p.ParseLine([]byte(msgLine))

	if p.TotalTokens() != 150 {
		t.Errorf("expected TotalTokens=150, got %d", p.TotalTokens())
	}
}

func TestParser_ParseLine_IgnoredTypes(t *testing.T) {
	p := NewParser()

	ignored := []string{
		`{"type":"agent_start"}`,
		`{"type":"turn_start"}`,
		`{"type":"tool_execution_start","toolCallId":"tool1","toolName":"bash"}`,
		`{"type":"tool_execution_update","toolCallId":"tool1","toolName":"bash"}`,
		`{"type":"message_update","assistantMessageEvent":{"type":"text_delta","contentIndex":0,"delta":"hello"}}`,
		`{"type":"message_update","assistantMessageEvent":{"type":"toolcall_start","contentIndex":0}}`,
		`{"type":"message_update","assistantMessageEvent":{"type":"toolcall_delta","contentIndex":0}}`,
	}

	for _, line := range ignored {
		event := p.ParseLine([]byte(line))
		if event != nil {
			t.Errorf("expected nil for %s, got %+v", line, event)
		}
	}
}

// Thinking event tests

func TestParser_ParseLine_ThinkingStart(t *testing.T) {
	p := NewParser()
	line := `{"type":"message_update","assistantMessageEvent":{"type":"thinking_start","contentIndex":0,"partial":{"role":"assistant","content":[]}}}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventThinking {
		t.Errorf("expected Type=EventThinking, got %v", event.Type)
	}
	if event.Data.Message != "start" {
		t.Errorf("expected Message=\"start\", got %q", event.Data.Message)
	}
	if !p.isThinking {
		t.Error("expected parser.isThinking=true")
	}
}

func TestParser_ParseLine_ThinkingDelta(t *testing.T) {
	p := NewParser()
	// First, start thinking
	startLine := `{"type":"message_update","assistantMessageEvent":{"type":"thinking_start","contentIndex":0,"partial":{"role":"assistant","content":[]}}}`
	p.ParseLine([]byte(startLine))

	deltaLine := `{"type":"message_update","assistantMessageEvent":{"type":"thinking_delta","contentIndex":0,"delta":"Let me analyze the codebase structure...","partial":{"role":"assistant","content":[]}}}`

	event := p.ParseLine([]byte(deltaLine))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventThinking {
		t.Errorf("expected Type=EventThinking, got %v", event.Type)
	}
	if event.Data.Message != "delta" {
		t.Errorf("expected Message=\"delta\", got %q", event.Data.Message)
	}
}

func TestParser_ParseLine_ThinkingDelta_Empty(t *testing.T) {
	p := NewParser()
	deltaLine := `{"type":"message_update","assistantMessageEvent":{"type":"thinking_delta","contentIndex":0,"delta":"","partial":{"role":"assistant","content":[]}}}`

	event := p.ParseLine([]byte(deltaLine))
	if event != nil {
		t.Errorf("expected nil for empty thinking delta, got %+v", event)
	}
}

func TestParser_ParseLine_ThinkingDeltaWithoutStart(t *testing.T) {
	p := NewParser()
	deltaLine := `{"type":"message_update","assistantMessageEvent":{"type":"thinking_delta","contentIndex":0,"delta":"orphan delta","partial":{"role":"assistant","content":[]}}}`

	event := p.ParseLine([]byte(deltaLine))
	if event != nil {
		t.Errorf("expected nil for thinking delta without start, got %+v", event)
	}
}

func TestParser_ParseLine_ThinkingEnd(t *testing.T) {
	p := NewParser()
	// Start thinking first
	startLine := `{"type":"message_update","assistantMessageEvent":{"type":"thinking_start","contentIndex":0,"partial":{"role":"assistant","content":[]}}}`
	p.ParseLine([]byte(startLine))

	endLine := `{"type":"message_update","assistantMessageEvent":{"type":"thinking_end","contentIndex":0,"content":"I have analyzed the codebase.","partial":{"role":"assistant","content":[]}}}`

	event := p.ParseLine([]byte(endLine))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventThinking {
		t.Errorf("expected Type=EventThinking, got %v", event.Type)
	}
	if event.Data.Message != "end" {
		t.Errorf("expected Message=\"end\", got %q", event.Data.Message)
	}
	if p.isThinking {
		t.Error("expected parser.isThinking=false after thinking_end")
	}
}

func TestParser_ParseLine_ThinkingEndWithoutStart(t *testing.T) {
	p := NewParser()
	endLine := `{"type":"message_update","assistantMessageEvent":{"type":"thinking_end","contentIndex":0,"content":"orphan end","partial":{"role":"assistant","content":[]}}}`

	event := p.ParseLine([]byte(endLine))
	if event != nil {
		t.Errorf("expected nil for thinking_end without start, got %+v", event)
	}
}

func TestParser_ThinkingDoesNotCollectText(t *testing.T) {
	p := NewParser()

	// Full thinking lifecycle
	p.ParseLine([]byte(`{"type":"message_update","assistantMessageEvent":{"type":"thinking_start","contentIndex":0,"partial":{"role":"assistant","content":[]}}}`))
	p.ParseLine([]byte(`{"type":"message_update","assistantMessageEvent":{"type":"thinking_delta","contentIndex":0,"delta":"internal reasoning...","partial":{"role":"assistant","content":[]}}}`))
	p.ParseLine([]byte(`{"type":"message_update","assistantMessageEvent":{"type":"thinking_end","contentIndex":0,"content":"internal reasoning complete","partial":{"role":"assistant","content":[]}}}`))

	// Thinking should NOT be added to collected text (that's for assistant output only)
	if p.CollectedText() != "" {
		t.Errorf("expected empty collected text, got %q", p.CollectedText())
	}
}

func TestParser_ThinkingClearedByToolCall(t *testing.T) {
	p := NewParser()

	// Start thinking
	p.ParseLine([]byte(`{"type":"message_update","assistantMessageEvent":{"type":"thinking_start","contentIndex":0,"partial":{"role":"assistant","content":[]}}}`))
	if !p.isThinking {
		t.Fatal("expected isThinking=true after start")
	}

	// Tool call should clear thinking state
	p.ParseLine([]byte(`{"type":"message_update","assistantMessageEvent":{"type":"toolcall_end","contentIndex":0,"toolCall":{"type":"toolCall","id":"tool1","name":"read","arguments":{"path":"test.go"}}}}`))
	if p.isThinking {
		t.Error("expected isThinking=false after toolcall_end")
	}

	// A trailing thinking_end should be ignored once state has been cleared.
	event := p.ParseLine([]byte(`{"type":"message_update","assistantMessageEvent":{"type":"thinking_end","contentIndex":0,"content":"done","partial":{"role":"assistant","content":[]}}}`))
	if event != nil {
		t.Errorf("expected nil for thinking_end after toolcall_end, got %+v", event)
	}
}

// Helper function tests

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

func TestShortPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"file.go", "file.go"},
		{"dir/file.go", "dir/file.go"},
		{"a/b/file.go", ".../b/file.go"},
		{"a/b/c/file.go", ".../c/file.go"},
	}

	for _, tc := range tests {
		result := shortPath(tc.input)
		if result != tc.expected {
			t.Errorf("shortPath(%q): expected %q, got %q", tc.input, tc.expected, result)
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
