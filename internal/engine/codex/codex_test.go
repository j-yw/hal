package codex

import (
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/engine"
)

func TestNew(t *testing.T) {
	e := New(nil)
	if e == nil {
		t.Fatal("New() returned nil")
	}
	if e.Timeout != engine.DefaultTimeout {
		t.Errorf("expected Timeout=%v, got %v", engine.DefaultTimeout, e.Timeout)
	}
}

func TestName(t *testing.T) {
	e := New(nil)
	if e.Name() != "codex" {
		t.Errorf("expected Name()=\"codex\", got %q", e.Name())
	}
}

func TestCLICommand(t *testing.T) {
	e := New(nil)
	if e.CLICommand() != "codex" {
		t.Errorf("expected CLICommand()=\"codex\", got %q", e.CLICommand())
	}
}

func TestBuildArgs(t *testing.T) {
	e := New(nil)
	args := e.BuildArgs()

	expected := []string{
		"exec",
		"--dangerously-bypass-approvals-and-sandbox",
		"--json",
		"-",
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

func TestBuildArgsNoJSON(t *testing.T) {
	e := New(nil)
	args := e.BuildArgsNoJSON()

	expected := []string{
		"exec",
		"--dangerously-bypass-approvals-and-sandbox",
		"-",
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

func TestCodexStreamInactivityTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{name: "uses default when zero", timeout: 0, want: 25 * time.Minute},
		{name: "keeps grace below long timeout", timeout: 30 * time.Minute, want: 25 * time.Minute},
		{name: "falls back to minimum for medium timeout", timeout: 15 * time.Minute, want: 10 * time.Minute},
		{name: "never exceeds total timeout", timeout: 2 * time.Minute, want: 2 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := codexStreamInactivityTimeout(tt.timeout)
			if got != tt.want {
				t.Fatalf("codexStreamInactivityTimeout(%v) = %v, want %v", tt.timeout, got, tt.want)
			}
		})
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
	if event.Data.Model != "" {
		t.Errorf("expected Model=\"\", got %q", event.Data.Model)
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

func TestParser_ParseLine_TurnCompleted_FailurePropagates(t *testing.T) {
	p := NewParser()
	failLine := `{"type":"item.completed","item":{"type":"command_execution","command":"false","exit_code":1}}`
	p.ParseLine([]byte(failLine))

	line := `{"type":"turn.completed","usage":{"input_tokens":1}}`
	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventResult {
		t.Errorf("expected Type=EventResult, got %v", event.Type)
	}
	if event.Data.Success {
		t.Error("expected Success=false after command failure, got true")
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

func TestParser_ParseLine_TurnFailed(t *testing.T) {
	p := NewParser()
	line := `{"type":"turn.failed","error":{"message":"rate limit"}}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventError {
		t.Errorf("expected Type=EventError, got %v", event.Type)
	}
	if event.Data.Message != "rate limit" {
		t.Errorf("expected Message=\"rate limit\", got %q", event.Data.Message)
	}
	if !p.HasFailure() {
		t.Error("expected parser failure to be set")
	}
}

func TestParser_ParseLine_ErrorEvent(t *testing.T) {
	p := NewParser()
	line := `{"type":"error","message":"auth failed"}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventError {
		t.Errorf("expected Type=EventError, got %v", event.Type)
	}
	if event.Data.Message != "auth failed" {
		t.Errorf("expected Message=\"auth failed\", got %q", event.Data.Message)
	}
	if !p.HasFailure() {
		t.Error("expected parser failure to be set")
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

func TestParser_ParseLine_UnknownItemType_FailedStatus(t *testing.T) {
	p := NewParser()
	line := `{"type":"item.completed","item":{"type":"file_change","status":"failed","error":{"message":"patch failed"}}}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventError {
		t.Errorf("expected Type=EventError, got %v", event.Type)
	}
	if event.Data.Message != "patch failed" {
		t.Errorf("expected Message=\"patch failed\", got %q", event.Data.Message)
	}
	if !p.HasFailure() {
		t.Error("expected parser failure to be set")
	}
}

func TestParser_ParseLine_EventMsgTaskStarted(t *testing.T) {
	p := NewParser()
	line := `{"type":"event_msg","payload":{"type":"task_started"}}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventInit {
		t.Errorf("expected Type=EventInit, got %v", event.Type)
	}
}

func TestParser_ParseLine_EventMsgReasoningStartAndDelta(t *testing.T) {
	p := NewParser()
	line := `{"type":"event_msg","payload":{"type":"agent_reasoning","text":"thinking"}}`

	first := p.ParseLine([]byte(line))
	if first == nil {
		t.Fatal("expected first event, got nil")
	}
	if first.Type != engine.EventThinking {
		t.Fatalf("first.Type = %v, want %v", first.Type, engine.EventThinking)
	}
	if first.Data.Message != "start" {
		t.Fatalf("first.Data.Message = %q, want %q", first.Data.Message, "start")
	}

	second := p.ParseLine([]byte(line))
	if second == nil {
		t.Fatal("expected second event, got nil")
	}
	if second.Type != engine.EventThinking {
		t.Fatalf("second.Type = %v, want %v", second.Type, engine.EventThinking)
	}
	if second.Data.Message != "delta" {
		t.Fatalf("second.Data.Message = %q, want %q", second.Data.Message, "delta")
	}
}

func TestParser_ParseLine_EventMsgTaskCompleteWithTokenCount(t *testing.T) {
	p := NewParser()
	tokenLine := `{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"total_tokens":1234}}}}`
	completeLine := `{"type":"event_msg","payload":{"type":"task_complete"}}`

	if event := p.ParseLine([]byte(tokenLine)); event != nil {
		t.Fatalf("expected nil for token_count event, got %+v", event)
	}

	event := p.ParseLine([]byte(completeLine))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventResult {
		t.Fatalf("expected Type=EventResult, got %v", event.Type)
	}
	if !event.Data.Success {
		t.Fatal("expected Success=true, got false")
	}
	if event.Data.Tokens != 1234 {
		t.Fatalf("expected Tokens=1234, got %d", event.Data.Tokens)
	}
}

func TestParser_ParseLine_DuplicateTerminalResultIgnored(t *testing.T) {
	p := NewParser()
	failLine := `{"type":"item.completed","item":{"type":"command_execution","command":"false","exit_code":1}}`
	taskCompleteLine := `{"type":"event_msg","payload":{"type":"task_complete"}}`
	turnCompletedLine := `{"type":"turn.completed","usage":{"input_tokens":1}}`

	if event := p.ParseLine([]byte(failLine)); event == nil || event.Type != engine.EventError {
		t.Fatalf("expected command failure event before terminal result, got %+v", event)
	}

	first := p.ParseLine([]byte(taskCompleteLine))
	if first == nil {
		t.Fatal("expected first terminal result, got nil")
	}
	if first.Type != engine.EventResult {
		t.Fatalf("expected first terminal type=EventResult, got %v", first.Type)
	}
	if first.Data.Success {
		t.Fatal("expected first terminal Success=false, got true")
	}

	if second := p.ParseLine([]byte(turnCompletedLine)); second != nil {
		t.Fatalf("expected duplicate terminal result to be ignored, got %+v", second)
	}
}

func TestParser_ParseLine_ResponseItemAssistantFinalAnswer(t *testing.T) {
	p := NewParser()
	line := `{"type":"response_item","payload":{"type":"message","role":"assistant","phase":"final_answer","content":[{"type":"output_text","text":"done"}]}}`

	event := p.ParseLine([]byte(line))
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.Type != engine.EventText {
		t.Fatalf("expected Type=EventText, got %v", event.Type)
	}
	if event.Detail != "done" {
		t.Fatalf("expected Detail=%q, got %q", "done", event.Detail)
	}
}

func TestEngine_parseSuccess_FailureWithoutTurnCompleted(t *testing.T) {
	e := New(nil)
	output := `{"type":"error","message":"auth failed"}`

	if e.parseSuccess(output) {
		t.Error("expected parseSuccess to return false for error-only output")
	}
}

func TestEngine_parseSuccess_ItemFailureWithoutTurnCompleted(t *testing.T) {
	e := New(nil)
	output := `{"type":"item.completed","item":{"type":"file_change","status":"failed"}}`

	if e.parseSuccess(output) {
		t.Error("expected parseSuccess to return false for failed item output")
	}
}

func TestEngine_parseSuccess_DuplicateTerminalResultDoesNotMaskFailure(t *testing.T) {
	e := New(nil)
	output := `{"type":"item.completed","item":{"type":"command_execution","command":"false","exit_code":1}}
{"type":"event_msg","payload":{"type":"task_complete"}}
{"type":"turn.completed","usage":{"input_tokens":1}}`

	if e.parseSuccess(output) {
		t.Error("expected parseSuccess to return false when duplicate terminal results follow a failure")
	}
}

func TestEngine_parseResultStatus_UsesFinalParserState(t *testing.T) {
	e := New(nil)
	output := `{"type":"turn.completed","usage":{"input_tokens":1}}
{"type":"event_msg","payload":{"type":"task_started"}}`

	hasResult, success := e.parseResultStatus(output)
	if hasResult {
		t.Fatal("expected no final terminal result after task restart")
	}
	if success {
		t.Fatal("expected success=false when no final terminal result exists")
	}
}

func TestTextCollectingStreamHandler_collectText_ItemCompletedAgentMessage(t *testing.T) {
	h := &textCollectingStreamHandler{}
	line := []byte(`{"type":"item.completed","item":{"type":"agent_message","text":"{\"summary\":\"ok\",\"issues\":[]}"}}`)

	h.collectText(line)

	if got := h.text.String(); got != `{"summary":"ok","issues":[]}` {
		t.Fatalf("collected text = %q, want %q", got, `{"summary":"ok","issues":[]}`)
	}
}

func TestTextCollectingStreamHandler_collectText_ResponseItemAssistantMessage(t *testing.T) {
	h := &textCollectingStreamHandler{}
	line := []byte(`{"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"{\"summary\":\"ok\",\"issues\":[]}"}]}}`)

	h.collectText(line)

	if got := h.text.String(); got != `{"summary":"ok","issues":[]}` {
		t.Fatalf("collected text = %q, want %q", got, `{"summary":"ok","issues":[]}`)
	}
}

func TestTextCollectingStreamHandler_collectText_ResponseItemCommentaryIgnored(t *testing.T) {
	h := &textCollectingStreamHandler{}
	line := []byte(`{"type":"response_item","payload":{"type":"message","role":"assistant","phase":"commentary","content":[{"type":"output_text","text":"working..."}]}}`)

	h.collectText(line)

	if got := h.text.String(); got != "" {
		t.Fatalf("collected text = %q, want empty", got)
	}
}

func TestTextCollectingStreamHandler_collectText_EventMessageJSONOnly(t *testing.T) {
	h := &textCollectingStreamHandler{}
	nonJSONLine := []byte(`{"type":"event_msg","payload":{"type":"agent_message","message":"working..."}}`)
	jsonLine := []byte(`{"type":"event_msg","payload":{"type":"agent_message","message":"{\"summary\":\"ok\",\"issues\":[]}"}}`)

	h.collectText(nonJSONLine)
	h.collectText(jsonLine)

	if got := h.text.String(); got != `{"summary":"ok","issues":[]}` {
		t.Fatalf("collected text = %q, want %q", got, `{"summary":"ok","issues":[]}`)
	}
}

func TestTextCollectingStreamHandler_collectText_PrefersLatestMachinePayload(t *testing.T) {
	h := &textCollectingStreamHandler{}
	first := []byte(`{"type":"item.completed","item":{"type":"agent_message","text":"{\"summary\":\"first\",\"issues\":[]}"}}`)
	second := []byte(`{"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"{\"summary\":\"second\",\"issues\":[]}"}]}}`)
	trailing := []byte(`{"type":"item.completed","item":{"type":"agent_message","text":"done"}}`)

	h.collectText(first)
	h.collectText(second)
	h.collectText(trailing)

	if got := h.Text(); got != `{"summary":"second","issues":[]}` {
		t.Fatalf("collected text = %q, want %q", got, `{"summary":"second","issues":[]}`)
	}
}

// Helper function tests

func TestExtractCommand(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Single-quoted wrappers
		{"/usr/bin/bash -lc 'echo hello'", "echo hello"},
		{"/bin/bash -lc 'ls -la'", "ls -la"},
		{"/usr/bin/bash -c 'git status'", "git status"},
		{"/usr/bin/bash -lc 'single'", "single"},

		// Double-quoted wrappers (Codex style)
		{`/usr/bin/bash -lc "echo hello"`, "echo hello"},
		{`/usr/bin/bash -lc "ls -la"`, "ls -la"},
		{`/usr/bin/bash -c "git status"`, "git status"},

		// Multi-line with shell preamble (Codex style)
		{"/usr/bin/bash -lc \"set -e\nls -ld .claude/skills\"", "ls -ld .claude/skills"},
		{"/usr/bin/bash -lc \"set -euo pipefail\ngit diff HEAD\"", "git diff HEAD"},
		{"/usr/bin/bash -lc \"set -e\nset -o pipefail\nrg -n foo\"", "rg -n foo"},

		// No wrapper
		{"echo hello", "echo hello"},

		// Empty command - no extraction possible (start > end)
		{"/usr/bin/bash -lc ''", "/usr/bin/bash -lc ''"},
		{`/usr/bin/bash -lc ""`, `/usr/bin/bash -lc ""`},
	}

	for _, tc := range tests {
		result := extractCommand(tc.input)
		if result != tc.expected {
			t.Errorf("extractCommand(%q): expected %q, got %q", tc.input, tc.expected, result)
		}
	}
}

func TestFirstMeaningfulLine(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"echo hello", "echo hello"},
		{"set -e\nls -la", "ls -la"},
		{"set -euo pipefail\nset -o pipefail\ngit status", "git status"},
		{"set -e", "set -e"},           // All preamble — return last
		{"\n\nset -e\n\n", "set -e"},   // Blank lines + preamble only
		{"", ""},                        // Empty
		{"\n\n", "\n\n"},               // Only newlines — falls through
	}

	for _, tc := range tests {
		result := firstMeaningfulLine(tc.input)
		if result != tc.expected {
			t.Errorf("firstMeaningfulLine(%q): expected %q, got %q", tc.input, tc.expected, result)
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
