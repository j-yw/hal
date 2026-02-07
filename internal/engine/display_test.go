package engine

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"
)

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func TestFormatThinkingComplete_ZeroStart(t *testing.T) {
	msg := formatThinkingComplete(time.Time{})
	if msg != "reasoning complete" {
		t.Errorf("expected fallback message, got %q", msg)
	}
}

func TestFormatThinkingComplete_WithElapsed(t *testing.T) {
	msg := formatThinkingComplete(time.Now().Add(-1500 * time.Millisecond))
	if !strings.HasPrefix(msg, "reasoning complete ") {
		t.Errorf("expected elapsed suffix, got %q", msg)
	}
}

func TestFormatThinkingComplete_FutureStart(t *testing.T) {
	msg := formatThinkingComplete(time.Now().Add(1 * time.Minute))
	if msg != "reasoning complete" {
		t.Errorf("expected fallback message for future start, got %q", msg)
	}
}

func TestRenderAnimatedSpinnerText_PreservesMessage(t *testing.T) {
	msg := "processing..."
	rendered := renderAnimatedSpinnerText(msg, 2)
	plain := ansiRegex.ReplaceAllString(rendered, "")
	if plain != msg {
		t.Errorf("expected rendered text to preserve message %q, got %q", msg, plain)
	}
}

func TestRenderAnimatedSpinnerText_Empty(t *testing.T) {
	rendered := renderAnimatedSpinnerText("", 5)
	if rendered != "" {
		t.Errorf("expected empty rendered text for empty input, got %q", rendered)
	}
}

func TestStartSpinner_UpdatesMessageWhenAlreadySpinning(t *testing.T) {
	var out bytes.Buffer
	d := NewDisplay(&out)

	d.StartSpinner("thinking...")
	d.StartSpinner("run ls -la")

	if !d.spinning {
		t.Fatal("expected spinner to remain active")
	}
	if d.spinMsg != "run ls -la" {
		t.Fatalf("expected spinner message to update, got %q", d.spinMsg)
	}

	d.StopSpinner()
}

func TestShowEvent_ToolKeepsSpinnerAndUpdatesMessage(t *testing.T) {
	var out bytes.Buffer
	d := NewDisplay(&out)

	d.StartSpinner("thinking...")
	d.ShowEvent(&Event{Type: EventTool, Tool: "run", Detail: "ls -la"})

	if !d.spinning {
		t.Fatal("expected spinner to stay active across tool event")
	}
	if d.spinMsg != "run ls -la" {
		t.Fatalf("expected spinner message to be updated to tool text, got %q", d.spinMsg)
	}

	d.StopSpinner()
}

func TestShowEvent_FullLifecycleSequence(t *testing.T) {
	// Init → Thinking start → Thinking delta → Tool → Tool → Thinking end → Result
	// Verifies FSM state at each step via display.fsm.State()
	var out bytes.Buffer
	d := NewDisplay(&out)

	// Step 1: Init — should transition to StateThinking
	d.ShowEvent(&Event{
		Type: EventInit,
		Data: EventData{Model: "test-model"},
	})
	if d.fsm.State() != StateThinking {
		t.Errorf("after Init: state = %v, want StateThinking", d.fsm.State())
	}
	d.StopSpinner()

	// Step 2: Thinking start — should stay in StateThinking (Reset + GoTo)
	d.ShowEvent(&Event{
		Type: EventThinking,
		Data: EventData{Message: "start"},
	})
	if d.fsm.State() != StateThinking {
		t.Errorf("after Thinking start: state = %v, want StateThinking", d.fsm.State())
	}
	if d.fsm.thinkingStart.IsZero() {
		t.Error("after Thinking start: thinkingStart should be non-zero")
	}
	d.StopSpinner()

	// Step 3: Thinking delta — should keep StateThinking unchanged
	d.ShowEvent(&Event{
		Type: EventThinking,
		Data: EventData{Message: "delta"},
	})
	if d.fsm.State() != StateThinking {
		t.Errorf("after Thinking delta: state = %v, want StateThinking", d.fsm.State())
	}
	d.StopSpinner()

	// Step 4: Tool — should transition to StateToolActivity
	d.ShowEvent(&Event{
		Type:   EventTool,
		Tool:   "Read",
		Detail: "main.go",
	})
	if d.fsm.State() != StateToolActivity {
		t.Errorf("after Tool(Read): state = %v, want StateToolActivity", d.fsm.State())
	}
	d.StopSpinner()

	// Step 5: Second Tool — should stay in StateToolActivity
	d.ShowEvent(&Event{
		Type:   EventTool,
		Tool:   "Write",
		Detail: "main.go",
	})
	if d.fsm.State() != StateToolActivity {
		t.Errorf("after Tool(Write): state = %v, want StateToolActivity", d.fsm.State())
	}
	d.StopSpinner()

	// Step 6: Thinking end — should transition through Completion then Reset to Idle
	d.ShowEvent(&Event{
		Type: EventThinking,
		Data: EventData{Message: "end"},
	})
	if d.fsm.State() != StateIdle {
		t.Errorf("after Thinking end: state = %v, want StateIdle", d.fsm.State())
	}

	// Step 7: Result — Init first to get to a valid state, then Result
	d.ShowEvent(&Event{
		Type: EventInit,
		Data: EventData{Model: "test-model"},
	})
	d.StopSpinner()
	d.ShowEvent(&Event{
		Type: EventResult,
		Data: EventData{
			Success:    true,
			Tokens:     1500,
			DurationMs: 5000,
		},
	})
	if d.fsm.State() != StateIdle {
		t.Errorf("after Result: state = %v, want StateIdle", d.fsm.State())
	}
}

func TestShowEvent_ErrorResetsToIdle(t *testing.T) {
	// Init → Thinking start → Error — verifies error handling resets FSM to StateIdle
	var out bytes.Buffer
	d := NewDisplay(&out)

	// Init
	d.ShowEvent(&Event{
		Type: EventInit,
		Data: EventData{Model: "test-model"},
	})
	d.StopSpinner()
	if d.fsm.State() != StateThinking {
		t.Fatalf("after Init: state = %v, want StateThinking", d.fsm.State())
	}

	// Thinking start
	d.ShowEvent(&Event{
		Type: EventThinking,
		Data: EventData{Message: "start"},
	})
	d.StopSpinner()
	if d.fsm.State() != StateThinking {
		t.Fatalf("after Thinking start: state = %v, want StateThinking", d.fsm.State())
	}

	// Error — should transition through StateError and reset to StateIdle
	d.ShowEvent(&Event{
		Type: EventError,
		Data: EventData{Message: "something went wrong"},
	})
	if d.fsm.State() != StateIdle {
		t.Errorf("after Error: state = %v, want StateIdle", d.fsm.State())
	}

	// Verify error message was printed
	output := out.String()
	if !strings.Contains(output, "something went wrong") {
		t.Errorf("error message not in output: %q", output)
	}
}

func TestShowEvent_DuplicateToolDedup(t *testing.T) {
	// Duplicate consecutive tool events are deduplicated via FSM lastTool
	var out bytes.Buffer
	d := NewDisplay(&out)

	// Init to get FSM into Thinking
	d.ShowEvent(&Event{
		Type: EventInit,
		Data: EventData{Model: "test-model"},
	})
	d.StopSpinner()

	// First tool event
	d.ShowEvent(&Event{
		Type:   EventTool,
		Tool:   "Read",
		Detail: "config.go",
	})
	d.StopSpinner()
	firstOutput := out.String()

	// Same tool event again — should be deduplicated (no additional output)
	d.ShowEvent(&Event{
		Type:   EventTool,
		Tool:   "Read",
		Detail: "config.go",
	})
	d.StopSpinner()
	secondOutput := out.String()

	if firstOutput != secondOutput {
		t.Errorf("duplicate tool event produced output:\nfirst:  %q\nsecond: %q", firstOutput, secondOutput)
	}

	// Verify FSM lastTool tracks the key
	expectedKey := "Readconfig.go"
	if d.fsm.LastTool() != expectedKey {
		t.Errorf("fsm.LastTool() = %q, want %q", d.fsm.LastTool(), expectedKey)
	}

	// Different tool should NOT be deduplicated
	d.ShowEvent(&Event{
		Type:   EventTool,
		Tool:   "Write",
		Detail: "config.go",
	})
	d.StopSpinner()
	thirdOutput := out.String()

	if thirdOutput == secondOutput {
		t.Error("different tool event was incorrectly deduplicated")
	}
}

func TestShowEvent_SpinnerMessageUpdatesOnTransition(t *testing.T) {
	// Spinner message updates on Thinking→ToolActivity transition
	var out bytes.Buffer
	d := NewDisplay(&out)

	// Init → FSM goes to Thinking, spinner starts with thinking word
	d.ShowEvent(&Event{
		Type: EventInit,
		Data: EventData{Model: "test-model"},
	})
	if d.fsm.State() != StateThinking {
		t.Fatalf("after Init: state = %v, want StateThinking", d.fsm.State())
	}
	// Spinner message should be a HAL thinking word
	thinkingMsg := d.spinMsg
	if thinkingMsg == "" {
		t.Fatal("spinner message should be set after Init")
	}

	// Tool event → FSM transitions to ToolActivity, spinner message updates
	d.ShowEvent(&Event{
		Type:   EventTool,
		Tool:   "Read",
		Detail: "server.go",
	})
	if d.fsm.State() != StateToolActivity {
		t.Fatalf("after Tool: state = %v, want StateToolActivity", d.fsm.State())
	}

	// Spinner message should now reflect the tool
	toolMsg := d.spinMsg
	if toolMsg == thinkingMsg {
		t.Errorf("spinner message did not update on Thinking→ToolActivity transition: still %q", toolMsg)
	}
	if !strings.Contains(toolMsg, "Read") {
		t.Errorf("spinner message should contain tool name, got %q", toolMsg)
	}

	d.StopSpinner()
}
