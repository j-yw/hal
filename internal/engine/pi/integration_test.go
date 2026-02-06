package pi

import (
	"bufio"
	"os"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
)

// TestParser_RealPiOutput feeds captured pi JSONL through the parser
// and validates the event sequence matches expectations.
//
// To generate the test fixture, run:
//
//	echo 'Read the file go.mod and tell me the module name. Only output the module name, nothing else.' |
//	  pi -p --no-session --mode json > /tmp/pi-test-output.jsonl
//
// Skips if the file doesn't exist.
func TestParser_RealPiOutput(t *testing.T) {
	const testFile = "/tmp/pi-test-output.jsonl"
	f, err := os.Open(testFile)
	if err != nil {
		t.Skipf("skipping: %s not found (run pi capture first)", testFile)
	}
	defer f.Close()

	parser := NewParser()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB lines

	var events []*engine.Event
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		event := parser.ParseLine(scanner.Bytes())
		if event != nil {
			events = append(events, event)
			t.Logf("line %d → %s tool=%q detail=%q model=%q tokens=%d",
				lineNum, event.Type, event.Tool, event.Detail, event.Data.Model, event.Data.Tokens)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}

	if len(events) == 0 {
		t.Fatal("parser produced no events from real pi output")
	}

	// Validate event sequence
	// Expected: EventInit(session) → EventInit(model) → EventTool(read) → EventResult(agent_end)
	var types []engine.EventType
	for _, e := range events {
		types = append(types, e.Type)
	}
	t.Logf("event types: %v", types)

	// First event should be EventInit (session)
	if events[0].Type != engine.EventInit {
		t.Errorf("first event: want EventInit, got %s", events[0].Type)
	}
	if events[0].Data.Model != "pi" {
		t.Errorf("session event model: want \"pi\", got %q", events[0].Data.Model)
	}

	// Should have a second EventInit with real model name
	var modelEvent *engine.Event
	for _, e := range events {
		if e.Type == engine.EventInit && e.Data.Model != "pi" {
			modelEvent = e
			break
		}
	}
	if modelEvent == nil {
		t.Error("no model init event found (expected model name from message_start)")
	} else {
		t.Logf("detected model: %s", modelEvent.Data.Model)
		if modelEvent.Data.Model == "" {
			t.Error("model name is empty")
		}
	}

	// Should have at least one tool event (the read call)
	var toolEvents []*engine.Event
	for _, e := range events {
		if e.Type == engine.EventTool {
			toolEvents = append(toolEvents, e)
		}
	}
	if len(toolEvents) == 0 {
		t.Error("no tool events found (expected at least a read)")
	} else {
		t.Logf("tool events: %d", len(toolEvents))
		// First tool should be read of go.mod
		if toolEvents[0].Tool != "read" {
			t.Errorf("first tool: want \"read\", got %q", toolEvents[0].Tool)
		}
	}

	// Last event should be EventResult (agent_end)
	last := events[len(events)-1]
	if last.Type != engine.EventResult {
		t.Errorf("last event: want EventResult, got %s", last.Type)
	}
	if !last.Data.Success {
		t.Error("agent_end should report success")
	}

	// Parser should have collected text
	text := parser.CollectedText()
	t.Logf("collected text: %q", text)
	if text == "" {
		t.Error("parser collected no text")
	}
	if text != "github.com/jywlabs/hal" {
		t.Errorf("collected text: want \"github.com/jywlabs/hal\", got %q", text)
	}

	// Token count should be > 0
	tokens := parser.TotalTokens()
	t.Logf("total tokens: %d", tokens)
	if tokens == 0 {
		t.Error("total tokens is 0")
	}

	// No failures
	if parser.HasFailure() {
		t.Error("parser reports failure but session was successful")
	}
}
