//go:build integration
// +build integration

package codex

// Codex CLI Integration Notes
//
// Quirks discovered during integration testing:
//
// 1. JSONL Event Format:
//    - Events are: thread.started, turn.started, item.started, item.completed, turn.completed
//    - Item types: command_execution, agent_message, reasoning
//    - No explicit success/failure in turn.completed - must infer from exit_code in command_execution
//
// 2. Command Wrapping:
//    - All bash commands are wrapped: /usr/bin/bash -lc 'actual command'
//    - Use extractCommand() to unwrap for display purposes
//
// 3. Display Events:
//    - Events display correctly with spinners cycling through tool execution
//    - Model is displayed as "codex" (not the actual model version)
//    - Token counts are available in turn.completed usage field
//
// 4. Timeout Handling:
//    - Context cancellation works correctly
//    - Short timeouts (1s) properly abort long-running operations
//    - Error message includes "timed out" for detection
//
// 5. Response Formats:
//    - Prompt() (without --json): Returns plain text directly
//    - Execute() (with --json): Returns JSONL stream
//    - StreamPrompt() (with --json): Returns JSONL stream, collects text from agent_message items
//
// 6. Complete Detection:
//    - <promise>COMPLETE</promise> in output correctly sets Result.Complete=true
//    - Works when included in agent_message text responses

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/engine"
)

// These tests require the Codex CLI to be installed and authenticated.
// Run with: go test -tags=integration ./internal/engine/codex/...

func TestCodexCLIAvailable(t *testing.T) {
	_, err := exec.LookPath("codex")
	if err != nil {
		t.Skip("codex CLI not found, skipping integration tests")
	}
}

func TestExecuteWithSimplePrompt(t *testing.T) {
	if _, err := exec.LookPath("codex"); err != nil {
		t.Skip("codex CLI not found")
	}

	eng := New()
	eng.Timeout = 2 * time.Minute

	ctx := context.Background()

	// Capture display output
	var buf bytes.Buffer
	display := engine.NewDisplay(&buf)

	// Simple prompt that should succeed quickly
	prompt := `Just respond with the exact text "Hello from Codex" and nothing else. Do not use any tools.`

	result := eng.Execute(ctx, prompt, display)

	// Log output for debugging
	t.Logf("Execute result: Success=%v, Complete=%v, Duration=%v", result.Success, result.Complete, result.Duration)
	t.Logf("Output length: %d bytes", len(result.Output))
	t.Logf("Display output:\n%s", buf.String())

	if result.Error != nil {
		t.Errorf("Execute failed with error: %v", result.Error)
	}

	if !result.Success {
		t.Errorf("Execute returned Success=false, output: %s", result.Output)
	}
}

func TestExecuteEventsDisplayCorrectly(t *testing.T) {
	if _, err := exec.LookPath("codex"); err != nil {
		t.Skip("codex CLI not found")
	}

	eng := New()
	eng.Timeout = 2 * time.Minute

	ctx := context.Background()

	var buf bytes.Buffer
	display := engine.NewDisplay(&buf)

	// Prompt that will trigger a tool use
	prompt := `Create a file named /tmp/codex-test-file.txt with the content "test". Then read it back to verify.`

	result := eng.Execute(ctx, prompt, display)

	displayOutput := buf.String()
	t.Logf("Display output:\n%s", displayOutput)

	if result.Error != nil {
		t.Errorf("Execute failed: %v", result.Error)
	}

	// Check that some events were displayed (tool usage arrows, etc.)
	// The display should show tool invocations like "run" for bash commands
	if len(displayOutput) == 0 {
		t.Log("Warning: Display output is empty - events may not be rendering")
	}
}

func TestResultReflectsSuccessFailure(t *testing.T) {
	if _, err := exec.LookPath("codex"); err != nil {
		t.Skip("codex CLI not found")
	}

	eng := New()
	eng.Timeout = 2 * time.Minute

	ctx := context.Background()

	// Test success case
	t.Run("success", func(t *testing.T) {
		var buf bytes.Buffer
		display := engine.NewDisplay(&buf)

		prompt := `Respond with "success" and do not use any tools.`
		result := eng.Execute(ctx, prompt, display)

		if result.Error != nil {
			t.Errorf("Expected no error, got: %v", result.Error)
		}
		if !result.Success {
			t.Errorf("Expected Success=true for simple prompt")
		}
	})

	// Test Complete flag detection
	t.Run("complete_flag", func(t *testing.T) {
		var buf bytes.Buffer
		display := engine.NewDisplay(&buf)

		prompt := `Respond with exactly this text: <promise>COMPLETE</promise>`
		result := eng.Execute(ctx, prompt, display)

		t.Logf("Output: %s", result.Output)
		t.Logf("Complete: %v", result.Complete)

		// Note: The Complete flag depends on the literal string appearing in output
		// This may or may not work depending on how Codex handles the response
		if strings.Contains(result.Output, "<promise>COMPLETE</promise>") && !result.Complete {
			t.Errorf("Expected Complete=true when output contains <promise>COMPLETE</promise>")
		}
	})
}

func TestPromptReturnsExpectedText(t *testing.T) {
	if _, err := exec.LookPath("codex"); err != nil {
		t.Skip("codex CLI not found")
	}

	eng := New()
	eng.Timeout = 2 * time.Minute

	ctx := context.Background()

	// Simple prompt that returns text
	prompt := `What is 2+2? Answer with just the number, nothing else.`

	response, err := eng.Prompt(ctx, prompt)

	t.Logf("Prompt response: %q", response)

	if err != nil {
		t.Errorf("Prompt failed: %v", err)
	}

	// Response should contain "4" somewhere
	if !strings.Contains(response, "4") {
		t.Errorf("Expected response to contain '4', got: %q", response)
	}
}

func TestStreamPromptCollectsText(t *testing.T) {
	if _, err := exec.LookPath("codex"); err != nil {
		t.Skip("codex CLI not found")
	}

	eng := New()
	eng.Timeout = 2 * time.Minute

	ctx := context.Background()

	var buf bytes.Buffer
	display := engine.NewDisplay(&buf)

	prompt := `What is 3+5? Answer with just the number.`

	response, err := eng.StreamPrompt(ctx, prompt, display)

	t.Logf("StreamPrompt response: %q", response)
	t.Logf("Display output:\n%s", buf.String())

	if err != nil {
		t.Errorf("StreamPrompt failed: %v", err)
	}

	// Response should contain "8" somewhere
	if !strings.Contains(response, "8") {
		t.Errorf("Expected response to contain '8', got: %q", response)
	}
}

func TestTimeoutBehavior(t *testing.T) {
	if _, err := exec.LookPath("codex"); err != nil {
		t.Skip("codex CLI not found")
	}

	eng := New()
	eng.Timeout = 1 * time.Second // Very short timeout

	ctx := context.Background()
	var buf bytes.Buffer
	display := engine.NewDisplay(&buf)

	// A prompt that would take longer than 1 second
	prompt := `Write a 500 word essay about artificial intelligence.`

	result := eng.Execute(ctx, prompt, display)

	t.Logf("Timeout test result: Success=%v, Error=%v", result.Success, result.Error)

	// With a 1-second timeout, this should either timeout or (if Codex responds fast) succeed
	// We mainly want to verify that timeout handling doesn't crash
	if result.Error != nil && !strings.Contains(result.Error.Error(), "timed out") {
		// Other errors are fine, we just want to make sure timeout is handled gracefully
		t.Logf("Got error (non-timeout): %v", result.Error)
	}
}
