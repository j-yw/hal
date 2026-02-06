//go:build integration

package pi

import (
	"context"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/engine"
)

func piAvailable() bool {
	_, err := exec.LookPath("pi")
	return err == nil
}

func TestLive_EngineCreation(t *testing.T) {
	eng := New(nil)
	if eng.Name() != "pi" {
		t.Errorf("Name() = %q, want \"pi\"", eng.Name())
	}
	if eng.model != "" || eng.provider != "" {
		t.Error("nil config should leave model/provider empty")
	}

	eng2 := New(&engine.EngineConfig{Model: "claude-sonnet-4-20250514", Provider: "anthropic"})
	if eng2.model != "claude-sonnet-4-20250514" {
		t.Errorf("model = %q, want claude-sonnet-4-20250514", eng2.model)
	}
	if eng2.provider != "anthropic" {
		t.Errorf("provider = %q, want anthropic", eng2.provider)
	}
}

func TestLive_Prompt(t *testing.T) {
	if !piAvailable() {
		t.Skip("pi CLI not found")
	}

	eng := New(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	resp, err := eng.Prompt(ctx, "What is 2+2? Reply with ONLY the number, nothing else.")
	if err != nil {
		t.Fatalf("Prompt() error: %v", err)
	}

	resp = strings.TrimSpace(resp)
	t.Logf("response: %q", resp)

	if !strings.Contains(resp, "4") {
		t.Errorf("expected response to contain '4', got %q", resp)
	}
}

func TestLive_StreamPrompt(t *testing.T) {
	if !piAvailable() {
		t.Skip("pi CLI not found")
	}

	eng := New(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	display := engine.NewDisplay(io.Discard) // nil writer = discard
	text, err := eng.StreamPrompt(ctx, "What is 3+3? Reply with ONLY the number, nothing else.", display)
	if err != nil {
		t.Fatalf("StreamPrompt() error: %v", err)
	}

	text = strings.TrimSpace(text)
	t.Logf("collected text: %q", text)

	if !strings.Contains(text, "6") {
		t.Errorf("expected collected text to contain '6', got %q", text)
	}
}

func TestLive_Execute(t *testing.T) {
	if !piAvailable() {
		t.Skip("pi CLI not found")
	}

	eng := New(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	display := engine.NewDisplay(io.Discard)
	result := eng.Execute(ctx, "What is 5+5? Reply with ONLY the number, nothing else.", display)

	t.Logf("success=%v complete=%v tokens=%d duration=%s", result.Success, result.Complete, result.Tokens, result.Duration)

	if result.Error != nil {
		t.Fatalf("Execute() error: %v", result.Error)
	}
	if !result.Success {
		t.Error("expected Success=true")
	}
	if result.Tokens == 0 {
		t.Error("expected Tokens > 0")
	}
	if result.Output == "" {
		t.Error("expected non-empty Output")
	}
}
