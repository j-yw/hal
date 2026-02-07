package engine

import (
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
