package engine

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)
var resultDurationRegex = regexp.MustCompile(`\[(?:OK|!!)\]\s+(\d+)s`)

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

func TestShowCommandHeader_OmitsEmptyEngine(t *testing.T) {
	var out bytes.Buffer
	d := NewDisplay(&out)

	d.ShowCommandHeader("Sandbox Stop", "1 target(s)", HeaderContext{})

	plain := ansiRegex.ReplaceAllString(out.String(), "")
	if strings.Contains(plain, "engine:") {
		t.Fatalf("header should omit empty engine metadata:\n%s", plain)
	}
	if !strings.Contains(plain, "Sandbox Stop") {
		t.Fatalf("header missing title:\n%s", plain)
	}
	if !strings.Contains(plain, "1 target(s)") {
		t.Fatalf("header missing context:\n%s", plain)
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

func TestShowEvent_ToolAfterThinkingShowsReasoningCompleteLine(t *testing.T) {
	var out bytes.Buffer
	d := NewDisplay(&out)

	d.isThinking = true
	d.thinkingStart = time.Now().Add(-2 * time.Second)
	d.StartSpinner("thinking...")
	d.ShowEvent(&Event{Type: EventTool, Tool: "run", Detail: "git status"})

	plain := ansiRegex.ReplaceAllString(out.String(), "")
	if !strings.Contains(plain, "reasoning complete") {
		t.Fatalf("expected reasoning completion line in output, got %q", plain)
	}
	if !strings.Contains(plain, "run git status") {
		t.Fatalf("expected tool line in output, got %q", plain)
	}

	d.StopSpinner()
}

func TestShowEvent_ResultFallsBackToDisplayElapsedWhenDurationMissing(t *testing.T) {
	var out bytes.Buffer
	d := NewDisplay(&out)
	d.startTime = time.Now().Add(-3 * time.Second)

	d.ShowEvent(&Event{Type: EventResult, Data: EventData{Success: true}})

	plain := ansiRegex.ReplaceAllString(out.String(), "")
	seconds := parseRenderedResultDurationSeconds(t, plain)
	if seconds < 1 {
		t.Fatalf("expected fallback duration >= 1s, got %ds in %q", seconds, plain)
	}
}

func TestShowEvent_ResultUsesEventDurationWhenProvided(t *testing.T) {
	var out bytes.Buffer
	d := NewDisplay(&out)
	d.startTime = time.Now().Add(-10 * time.Second)

	d.ShowEvent(&Event{Type: EventResult, Data: EventData{Success: true, DurationMs: 2000}})

	plain := ansiRegex.ReplaceAllString(out.String(), "")
	seconds := parseRenderedResultDurationSeconds(t, plain)
	if seconds != 2 {
		t.Fatalf("expected event duration 2s, got %ds in %q", seconds, plain)
	}
}

func TestShowEvent_ResultSubSecondDurationDoesNotFallback(t *testing.T) {
	var out bytes.Buffer
	d := NewDisplay(&out)
	d.startTime = time.Now().Add(-10 * time.Second)

	d.ShowEvent(&Event{Type: EventResult, Data: EventData{Success: true, DurationMs: 500}})

	plain := ansiRegex.ReplaceAllString(out.String(), "")
	seconds := parseRenderedResultDurationSeconds(t, plain)
	if seconds != 0 {
		t.Fatalf("expected sub-second duration to render 0s, got %ds in %q", seconds, plain)
	}
}

func parseRenderedResultDurationSeconds(t *testing.T, rendered string) int {
	t.Helper()

	match := resultDurationRegex.FindStringSubmatch(rendered)
	if len(match) != 2 {
		t.Fatalf("could not parse result duration from %q", rendered)
	}

	seconds, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("invalid duration seconds %q: %v", match[1], err)
	}

	return seconds
}
