package engine

import (
	"context"
	"time"
)

// Result represents the outcome of an engine execution.
type Result struct {
	Success  bool          // Whether the execution succeeded
	Complete bool          // Whether all tasks are complete (<promise>COMPLETE</promise>)
	Output   string        // Raw output from the engine
	Duration time.Duration // How long the execution took
	Tokens   int           // Total tokens used (if available)
	Error    error         // Any error that occurred
}

// Event represents a normalized event from any engine's output.
type Event struct {
	Type   EventType // Category of event
	Tool   string    // Tool name (read, write, bash, etc.)
	Detail string    // Path, command, message, etc.
	Data   EventData // Additional structured data
}

// EventType categorizes engine output events.
type EventType string

const (
	EventInit     EventType = "init"     // Session initialization
	EventTool     EventType = "tool"     // Tool invocation
	EventText     EventType = "text"     // Text response
	EventThinking EventType = "thinking" // Model is thinking/reasoning
	EventResult   EventType = "result"   // Final result
	EventError    EventType = "error"    // Error occurred
	EventUnknown  EventType = "unknown"  // Unrecognized event
)

// EventData holds optional structured data for events.
type EventData struct {
	Model      string  // Model name (for init events)
	Success    bool    // Success status (for result events)
	Tokens     int     // Token count (for result events)
	DurationMs float64 // Duration in ms (for result events)
	Message    string  // Error or info message
}

// Engine defines the interface for AI coding tool engines.
type Engine interface {
	// Name returns the engine identifier (e.g., "claude")
	Name() string

	// Execute runs the prompt and returns the result.
	// The display is used to show progress during execution.
	Execute(ctx context.Context, prompt string, display *Display) Result

	// Prompt executes a single prompt and returns the text response.
	// This is a simpler interface for non-streaming, single-shot prompts.
	Prompt(ctx context.Context, prompt string) (string, error)

	// StreamPrompt executes a prompt with streaming display feedback.
	// Events (spinners, tool calls) are shown via the display while
	// the text response is collected and returned.
	StreamPrompt(ctx context.Context, prompt string, display *Display) (string, error)
}

// OutputParser parses engine-specific output into normalized Events.
type OutputParser interface {
	// ParseLine parses a single line of output and returns an Event.
	// Returns nil if the line should be ignored.
	ParseLine(line []byte) *Event
}

// EngineConfig holds optional per-engine configuration from .hal/config.yaml.
// Nil or empty fields mean "use engine defaults".
type EngineConfig struct {
	Model    string        // Model ID (e.g., "claude-sonnet-4-20250514", "gemini-2.5-pro")
	Provider string        // Provider name (pi-only: "anthropic", "google", "openai", etc.)
	Timeout  time.Duration // Per-session timeout (0 means use DefaultTimeout)
}

// DefaultTimeout for engine execution.
const DefaultTimeout = 15 * time.Minute
