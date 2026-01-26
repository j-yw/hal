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
	EventInit    EventType = "init"    // Session initialization
	EventTool    EventType = "tool"    // Tool invocation
	EventText    EventType = "text"    // Text response
	EventResult  EventType = "result"  // Final result
	EventError   EventType = "error"   // Error occurred
	EventUnknown EventType = "unknown" // Unrecognized event
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
	// Name returns the engine identifier (e.g., "claude", "amp")
	Name() string

	// Execute runs the prompt and returns the result.
	// The display is used to show progress during execution.
	Execute(ctx context.Context, prompt string, display *Display) Result
}

// OutputParser parses engine-specific output into normalized Events.
type OutputParser interface {
	// ParseLine parses a single line of output and returns an Event.
	// Returns nil if the line should be ignored.
	ParseLine(line []byte) *Event
}

// DefaultTimeout for engine execution.
const DefaultTimeout = 30 * time.Minute
