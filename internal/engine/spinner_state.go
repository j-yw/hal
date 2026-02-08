package engine

import (
	"fmt"
	"time"
)

// SpinnerState represents the current state of the spinner finite state machine.
type SpinnerState int

const (
	StateIdle         SpinnerState = iota // No activity
	StateThinking                         // Model is reasoning
	StateToolActivity                     // Tool is executing
	StateCompletion                       // Execution completed successfully
	StateError                            // Error occurred
)

// String returns a human-readable name for the state.
func (s SpinnerState) String() string {
	switch s {
	case StateIdle:
		return "Idle"
	case StateThinking:
		return "Thinking"
	case StateToolActivity:
		return "ToolActivity"
	case StateCompletion:
		return "Completion"
	case StateError:
		return "Error"
	default:
		return fmt.Sprintf("Unknown(%d)", int(s))
	}
}

// validTransitions defines the explicit allow-list of state transitions.
var validTransitions = map[SpinnerState]map[SpinnerState]bool{
	StateIdle: {
		StateThinking: true,
		StateIdle:     true,
	},
	StateThinking: {
		StateToolActivity: true,
		StateCompletion:   true,
		StateError:        true,
	},
	StateToolActivity: {
		StateThinking:     true,
		StateToolActivity: true,
		StateCompletion:   true,
		StateError:        true,
	},
	StateCompletion: {
		StateIdle: true,
	},
	StateError: {
		StateIdle: true,
	},
}

// Transition validates whether a state transition from → to is allowed.
// Returns nil if the transition is valid, or an error describing the invalid transition.
func Transition(from, to SpinnerState) error {
	if targets, ok := validTransitions[from]; ok {
		if targets[to] {
			return nil
		}
	}
	return fmt.Errorf("invalid spinner transition: %s → %s", from, to)
}

// SpinnerFSM encapsulates spinner state, message, timing, and tool dedup tracking.
type SpinnerFSM struct {
	state         SpinnerState
	message       string
	thinkingStart time.Time
	lastTool      string
}

// NewSpinnerFSM returns a new FSM in StateIdle with zero-value fields.
func NewSpinnerFSM() *SpinnerFSM {
	return &SpinnerFSM{state: StateIdle}
}

// State returns the current SpinnerState.
func (f *SpinnerFSM) State() SpinnerState {
	return f.state
}

// GoTo transitions the FSM to the next state with the given message.
// Returns an error if the transition is invalid.
func (f *SpinnerFSM) GoTo(next SpinnerState, msg string) error {
	if err := Transition(f.state, next); err != nil {
		return err
	}
	f.state = next
	f.message = msg
	if next == StateThinking {
		f.thinkingStart = time.Now()
	}
	return nil
}

// Message returns the current message string.
func (f *SpinnerFSM) Message() string {
	return f.message
}

// ThinkingElapsed returns the time elapsed since entering StateThinking.
// Returns zero if not currently in StateThinking.
func (f *SpinnerFSM) ThinkingElapsed() time.Duration {
	if f.state == StateThinking {
		return time.Since(f.thinkingStart)
	}
	return 0
}

// SetLastTool sets the last tool key for dedup tracking.
func (f *SpinnerFSM) SetLastTool(key string) {
	f.lastTool = key
}

// LastTool returns the last tool key.
func (f *SpinnerFSM) LastTool() string {
	return f.lastTool
}

// Reset sets the FSM back to StateIdle and clears all fields.
func (f *SpinnerFSM) Reset() {
	f.state = StateIdle
	f.message = ""
	f.thinkingStart = time.Time{}
	f.lastTool = ""
}
