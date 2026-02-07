package engine

import "fmt"

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
