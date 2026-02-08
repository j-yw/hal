package engine

import (
	"testing"
	"time"
)

func TestTransition_ValidTransitions(t *testing.T) {
	tests := []struct {
		name string
		from SpinnerState
		to   SpinnerState
	}{
		{"Idle→Thinking", StateIdle, StateThinking},
		{"Idle→Idle", StateIdle, StateIdle},
		{"Thinking→ToolActivity", StateThinking, StateToolActivity},
		{"Thinking→Completion", StateThinking, StateCompletion},
		{"Thinking→Error", StateThinking, StateError},
		{"ToolActivity→Thinking", StateToolActivity, StateThinking},
		{"ToolActivity→ToolActivity", StateToolActivity, StateToolActivity},
		{"ToolActivity→Completion", StateToolActivity, StateCompletion},
		{"ToolActivity→Error", StateToolActivity, StateError},
		{"Completion→Idle", StateCompletion, StateIdle},
		{"Error→Idle", StateError, StateIdle},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Transition(tt.from, tt.to); err != nil {
				t.Errorf("expected valid transition %s → %s, got error: %v", tt.from, tt.to, err)
			}
		})
	}
}

func TestTransition_InvalidTransitions(t *testing.T) {
	tests := []struct {
		name string
		from SpinnerState
		to   SpinnerState
	}{
		{"Idle→Completion", StateIdle, StateCompletion},
		{"Idle→Error", StateIdle, StateError},
		{"Idle→ToolActivity", StateIdle, StateToolActivity},
		{"Completion→Thinking", StateCompletion, StateThinking},
		{"Completion→ToolActivity", StateCompletion, StateToolActivity},
		{"Completion→Error", StateCompletion, StateError},
		{"Error→Thinking", StateError, StateThinking},
		{"Error→ToolActivity", StateError, StateToolActivity},
		{"Error→Completion", StateError, StateCompletion},
		{"Thinking→Idle", StateThinking, StateIdle},
		{"Thinking→Thinking", StateThinking, StateThinking},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Transition(tt.from, tt.to)
			if err == nil {
				t.Errorf("expected error for invalid transition %s → %s, got nil", tt.from, tt.to)
			}
		})
	}
}

func TestSpinnerState_String(t *testing.T) {
	tests := []struct {
		state SpinnerState
		want  string
	}{
		{StateIdle, "Idle"},
		{StateThinking, "Thinking"},
		{StateToolActivity, "ToolActivity"},
		{StateCompletion, "Completion"},
		{StateError, "Error"},
		{SpinnerState(99), "Unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("SpinnerState(%d).String() = %q, want %q", int(tt.state), got, tt.want)
			}
		})
	}
}

func TestNewSpinnerFSM(t *testing.T) {
	fsm := NewSpinnerFSM()
	if fsm.State() != StateIdle {
		t.Errorf("NewSpinnerFSM().State() = %v, want StateIdle", fsm.State())
	}
	if fsm.Message() != "" {
		t.Errorf("NewSpinnerFSM().Message() = %q, want empty", fsm.Message())
	}
	if fsm.LastTool() != "" {
		t.Errorf("NewSpinnerFSM().LastTool() = %q, want empty", fsm.LastTool())
	}
	if fsm.ThinkingElapsed() != 0 {
		t.Errorf("NewSpinnerFSM().ThinkingElapsed() = %v, want 0", fsm.ThinkingElapsed())
	}
}

func TestFSM_GoTo_UpdatesStateAndMessage(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(f *SpinnerFSM)
		next      SpinnerState
		msg       string
		wantState SpinnerState
		wantMsg   string
		wantErr   bool
	}{
		{
			name:      "Idle to Thinking",
			setup:     nil,
			next:      StateThinking,
			msg:       "thinking...",
			wantState: StateThinking,
			wantMsg:   "thinking...",
		},
		{
			name:      "Thinking to ToolActivity",
			setup:     func(f *SpinnerFSM) { f.GoTo(StateThinking, "think") },
			next:      StateToolActivity,
			msg:       "running tool",
			wantState: StateToolActivity,
			wantMsg:   "running tool",
		},
		{
			name:      "Thinking to Completion",
			setup:     func(f *SpinnerFSM) { f.GoTo(StateThinking, "think") },
			next:      StateCompletion,
			msg:       "done",
			wantState: StateCompletion,
			wantMsg:   "done",
		},
		{
			name:      "Invalid: Idle to Completion",
			setup:     nil,
			next:      StateCompletion,
			msg:       "done",
			wantState: StateIdle,
			wantMsg:   "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsm := NewSpinnerFSM()
			if tt.setup != nil {
				tt.setup(fsm)
			}
			err := fsm.GoTo(tt.next, tt.msg)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if fsm.State() != tt.wantState {
				t.Errorf("state = %v, want %v", fsm.State(), tt.wantState)
			}
			if fsm.Message() != tt.wantMsg {
				t.Errorf("message = %q, want %q", fsm.Message(), tt.wantMsg)
			}
		})
	}
}

func TestFSM_GoTo_ThinkingSetsThinkingStart(t *testing.T) {
	fsm := NewSpinnerFSM()
	before := time.Now()
	if err := fsm.GoTo(StateThinking, "thinking"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	after := time.Now()

	if fsm.thinkingStart.Before(before) || fsm.thinkingStart.After(after) {
		t.Errorf("thinkingStart = %v, want between %v and %v", fsm.thinkingStart, before, after)
	}

	elapsed := fsm.ThinkingElapsed()
	if elapsed <= 0 {
		t.Errorf("ThinkingElapsed() = %v, want > 0", elapsed)
	}
}

func TestFSM_GoTo_NonThinkingDoesNotSetThinkingStart(t *testing.T) {
	fsm := NewSpinnerFSM()
	fsm.GoTo(StateThinking, "think")
	originalStart := fsm.thinkingStart

	fsm.GoTo(StateToolActivity, "tool")
	if fsm.thinkingStart != originalStart {
		t.Errorf("thinkingStart changed on non-Thinking transition: got %v, want %v", fsm.thinkingStart, originalStart)
	}
}

func TestFSM_ThinkingElapsed_ZeroWhenNotThinking(t *testing.T) {
	fsm := NewSpinnerFSM()

	// Idle state
	if elapsed := fsm.ThinkingElapsed(); elapsed != 0 {
		t.Errorf("ThinkingElapsed() in Idle = %v, want 0", elapsed)
	}

	// Move to Thinking then to ToolActivity
	fsm.GoTo(StateThinking, "think")
	fsm.GoTo(StateToolActivity, "tool")
	if elapsed := fsm.ThinkingElapsed(); elapsed != 0 {
		t.Errorf("ThinkingElapsed() in ToolActivity = %v, want 0", elapsed)
	}
}

func TestFSM_LastTool(t *testing.T) {
	fsm := NewSpinnerFSM()
	if fsm.LastTool() != "" {
		t.Errorf("initial LastTool() = %q, want empty", fsm.LastTool())
	}

	fsm.SetLastTool("Read:file.go")
	if got := fsm.LastTool(); got != "Read:file.go" {
		t.Errorf("LastTool() = %q, want %q", got, "Read:file.go")
	}

	fsm.SetLastTool("Write:main.go")
	if got := fsm.LastTool(); got != "Write:main.go" {
		t.Errorf("LastTool() = %q, want %q", got, "Write:main.go")
	}
}

func TestFSM_Reset(t *testing.T) {
	fsm := NewSpinnerFSM()
	fsm.GoTo(StateThinking, "thinking hard")
	fsm.SetLastTool("Read:file.go")

	// Verify pre-conditions
	if fsm.State() != StateThinking {
		t.Fatalf("setup: state = %v, want StateThinking", fsm.State())
	}
	if fsm.Message() == "" {
		t.Fatalf("setup: message should not be empty")
	}
	if fsm.LastTool() == "" {
		t.Fatalf("setup: lastTool should not be empty")
	}
	if fsm.thinkingStart.IsZero() {
		t.Fatalf("setup: thinkingStart should not be zero")
	}

	// Reset
	fsm.Reset()

	if fsm.State() != StateIdle {
		t.Errorf("after Reset(), State() = %v, want StateIdle", fsm.State())
	}
	if fsm.Message() != "" {
		t.Errorf("after Reset(), Message() = %q, want empty", fsm.Message())
	}
	if fsm.LastTool() != "" {
		t.Errorf("after Reset(), LastTool() = %q, want empty", fsm.LastTool())
	}
	if !fsm.thinkingStart.IsZero() {
		t.Errorf("after Reset(), thinkingStart = %v, want zero", fsm.thinkingStart)
	}
	if fsm.ThinkingElapsed() != 0 {
		t.Errorf("after Reset(), ThinkingElapsed() = %v, want 0", fsm.ThinkingElapsed())
	}
}
