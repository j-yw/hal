package cloud

import (
	"strings"
	"testing"
	"time"
)

func validEvent() Event {
	return Event{
		ID:        "evt-001",
		RunID:     "run-001",
		EventType: "sandbox_created",
		CreatedAt: time.Now(),
	}
}

func TestEvent_Validate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(e *Event)
		wantErr string
	}{
		{
			name:   "valid event passes",
			modify: func(e *Event) {},
		},
		{
			name:    "empty id",
			modify:  func(e *Event) { e.ID = "" },
			wantErr: "event.id must not be empty",
		},
		{
			name:    "empty run_id",
			modify:  func(e *Event) { e.RunID = "" },
			wantErr: "event.run_id must not be empty",
		},
		{
			name:    "empty event_type",
			modify:  func(e *Event) { e.EventType = "" },
			wantErr: "event.event_type must not be empty",
		},
		{
			name: "valid with all optional fields",
			modify: func(e *Event) {
				aid := "attempt-001"
				payload := `{"key":"value"}`
				e.AttemptID = &aid
				e.PayloadJSON = &payload
				e.Redacted = true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := validEvent()
			tt.modify(&e)
			err := e.Validate()

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestEvent_OptionalFields(t *testing.T) {
	e := validEvent()
	if e.AttemptID != nil {
		t.Error("AttemptID should be nil by default")
	}
	if e.PayloadJSON != nil {
		t.Error("PayloadJSON should be nil by default")
	}
	if e.Redacted {
		t.Error("Redacted should be false by default")
	}

	aid := "attempt-001"
	payload := `{"detail":"sandbox provisioned"}`
	e.AttemptID = &aid
	e.PayloadJSON = &payload
	e.Redacted = true

	if err := e.Validate(); err != nil {
		t.Fatalf("valid event with optional fields set: unexpected error: %v", err)
	}
}

func TestEventsSchema_ContainsRequiredColumns(t *testing.T) {
	requiredColumns := []string{
		"id",
		"run_id",
		"attempt_id",
		"event_type",
		"payload_json",
		"redacted",
		"created_at",
	}

	for _, col := range requiredColumns {
		if !strings.Contains(EventsSchema, col) {
			t.Errorf("EventsSchema missing column %q", col)
		}
	}
}

func TestEventsSchema_ForeignKeys(t *testing.T) {
	if !strings.Contains(EventsSchema, "REFERENCES runs(id)") {
		t.Error("EventsSchema missing foreign key reference to runs(id)")
	}
	if !strings.Contains(EventsSchema, "REFERENCES attempts(id)") {
		t.Error("EventsSchema missing foreign key reference to attempts(id)")
	}
}

func TestEventsRunIDCreatedAtIndex(t *testing.T) {
	want := []string{"idx_events_run_id_created_at", "run_id", "created_at"}
	for _, w := range want {
		if !strings.Contains(EventsRunIDCreatedAtIndex, w) {
			t.Errorf("EventsRunIDCreatedAtIndex missing %q", w)
		}
	}
}

func TestEventsPreventUpdate(t *testing.T) {
	if !strings.Contains(EventsPreventUpdate, "BEFORE UPDATE ON events") {
		t.Error("EventsPreventUpdate must be a BEFORE UPDATE trigger on events")
	}
	if !strings.Contains(EventsPreventUpdate, "RAISE(ABORT") {
		t.Error("EventsPreventUpdate must use RAISE(ABORT) to prevent updates")
	}
}

func TestEventsPreventDelete(t *testing.T) {
	if !strings.Contains(EventsPreventDelete, "BEFORE DELETE ON events") {
		t.Error("EventsPreventDelete must be a BEFORE DELETE trigger on events")
	}
	if !strings.Contains(EventsPreventDelete, "RAISE(ABORT") {
		t.Error("EventsPreventDelete must use RAISE(ABORT) to prevent deletes")
	}
}

func TestEventsImmutabilityTriggers_Messages(t *testing.T) {
	if !strings.Contains(EventsPreventUpdate, "immutable") {
		t.Error("EventsPreventUpdate error message should mention immutability")
	}
	if !strings.Contains(EventsPreventDelete, "immutable") {
		t.Error("EventsPreventDelete error message should mention immutability")
	}
}
