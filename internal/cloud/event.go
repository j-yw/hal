package cloud

import (
	"fmt"
	"time"
)

// Event represents a durable, append-only event in a run timeline.
type Event struct {
	ID          string    `json:"id"`
	RunID       string    `json:"run_id"`
	AttemptID   *string   `json:"attempt_id,omitempty"`
	EventType   string    `json:"event_type"`
	PayloadJSON *string   `json:"payload_json,omitempty"`
	Redacted    bool      `json:"redacted"`
	CreatedAt   time.Time `json:"created_at"`
}

// Validate checks that all required fields are set.
func (e *Event) Validate() error {
	if e.ID == "" {
		return fmt.Errorf("event.id must not be empty")
	}
	if e.RunID == "" {
		return fmt.Errorf("event.run_id must not be empty")
	}
	if e.EventType == "" {
		return fmt.Errorf("event.event_type must not be empty")
	}
	return nil
}

// EventsSchema is the SQL DDL for the events table.
const EventsSchema = `CREATE TABLE IF NOT EXISTS events (
    id           TEXT PRIMARY KEY,
    run_id       TEXT NOT NULL REFERENCES runs(id),
    attempt_id   TEXT REFERENCES attempts(id),
    event_type   TEXT NOT NULL,
    payload_json TEXT,
    redacted     INTEGER NOT NULL DEFAULT 0,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

// EventsRunIDCreatedAtIndex is the SQL DDL for the index on (run_id, created_at).
const EventsRunIDCreatedAtIndex = `CREATE INDEX IF NOT EXISTS idx_events_run_id_created_at ON events (run_id, created_at);`

// EventsPreventUpdate is a SQL trigger that prevents UPDATE on events rows.
const EventsPreventUpdate = `CREATE TRIGGER IF NOT EXISTS events_prevent_update
    BEFORE UPDATE ON events
    BEGIN
        SELECT RAISE(ABORT, 'events rows are immutable: UPDATE not allowed');
    END;`

// EventsPreventDelete is a SQL trigger that prevents DELETE on events rows.
const EventsPreventDelete = `CREATE TRIGGER IF NOT EXISTS events_prevent_delete
    BEFORE DELETE ON events
    BEGIN
        SELECT RAISE(ABORT, 'events rows are immutable: DELETE not allowed');
    END;`
