package cloud

import (
	"fmt"
	"time"
)

// IdempotencyKey represents a persisted idempotency key for external side effects.
type IdempotencyKey struct {
	Key            string    `json:"key"`
	RunID          string    `json:"run_id"`
	SideEffectType string    `json:"side_effect_type"`
	ResultRef      *string   `json:"result_ref,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// Validate checks that all required fields are set.
func (k *IdempotencyKey) Validate() error {
	if k.Key == "" {
		return fmt.Errorf("idempotency_key.key must not be empty")
	}
	if k.RunID == "" {
		return fmt.Errorf("idempotency_key.run_id must not be empty")
	}
	if k.SideEffectType == "" {
		return fmt.Errorf("idempotency_key.side_effect_type must not be empty")
	}
	return nil
}

// ErrDuplicateKey is the domain error returned when an idempotency key already exists.
var ErrDuplicateKey = fmt.Errorf("duplicate_key")

// IsDuplicateKey reports whether err is the duplicate_key domain error.
func IsDuplicateKey(err error) bool {
	return err == ErrDuplicateKey
}

// IdempotencyKeysSchema is the SQL DDL for the idempotency_keys table.
const IdempotencyKeysSchema = `CREATE TABLE IF NOT EXISTS idempotency_keys (
    key              TEXT PRIMARY KEY,
    run_id           TEXT NOT NULL REFERENCES runs(id),
    side_effect_type TEXT NOT NULL,
    result_ref       TEXT,
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);`
