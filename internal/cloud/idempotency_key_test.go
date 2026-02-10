package cloud

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func validIdempotencyKey() IdempotencyKey {
	return IdempotencyKey{
		Key:            "pr-create:run-001:repo/main",
		RunID:          "run-001",
		SideEffectType: "pr_create",
		CreatedAt:      time.Now(),
	}
}

func TestIdempotencyKey_Validate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(k *IdempotencyKey)
		wantErr string
	}{
		{
			name:   "valid key passes",
			modify: func(k *IdempotencyKey) {},
		},
		{
			name:    "empty key",
			modify:  func(k *IdempotencyKey) { k.Key = "" },
			wantErr: "idempotency_key.key must not be empty",
		},
		{
			name:    "empty run_id",
			modify:  func(k *IdempotencyKey) { k.RunID = "" },
			wantErr: "idempotency_key.run_id must not be empty",
		},
		{
			name:    "empty side_effect_type",
			modify:  func(k *IdempotencyKey) { k.SideEffectType = "" },
			wantErr: "idempotency_key.side_effect_type must not be empty",
		},
		{
			name: "valid with result_ref",
			modify: func(k *IdempotencyKey) {
				ref := "https://github.com/org/repo/pull/42"
				k.ResultRef = &ref
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := validIdempotencyKey()
			tt.modify(&k)
			err := k.Validate()

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

func TestIdempotencyKey_OptionalFields(t *testing.T) {
	k := validIdempotencyKey()
	if k.ResultRef != nil {
		t.Error("ResultRef should be nil by default")
	}

	ref := "https://github.com/org/repo/pull/42"
	k.ResultRef = &ref

	if err := k.Validate(); err != nil {
		t.Fatalf("valid key with optional fields set: unexpected error: %v", err)
	}
}

func TestIdempotencyKeysSchema_ContainsRequiredColumns(t *testing.T) {
	requiredColumns := []string{
		"key",
		"run_id",
		"side_effect_type",
		"result_ref",
		"created_at",
	}

	for _, col := range requiredColumns {
		if !strings.Contains(IdempotencyKeysSchema, col) {
			t.Errorf("IdempotencyKeysSchema missing column %q", col)
		}
	}
}

func TestIdempotencyKeysSchema_UniqueKey(t *testing.T) {
	if !strings.Contains(IdempotencyKeysSchema, "PRIMARY KEY") {
		t.Error("IdempotencyKeysSchema must enforce unique constraint on key (via PRIMARY KEY)")
	}
}

func TestIdempotencyKeysSchema_ForeignKeys(t *testing.T) {
	if !strings.Contains(IdempotencyKeysSchema, "REFERENCES runs(id)") {
		t.Error("IdempotencyKeysSchema missing foreign key reference to runs(id)")
	}
}

func TestErrDuplicateKey(t *testing.T) {
	if ErrDuplicateKey == nil {
		t.Fatal("ErrDuplicateKey must not be nil")
	}
	if ErrDuplicateKey.Error() != "duplicate_key" {
		t.Errorf("ErrDuplicateKey.Error() = %q, want %q", ErrDuplicateKey.Error(), "duplicate_key")
	}
}

func TestIsDuplicateKey(t *testing.T) {
	if !IsDuplicateKey(ErrDuplicateKey) {
		t.Error("IsDuplicateKey(ErrDuplicateKey) should return true")
	}
	if IsDuplicateKey(nil) {
		t.Error("IsDuplicateKey(nil) should return false")
	}
	if IsDuplicateKey(fmt.Errorf("some other error")) {
		t.Error("IsDuplicateKey(other error) should return false")
	}
}
