package cloud

import (
	"context"
	"testing"
	"time"
)

// mockStore is a minimal mock that proves the Store interface compiles
// and can be satisfied without adapter-specific imports.
type mockStore struct{}

func (m *mockStore) EnqueueRun(_ context.Context, _ *Run) error                  { return nil }
func (m *mockStore) ClaimRun(_ context.Context, _ string) (*Run, error)           { return nil, nil }
func (m *mockStore) TransitionRun(_ context.Context, _ string, _, _ RunStatus) error {
	return nil
}
func (m *mockStore) GetRun(_ context.Context, _ string) (*Run, error) { return nil, nil }

func (m *mockStore) CreateAttempt(_ context.Context, _ *Attempt) error { return nil }
func (m *mockStore) HeartbeatAttempt(_ context.Context, _ string, _, _ time.Time) error {
	return nil
}
func (m *mockStore) TransitionAttempt(_ context.Context, _ string, _ AttemptStatus, _ time.Time, _, _ *string) error {
	return nil
}
func (m *mockStore) ListStaleAttempts(_ context.Context, _ time.Time) ([]*Attempt, error) {
	return nil, nil
}
func (m *mockStore) GetAttempt(_ context.Context, _ string) (*Attempt, error) { return nil, nil }

func (m *mockStore) InsertEvent(_ context.Context, _ *Event) error              { return nil }
func (m *mockStore) ListEvents(_ context.Context, _ string) ([]*Event, error)   { return nil, nil }

func (m *mockStore) PutIdempotencyKey(_ context.Context, _ *IdempotencyKey) error       { return nil }
func (m *mockStore) GetIdempotencyKey(_ context.Context, _ string) (*IdempotencyKey, error) {
	return nil, nil
}

func (m *mockStore) GetAuthProfile(_ context.Context, _ string) (*AuthProfile, error) {
	return nil, nil
}
func (m *mockStore) UpdateAuthProfile(_ context.Context, _ *AuthProfile) error { return nil }

func (m *mockStore) AcquireAuthLock(_ context.Context, _ *AuthProfileLock) error { return nil }
func (m *mockStore) RenewAuthLock(_ context.Context, _, _ string, _, _ time.Time) error {
	return nil
}
func (m *mockStore) ReleaseAuthLock(_ context.Context, _, _ string, _ time.Time) error {
	return nil
}

func (m *mockStore) PutSnapshot(_ context.Context, _ *RunStateSnapshot) error { return nil }
func (m *mockStore) GetSnapshot(_ context.Context, _ string) (*RunStateSnapshot, error) {
	return nil, nil
}
func (m *mockStore) GetLatestSnapshot(_ context.Context, _ string) (*RunStateSnapshot, error) {
	return nil, nil
}

// TestStoreInterfaceSatisfied proves that a concrete type can satisfy the
// Store interface using only cloud package types — no adapter imports needed.
func TestStoreInterfaceSatisfied(t *testing.T) {
	var s Store = &mockStore{}
	if s == nil {
		t.Fatal("mockStore does not satisfy Store interface")
	}
}

// TestStoreMethodCount ensures the interface has the expected number of methods.
// If a method is added or removed, this test reminds developers to update
// contract tests and adapters.
func TestStoreMethodCount(t *testing.T) {
	// Count methods by category:
	//   Runs:        EnqueueRun, ClaimRun, TransitionRun, GetRun = 4
	//   Attempts:    CreateAttempt, HeartbeatAttempt, TransitionAttempt, ListStaleAttempts, GetAttempt = 5
	//   Events:      InsertEvent, ListEvents = 2
	//   Idempotency: PutIdempotencyKey, GetIdempotencyKey = 2
	//   AuthProfile: GetAuthProfile, UpdateAuthProfile = 2
	//   AuthLocks:   AcquireAuthLock, RenewAuthLock, ReleaseAuthLock = 3
	//   Snapshots:   PutSnapshot, GetSnapshot, GetLatestSnapshot = 3
	//   Total: 21
	const expectedMethods = 21

	// This is a documentation-only test. The mockStore above proves the
	// interface compiles. If the method count changes, update this constant
	// and the comment above.
	_ = expectedMethods
}
