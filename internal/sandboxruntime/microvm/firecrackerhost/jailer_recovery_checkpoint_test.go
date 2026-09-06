package firecrackerhost

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// Deliberately fake owner callbacks for pre-existing coordinator unit fixtures.
// Production has no nil/default substitute for a live selected owner store.
func newFakeJailerRecoveryAuthority() *jailerRecoveryAuthority {
	return &jailerRecoveryAuthority{
		current:  func(context.Context, string, string) error { return nil },
		busy:     func(context.Context, *strictJailerIdentityLease) error { return nil },
		terminal: func(context.Context, *strictJailerIdentityLease) error { return nil },
	}
}

func TestJailerRecoveryCoordinatorRequiresBusyAndTerminalCheckpoints(t *testing.T) {
	for _, failAt := range []string{"", "current", "busy", "terminal"} {
		t.Run(failAt, func(t *testing.T) {
			events := []string{}
			lifecycle := &coordinatorFakeLifecycle{events: &events}
			coordinator := coordinatorForStateTest(&events, &coordinatorFakeRoot{events: &events}, lifecycle)
			identity, store := newFakeJailerIdentityAuthority()
			coordinator.deps.identity = identity
			request := validStrictJailerCoordinatorRequest(t)
			step := func(name string) error {
				events = append(events, name)
				if name == failAt {
					return errors.New("checkpoint unavailable")
				}
				return nil
			}
			coordinator.deps.recovery = &jailerRecoveryAuthority{
				current: func(_ context.Context, runtimeID, digest string) error {
					if runtimeID != request.runtimeID || digest != request.config.SHA256 {
						t.Fatal("owner correlation drift")
					}
					return step("current")
				},
				busy: func(ctx context.Context, lease *strictJailerIdentityLease) error {
					if lease == nil || lease.verify(ctx) != nil {
						t.Fatal("busy checkpoint before durable reservation")
					}
					return step("busy")
				},
				terminal: func(ctx context.Context, lease *strictJailerIdentityLease) error {
					if lease == nil || lease.verifyCleanup(ctx) != nil || !slices.Contains(events, "forget") {
						t.Fatal("terminal checkpoint before exact cleanup")
					}
					return step("terminal")
				},
			}
			session, err := coordinator.start(context.Background(), request)
			if failAt == "current" || failAt == "busy" {
				if err == nil || slices.Contains(events, "start") {
					t.Fatalf("failed checkpoint reached start: %v %v", err, events)
				}
			} else {
				if err != nil {
					t.Fatalf("start: %v", err)
				}
				err = coordinator.stop(context.Background(), session)
				if (err != nil) != (failAt == "terminal") {
					t.Fatalf("terminal result %v events %v", err, events)
				}
			}
			record, err := readJailerIdentityRecord(store.snapshot(), identity.slot)
			if err != nil {
				t.Fatal(err)
			}
			if failAt == "terminal" && (record.State != "busy" || coordinator.generation == nil) {
				t.Fatalf("failed terminal checkpoint freed identity: %s", record.State)
			}
			if failAt == "" && (!slices.Contains(events, "busy") || !slices.Contains(events, "terminal") || record.State != "idle") {
				t.Fatalf("required checkpoint missing: %v state %s", events, record.State)
			}
			_ = coordinator.generationIdentityForTest().close()
		})
	}
}
