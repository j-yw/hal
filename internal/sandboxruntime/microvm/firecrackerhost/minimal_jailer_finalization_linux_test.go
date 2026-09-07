//go:build linux

package firecrackerhost

import (
	"context"
	"slices"
	"testing"
)

func TestMinimalJailerFinalizationActualPauseThenSameOwnerCommit(t *testing.T) {
	f := newJailerRecoveryWireFixture(t)
	client := f.fresh(t)
	completion, err := client.finalizeMinimalCleanup(context.Background())
	if err != nil || !completion.valid() {
		t.Fatalf("actual selected Finalize: %v", err)
	}
	f.waitConnection()
	if client.socket != nil || client.session != "" || !completion.state.ready || completion.state.active != nil || completion.state.acknowledged {
		t.Fatal("finalization retained a protocol session or invented Commit")
	}
	if !client.mu.TryLock() {
		t.Fatal("client mutex retained across the handoff gap")
	}
	client.mu.Unlock()
	if !completion.state.mu.TryLock() {
		t.Fatal("completion mutex retained across the handoff gap")
	}
	completion.state.mu.Unlock()
	before, err := client.readRecord()
	if err != nil || before.State != "finalized" || before.ControllerState != "unclaimed" {
		t.Fatal("finalized original owner did not survive the closed connection", err)
	}
	if client.stopAndCommit(context.Background()) == nil {
		t.Fatal("selected client migrated back to legacy cleanup")
	}
	// Only the protocol pause is tested. No fixture writer or L7 cleanup is
	// supplied as proof; future production composition must implement those.
	if err := completion.commit(context.Background()); err != nil {
		t.Fatal("same retained client could not commit actual finalization", err)
	}
	f.waitConnection()
	if !completion.state.acknowledged || client.socket != nil || client.session != "" {
		t.Fatal("exact Commit ACK or joined session disposal missing")
	}
	if _, err := f.owned.store.Load(context.Background()); err == nil || !f.owned.store.selected.retired {
		t.Fatal("explicit selected Commit failed to retire the actual original record")
	}
	f.mu.Lock()
	operations := slices.Clone(f.operations)
	f.mu.Unlock()
	if !slices.Equal(operations, []uint16{l8RuntimeOwnerOpcodeStopReap, l8RuntimeOwnerOpcodeFinalize, l8RuntimeOwnerOpcodeFinalize, l8RuntimeOwnerOpcodeCommit}) {
		t.Fatalf("unexpected same-owner reconnect transcript: %v", operations)
	}
	if completion.commit(context.Background()) != nil {
		t.Fatal("same original handle lost its actual cached ACK")
	}
	f.mu.Lock()
	unchanged := slices.Equal(operations, f.operations)
	f.mu.Unlock()
	if !unchanged {
		t.Fatal("acknowledged retry inferred success through another exchange")
	}
	if client.close() != nil || completion.commit(context.Background()) == nil {
		t.Fatal("closed completion remained usable")
	}
}

func TestMinimalJailerFinalizationRepeatedFinalizePinsOriginalResult(t *testing.T) {
	f := newJailerRecoveryWireFixture(t)
	client := f.fresh(t)
	first, err := client.finalizeMinimalCleanup(context.Background())
	if err != nil || first == nil {
		t.Fatal("first actual Finalize", err)
	}
	f.waitConnection()
	frozen := first.state.frozen
	second, err := client.finalizeMinimalCleanup(context.Background())
	if err != nil || second != first || second.state.frozen != frozen {
		t.Fatal("repeat Finalize replaced its retained result", err)
	}
	f.waitConnection()
	f.mu.Lock()
	operations := slices.Clone(f.operations)
	f.mu.Unlock()
	if !slices.Equal(operations, []uint16{l8RuntimeOwnerOpcodeStopReap, l8RuntimeOwnerOpcodeFinalize, l8RuntimeOwnerOpcodeFinalize}) {
		t.Fatalf("repeat Finalize restarted or committed cleanup: %v", operations)
	}
	copied := *first // The outer handle has no mutex; its private self is pinned.
	var zero minimalJailerFinalization
	if copied.commit(context.Background()) == nil || zero.commit(context.Background()) == nil || first.commit(nil) == nil {
		t.Fatal("copied/zero handle or nil caller obtained Commit")
	}
}

func TestMinimalJailerFinalizationLegacyAdmissionIsNotMigratable(t *testing.T) {
	for _, admitted := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalid_legacy_calls", true: "admitted_legacy_call"}[admitted], func(t *testing.T) {
			f := newJailerRecoveryWireFixture(t)
			client := f.fresh(t)
			if admitted {
				if client.stopAndCommit(context.Background()) != nil {
					t.Fatal("actual legacy cleanup prerequisite")
				}
				f.waitConnection()
			} else {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if client.stopAndCommit(nil) == nil || client.stopAndCommit(ctx) == nil || client.legacyAdmitted {
					t.Fatal("invalid legacy calls consumed selected admission")
				}
			}
			completion, err := client.finalizeMinimalCleanup(context.Background())
			if admitted {
				if completion != nil || err == nil || client.minimal != nil {
					t.Fatal("admitted legacy cleanup silently migrated to selected route")
				}
			} else {
				if completion == nil || err != nil {
					t.Fatal("invalid legacy calls blocked the first selected admission", err)
				}
				f.waitConnection()
			}
		})
	}
}
