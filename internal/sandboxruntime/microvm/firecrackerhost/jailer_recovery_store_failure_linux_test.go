//go:build linux

package firecrackerhost

import (
	"context"
	"io"
	"testing"
)

func TestJailerRecoveryStoreUncertainReadCannotBeRestoredIntoAuthority(t *testing.T) {
	f := newJailerRecoveryWireFixture(t)
	store := f.owned.store
	file := store.selected.file
	payload, err := io.ReadAll(io.NewSectionReader(file, 0, l8RuntimeOwnerRecordLimit+1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("!"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background()); err == nil {
		t.Fatal("corrupt retained record accepted")
	}
	if _, err := file.WriteAt(payload, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background()); err == nil || !store.selected.poisoned {
		t.Fatal("restored bytes cleared uncertain record quarantine")
	}
	if store.selected.terminal || f.owned.selected.coordinator.generation == nil {
		t.Fatal("uncertain read released resource authority")
	}
}

func TestJailerRecoveryCommitRetiresExactRecordHandle(t *testing.T) {
	f := newJailerRecoveryWireFixture(t)
	client := f.fresh(t)
	if err := client.stopAndCommit(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitConnection()
	if !f.owned.store.selected.retired || f.owned.store.selected.file != nil {
		t.Fatal("committed selected record descriptor not retired")
	}
}

func TestJailerRecoveryStarterCloseErrorStaysHandleLocal(t *testing.T) {
	f := newJailerRecoveryWireFixture(t)
	starter := f.owned.selected.starter
	if err := starter.gate.Close(); err != nil {
		t.Fatal(err)
	}
	if err := starter.close(); err == nil {
		t.Fatal("closed descriptor failure lost")
	}
	if err := starter.close(); err == nil {
		t.Fatal("retry invented successful descriptor cleanup")
	}
}
