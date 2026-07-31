//go:build linux

package linuxtopology

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestLinuxTopologyRestartReconcilesExactRecordedHelper(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	boundary := &execBoundary{}
	handle, err := boundary.Start(context.Background(), ProcessSpec{
		Role: ProcessRoleKeeper, Path: sleep, Args: []string{"30"}, OutputLimit: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = handle.Terminate(ctx)
	})

	store, err := newFileOwnershipStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	oldIdentity := testIdentity("topology-gen-restart-old")
	oldLease, err := store.acquire(context.Background(), oldIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if err := oldLease.Record(context.Background(), handle, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := oldLease.Release(); err != nil {
		t.Fatal(err)
	}

	newIdentity := testIdentity("topology-gen-restart-new")
	newIdentity.ExecutionID = "execution-restart-new"
	newIdentity.ProxyGenerationID = "proxy-generation-restart-new"
	newLease, err := store.acquire(context.Background(), newIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := newLease.Release(); err != nil {
			t.Errorf("release reconciler lease: %v", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := newLease.Reconcile(ctx); err != nil {
		t.Fatalf("reconcile exact recorded helper: %v", err)
	}
	select {
	case <-handle.Done():
	case <-time.After(time.Second):
		t.Fatal("recorded helper remained alive after reconciliation")
	}
	if _, err := store.acquire(context.Background(), oldIdentity); !errors.Is(err, ErrTopologyCollision) {
		// The new-generation lease intentionally still holds the per-sandbox lock.
		t.Fatalf("old generation while locked error = %v, want ErrTopologyCollision", err)
	}
	if err := newLease.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.acquire(context.Background(), oldIdentity); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("reconciled generation error = %v, want ErrStaleGeneration", err)
	}
}

func TestLinuxTopologyRestartJournalRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	store, err := newFileOwnershipStore(root)
	if err != nil {
		t.Fatal(err)
	}
	identity := testIdentity("topology-gen-symlink")
	lease, err := store.acquire(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lease.Release(); err != nil {
			t.Errorf("release symlink-test lease: %v", err)
		}
	}()
	target := filepath.Join(root, "outside-journal")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, lease.journalPath); err != nil {
		t.Fatal(err)
	}
	if err := lease.Reconcile(context.Background()); !errors.Is(err, ErrStaleTopologyUnverified) {
		t.Fatalf("symlink journal reconciliation error = %v, want ErrStaleTopologyUnverified", err)
	}
}

func TestLinuxTopologyLongRunningCreatorThreadIsRetained(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	boundary := &execBoundary{}
	handle, err := boundary.Start(context.Background(), ProcessSpec{
		Role: ProcessRoleKeeper, Path: sleep, Args: []string{"30"}, OutputLimit: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	probe, ok := handle.(interface {
		creatorThreadState() (int, bool)
		creatorThreadExitTID() int
	})
	if !ok {
		t.Fatal("long-running process handle exposes no creator-thread lifetime proof")
	}
	creatorTID, retained := probe.creatorThreadState()
	if creatorTID <= 0 || !retained {
		t.Fatalf("creator thread state = (%d, %t), want retained", creatorTID, retained)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := handle.Terminate(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		_, retained = probe.creatorThreadState()
		if !retained {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("creator thread remained retained after helper reap")
		}
		time.Sleep(time.Millisecond)
	}
	if exitTID := probe.creatorThreadExitTID(); exitTID != creatorTID {
		t.Fatalf("creator thread changed across helper lifetime: start=%d exit=%d", creatorTID, exitTID)
	}
}

func TestLinuxTopologyArmedMappingJournalBlocksLiveCreatorReconcile(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	store, err := newFileOwnershipStore(root)
	if err != nil {
		t.Fatal(err)
	}
	oldIdentity := testIdentity("topology-gen-armed-old")
	oldLease, err := store.acquire(context.Background(), oldIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := oldLease.Release(); err != nil {
			t.Errorf("release armed-journal owner: %v", err)
		}
	}()
	boundary := &execBoundary{}
	keeper, err := boundary.Start(context.Background(), ProcessSpec{
		Role: ProcessRoleKeeper, Path: sleep, Args: []string{"30"}, OutputLimit: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := keeper.Terminate(ctx); err != nil {
			t.Errorf("terminate armed-journal keeper: %v", err)
		}
	}()
	userFile, err := os.CreateTemp(t.TempDir(), "user-evidence-")
	if err != nil {
		t.Fatal(err)
	}
	netFile, err := os.CreateTemp(t.TempDir(), "net-evidence-")
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := NewNamespaceHandle(userFile, netFile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := namespace.Close(); err != nil {
			t.Errorf("close armed-journal namespace evidence: %v", err)
		}
	}()
	if err := oldLease.ArmMapping(context.Background(), keeper, namespace); err != nil {
		t.Fatal(err)
	}
	payload, err := readPrivateBounded(oldLease.journalPath, maxOutputLimit)
	if err != nil {
		t.Fatal(err)
	}
	var journal privateOwnershipJournal
	if err := json.Unmarshal(payload, &journal); err != nil {
		t.Fatal(err)
	}
	creator, err := currentProcessRecord()
	if err != nil {
		t.Fatal(err)
	}
	if !journal.MappingArmed || journal.MappingCreator == nil || *journal.MappingCreator != *creator || journal.Mapper != nil {
		t.Fatal("armed journal omitted exact private creator containment evidence")
	}
	if err := oldLease.Release(); err != nil {
		t.Fatal(err)
	}

	newIdentity := testIdentity("topology-gen-armed-new")
	newIdentity.ExecutionID = "execution-armed-new"
	newIdentity.ProxyGenerationID = "proxy-generation-armed-new"
	newLease, err := store.acquire(context.Background(), newIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := newLease.Release(); err != nil {
			t.Errorf("release live-creator reconciler: %v", err)
		}
	}()
	if err := newLease.Reconcile(context.Background()); !errors.Is(err, ErrStaleTopologyUnverified) {
		t.Fatalf("live-creator reconciliation error = %v, want ErrStaleTopologyUnverified", err)
	}
	if processDone(keeper) {
		t.Fatal("live-creator reconciliation signalled the armed keeper")
	}
	if _, err := os.Stat(newLease.journalPath); err != nil {
		t.Fatalf("live-creator reconciliation removed recovery journal: %v", err)
	}
	retired := filepath.Join(newLease.dir, "retired-"+oldIdentity.TopologyGenerationID)
	if _, err := os.Stat(retired); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("live-creator reconciliation retired generation: %v", err)
	}
}
