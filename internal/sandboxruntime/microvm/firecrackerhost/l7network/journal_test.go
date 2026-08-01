package l7network

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFirecrackerHostTopologyJournalIsPrivateAtomicAndGenerationOwned(t *testing.T) {
	root := filepath.Join(t.TempDir(), "topology")
	store, err := newFileJournalStore(root)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.Acquire(context.Background(), testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(root); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("state root mode = %v, %v", info, err)
	}
	record := journalRecord{identity: testIdentity(), stage: journalStageTAPCreated, tapName: "ht0123456789", tapFingerprint: strings.Repeat("a", 64),
		proxyAddress: "192.0.2.2", proxyPort: 43123}
	if err := lease.Save(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, testIdentity().SandboxID, "host-topology.json")
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode = %v, %v", info, err)
	}
	loaded, err := lease.Load()
	if err != nil || !reflect.DeepEqual(loaded, record) {
		t.Fatalf("Load() = %#v, %v", loaded, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".host-topology-") {
			t.Fatalf("atomic temp artifact retained: %s", entry.Name())
		}
	}
	if _, err := store.Acquire(context.Background(), testIdentity()); !errors.Is(err, ErrTopologyCollision) {
		t.Fatalf("second Acquire() = %v, want cross-process collision", err)
	}
	if err := lease.Remove(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Acquire(context.Background(), testIdentity()); !errors.Is(err, ErrStaleTopologyUnverified) {
		t.Fatalf("retired generation Acquire() = %v", err)
	}
}

func TestFirecrackerHostTopologyJournalCorruptionFailsClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "topology")
	store, err := newFileJournalStore(root)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.Acquire(context.Background(), testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, testIdentity().SandboxID, "host-topology.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"identity":{"sandboxId":"unsafe/path"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.Load(); !errors.Is(err, ErrStaleTopologyUnverified) {
		t.Fatalf("corrupt Load() = %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.Load(); !errors.Is(err, ErrStaleTopologyUnverified) {
		t.Fatalf("wrong-mode Load() = %v", err)
	}
	_ = lease.Release()
}

func TestFirecrackerHostTopologyRestartNeverReconstructsInspectedProof(t *testing.T) {
	root := filepath.Join(t.TempDir(), "topology")
	store, err := newFileJournalStore(root)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.Acquire(context.Background(), testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Save(context.Background(), journalRecord{identity: testIdentity(), stage: journalStageProxyStarting}); err != nil {
		t.Fatal(err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	sequence := &callSequence{}
	coordinator := mustCoordinator(t, Options{Enabled: true, Proxy: newFakeProxy(sequence), Topology: newFakeTopology(sequence),
		TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		Journal: store})
	if _, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()}); !errors.Is(err, ErrStaleTopologyUnverified) {
		t.Fatalf("restart Prepare() = %v", err)
	}
	if got := sequence.snapshot(); len(got) != 0 {
		t.Fatalf("restart reconstructed or mutated live state: %#v", got)
	}
}
