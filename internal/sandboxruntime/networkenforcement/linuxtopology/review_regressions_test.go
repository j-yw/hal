package linuxtopology

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type flakyMapperOwnershipStore struct {
	base  *memoryOwnershipStore
	lease *flakyMapperOwnershipLease
}

type flakyMapperOwnershipLease struct {
	OwnershipLease
	mapperAttempts int
	mapperDurable  bool
}

type retireFailOwnershipStore struct {
	base  *memoryOwnershipStore
	lease *retireFailOwnershipLease
}

type retireFailOwnershipLease struct {
	OwnershipLease
	failRetire bool
	released   bool
}

type persistentMapperRecordFailureStore struct {
	base  *memoryOwnershipStore
	lease *persistentMapperRecordFailureLease
}

type persistentMapperRecordFailureLease struct {
	OwnershipLease
	mappingArmed bool
}

func (s *persistentMapperRecordFailureStore) Acquire(ctx context.Context, identity Identity) (OwnershipLease, error) {
	lease, err := s.base.Acquire(ctx, identity)
	if err != nil {
		return nil, err
	}
	s.lease = &persistentMapperRecordFailureLease{OwnershipLease: lease}
	return s.lease, nil
}

func (l *persistentMapperRecordFailureLease) ArmMapping(context.Context, ProcessHandle, *NamespaceHandle) error {
	l.mappingArmed = true
	return nil
}

func (l *persistentMapperRecordFailureLease) Record(ctx context.Context, keeper, mapper ProcessHandle, namespace *NamespaceHandle) error {
	if mapper != nil {
		return errors.New("persistent mapper journal failure")
	}
	return l.OwnershipLease.Record(ctx, keeper, mapper, namespace)
}

func (s *retireFailOwnershipStore) Acquire(ctx context.Context, identity Identity) (OwnershipLease, error) {
	lease, err := s.base.Acquire(ctx, identity)
	if err != nil {
		return nil, err
	}
	s.lease = &retireFailOwnershipLease{OwnershipLease: lease, failRetire: true}
	return s.lease, nil
}

func (l *retireFailOwnershipLease) Retire(identity Identity) error {
	if l.failRetire {
		return errors.New("retirement unavailable")
	}
	return l.OwnershipLease.Retire(identity)
}

func (l *retireFailOwnershipLease) Release() error {
	l.released = true
	return l.OwnershipLease.Release()
}

func (s *flakyMapperOwnershipStore) Acquire(ctx context.Context, identity Identity) (OwnershipLease, error) {
	lease, err := s.base.Acquire(ctx, identity)
	if err != nil {
		return nil, err
	}
	s.lease = &flakyMapperOwnershipLease{OwnershipLease: lease}
	return s.lease, nil
}

func (l *flakyMapperOwnershipLease) Record(ctx context.Context, keeper, mapper ProcessHandle, namespace *NamespaceHandle) error {
	if mapper != nil {
		l.mapperAttempts++
		if l.mapperAttempts == 1 {
			return errors.New("transient journal failure")
		}
		l.mapperDurable = true
	}
	return l.OwnershipLease.Record(ctx, keeper, mapper, namespace)
}

func TestLinuxTopologyLossRevokesInspectionAndNamespaceTransfer(t *testing.T) {
	starter := newFakeStarter()
	runner := &fakeRunner{output: goodLinkJSON()}
	namespaces := newFakeNamespaces(t, &starter.events)
	lifecycle := newTestLifecycle(t, starter, runner, namespaces)
	session, err := lifecycle.Start(context.Background(), testRequest("topology-gen-loss-revoke"))
	if err != nil {
		t.Fatal(err)
	}
	starter.latest(ProcessRoleMapping).exit()
	select {
	case <-session.Losses():
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for loss")
	}
	if metadata := session.Metadata(); metadata.Status != StatusLost || metadata.StructuralInspected || metadata.MappingReachable {
		t.Fatalf("metadata after loss = %#v, want lost without inspection", metadata)
	}
	if handle, err := session.NamespaceHandle(); !errors.Is(err, ErrStopped) || handle != nil {
		t.Fatalf("NamespaceHandle after loss = %#v, %v", handle, err)
	}
	_, _ = lifecycle.Stop(context.Background(), testIdentity("topology-gen-loss-revoke"))
}

func TestLinuxTopologyStoppedGenerationCannotEverRestart(t *testing.T) {
	starter := newFakeStarter()
	runner := &fakeRunner{output: goodLinkJSON()}
	namespaces := newFakeNamespaces(t, &starter.events)
	lifecycle := newTestLifecycle(t, starter, runner, namespaces)
	request := testRequest("topology-gen-retired")
	if _, err := lifecycle.Start(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.Stop(context.Background(), request.Identity); err != nil {
		t.Fatal(err)
	}
	before := starter.startCount()
	if _, err := lifecycle.Start(context.Background(), request); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("reused generation error = %v, want ErrStaleGeneration", err)
	}
	if got := starter.startCount(); got != before {
		t.Fatalf("reused generation started processes: before=%d after=%d", before, got)
	}
}

func TestLinuxTopologyStopRevokesAndWaitsForNamespaceTransfers(t *testing.T) {
	starter := newFakeStarter()
	runner := &fakeRunner{output: goodLinkJSON()}
	namespaces := newFakeNamespaces(t, &starter.events)
	lifecycle := newTestLifecycle(t, starter, runner, namespaces)
	identity := testIdentity("topology-gen-transfer")
	session, err := lifecycle.Start(context.Background(), testRequest("topology-gen-transfer"))
	if err != nil {
		t.Fatal(err)
	}
	borrowed, err := session.NamespaceHandle()
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, stopErr := lifecycle.Stop(context.Background(), identity)
		result <- stopErr
	}()
	deadline := time.Now().Add(time.Second)
	for session.Metadata().Status != StatusStopping && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if session.Metadata().Status != StatusStopping {
		t.Fatal("stop did not revoke prepared state")
	}
	if handle, err := session.NamespaceHandle(); !errors.Is(err, ErrStopped) || handle != nil {
		t.Fatalf("transfer during stop = %#v, %v", handle, err)
	}
	select {
	case err := <-result:
		t.Fatalf("Stop returned before transferred handle closed: %v", err)
	default:
	}
	if err := borrowed.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop did not continue after transferred handle closed")
	}
}

func TestLinuxTopologyIncompleteRollbackRetainsOwnershipAndBlocksReplacement(t *testing.T) {
	starter := newFakeStarter()
	runner := &fakeRunner{output: []byte(`[]`)}
	namespaces := newFakeNamespaces(t, &starter.events)
	lifecycle := newTestLifecycle(t, starter, runner, namespaces)

	// Force reverse rollback to remain uncertain after structural inspection fails.
	starter.terminateErr[ProcessRoleMapping] = errors.New("uncertain termination")
	session, err := lifecycle.Start(context.Background(), testRequest("topology-gen-incomplete"))
	if !errors.Is(err, ErrCleanupIncomplete) || session == nil {
		t.Fatalf("Start = %#v, %v, want retained session and ErrCleanupIncomplete", session, err)
	}
	if metadata := session.Metadata(); metadata.Status != StatusCleanupIncomplete || metadata.StructuralInspected || metadata.MappingReachable {
		t.Fatalf("retained metadata = %#v", metadata)
	}
	if _, err := lifecycle.Start(context.Background(), testRequest("topology-gen-replacement")); !errors.Is(err, ErrTopologyCollision) {
		t.Fatalf("replacement error = %v, want ErrTopologyCollision", err)
	}
	starter.latest(ProcessRoleMapping).terminateErr = nil
	if _, err := lifecycle.Stop(context.Background(), testIdentity("topology-gen-incomplete")); err != nil {
		t.Fatalf("retry cleanup: %v", err)
	}
}

func TestLinuxTopologyMapperIsDurableBeforeIncompleteRollbackReturns(t *testing.T) {
	starter := newFakeStarter()
	starter.terminateErr[ProcessRoleMapping] = errors.New("uncertain termination")
	runner := &fakeRunner{output: goodLinkJSON()}
	namespaces := newFakeNamespaces(t, &starter.events)
	ownership := &flakyMapperOwnershipStore{base: newMemoryOwnershipStore()}
	lifecycle, err := New(Config{
		Enabled: true, Tools: testTools(), Starter: starter, Runner: runner,
		OpenNamespaces: namespaces.Open, Reachability: &fakeReachabilityProber{}, Ownership: ownership,
		CleanupTimeout: 250 * time.Millisecond, InspectionTimeout: 250 * time.Millisecond,
		InspectionInterval: time.Millisecond, OutputLimit: 8 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := lifecycle.Start(context.Background(), testRequest("topology-gen-journal-retry"))
	if !errors.Is(err, ErrCleanupIncomplete) || session == nil {
		t.Fatalf("Start = %#v, %v, want retained cleanup-incomplete session", session, err)
	}
	if ownership.lease == nil || ownership.lease.mapperAttempts < 2 || !ownership.lease.mapperDurable {
		t.Fatalf("mapper journal attempts=%d durable=%t", ownership.lease.mapperAttempts, ownership.lease.mapperDurable)
	}
	starter.latest(ProcessRoleMapping).terminateErr = nil
	if _, err := lifecycle.Stop(context.Background(), testIdentity("topology-gen-journal-retry")); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxTopologyPersistentMapperRecordFailureIsDurablyArmed(t *testing.T) {
	starter := newFakeStarter()
	starter.terminateErr[ProcessRoleMapping] = errors.New("uncertain termination")
	runner := &fakeRunner{output: goodLinkJSON()}
	namespaces := newFakeNamespaces(t, &starter.events)
	ownership := &persistentMapperRecordFailureStore{base: newMemoryOwnershipStore()}
	lifecycle, err := New(Config{
		Enabled: true, Tools: testTools(), Starter: starter, Runner: runner,
		OpenNamespaces: namespaces.Open, Reachability: &fakeReachabilityProber{}, Ownership: ownership,
		CleanupTimeout: 250 * time.Millisecond, InspectionTimeout: 250 * time.Millisecond,
		InspectionInterval: time.Millisecond, OutputLimit: 8 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := lifecycle.Start(context.Background(), testRequest("topology-gen-persistent-journal"))
	if !errors.Is(err, ErrCleanupIncomplete) || session == nil {
		t.Fatalf("Start = %#v, %v, want retained cleanup-incomplete session", session, err)
	}
	if ownership.lease == nil || !ownership.lease.mappingArmed {
		t.Fatal("live unrecorded mapper returned without durable pre-launch containment evidence")
	}
	starter.latest(ProcessRoleMapping).terminateErr = nil
	if _, err := lifecycle.Stop(context.Background(), testIdentity("topology-gen-persistent-journal")); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxTopologyRetirementFailureRetainsOwnership(t *testing.T) {
	starter := newFakeStarter()
	runner := &fakeRunner{output: goodLinkJSON()}
	namespaces := newFakeNamespaces(t, &starter.events)
	ownership := &retireFailOwnershipStore{base: newMemoryOwnershipStore()}
	lifecycle, err := New(Config{
		Enabled: true, Tools: testTools(), Starter: starter, Runner: runner,
		OpenNamespaces: namespaces.Open, Reachability: &fakeReachabilityProber{}, Ownership: ownership,
		CleanupTimeout: 250 * time.Millisecond, InspectionTimeout: 250 * time.Millisecond,
		InspectionInterval: time.Millisecond, OutputLimit: 8 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := testIdentity("topology-gen-retire-failure")
	if _, err := lifecycle.Start(context.Background(), StartRequest{Identity: identity, Mapping: testRequest("topology-gen-retire-failure").Mapping}); err != nil {
		t.Fatal(err)
	}
	if metadata, err := lifecycle.Stop(context.Background(), identity); !errors.Is(err, ErrCleanupIncomplete) || metadata.Status != StatusCleanupIncomplete {
		t.Fatalf("Stop = %#v, %v, want cleanup-incomplete", metadata, err)
	}
	if ownership.lease == nil || ownership.lease.released {
		t.Fatal("retirement failure released ownership")
	}
	ownership.lease.failRetire = false
	if _, err := lifecycle.Stop(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxTopologyFileOwnershipLockAndRetirementAreDurable(t *testing.T) {
	root := t.TempDir()
	store, err := newFileOwnershipStore(root)
	if err != nil {
		t.Fatal(err)
	}
	identity := testIdentity("topology-gen-durable")
	lease, err := store.acquire(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newFileOwnershipStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.acquire(context.Background(), identity); !errors.Is(err, ErrTopologyCollision) {
		t.Fatalf("second acquire error = %v, want ErrTopologyCollision", err)
	}
	if err := lease.retire(identity); err != nil {
		t.Fatal(err)
	}
	if err := lease.release(); err != nil {
		t.Fatal(err)
	}
	if _, err := second.acquire(context.Background(), identity); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("retired acquire error = %v, want ErrStaleGeneration", err)
	}

	sandboxDir := filepath.Join(root, identity.SandboxID)
	info, err := os.Stat(sandboxDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("sandbox state mode = %o, want 700", info.Mode().Perm())
	}
	entries, err := os.ReadDir(sandboxDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().IsRegular() && info.Mode().Perm() != 0o600 {
			t.Fatalf("private state %q mode = %o, want 600", entry.Name(), info.Mode().Perm())
		}
	}
}

func TestLinuxTopologyProductionSourceUsesAtomicCLOEXECAndParentDeath(t *testing.T) {
	duplication, err := os.ReadFile("namespace_dup_unix.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(duplication), "syscall.Dup(") ||
		!strings.Contains(string(duplication), "F_DUPFD_CLOEXEC") ||
		!strings.Contains(string(duplication), "uintptr(3)") {
		t.Fatal("namespace duplication must be atomic CLOEXEC")
	}
	process, err := os.ReadFile("process_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(process), "Pdeathsig") < 2 {
		t.Fatal("production helpers must have parent-death containment")
	}
}
