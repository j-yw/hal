//go:build linux

package linuxtopology

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fileRecoveryFixture struct {
	store       *fileOwnershipStore
	identity    Identity
	namespace   *NamespaceHandle
	keeper      ProcessHandle
	mapper      ProcessHandle
	journalPath string
}

func newFileRecoveryFixture(t *testing.T) *fileRecoveryFixture {
	t.Helper()
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	boundary := &execBoundary{}
	keeper, err := boundary.Start(context.Background(), ProcessSpec{Role: ProcessRoleKeeper, Path: sleep, Args: []string{"30"}, OutputLimit: 1024})
	if err != nil {
		t.Fatal(err)
	}
	mapper, err := boundary.Start(context.Background(), ProcessSpec{Role: ProcessRoleMapping, Path: sleep, Args: []string{"30"}, OutputLimit: 1024})
	if err != nil {
		terminateTestProcess(t, keeper)
		t.Fatal(err)
	}
	namespace, err := openRecordedTestNamespaces(keeper.PID())
	if err != nil {
		terminateTestProcess(t, mapper)
		terminateTestProcess(t, keeper)
		t.Fatal(err)
	}
	store, err := newFileOwnershipStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identity := testIdentity("topology-gen-hardening")
	lease, err := store.acquire(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Record(context.Background(), keeper, mapper, namespace); err != nil {
		_ = lease.Release()
		t.Fatal(err)
	}
	journalPath := lease.journalPath
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	fixture := &fileRecoveryFixture{store: store, identity: identity, namespace: namespace, keeper: keeper, mapper: mapper, journalPath: journalPath}
	t.Cleanup(func() {
		_ = namespace.Close()
		terminateTestProcess(t, mapper)
		terminateTestProcess(t, keeper)
	})
	return fixture
}

func (f *fileRecoveryFixture) recoveryStore(t *testing.T) RecoveryOwnershipStore {
	t.Helper()
	store, ok := any(f.store).(RecoveryOwnershipStore)
	if !ok {
		t.Fatal("file ownership store exposes no exact recovery claim")
	}
	return store
}

func (f *fileRecoveryFixture) rewriteJournal(t *testing.T, mutate func(map[string]any)) {
	t.Helper()
	payload, err := os.ReadFile(f.journalPath)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatal(err)
	}
	mutate(raw)
	payload, err = json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivateAtomic(f.journalPath, payload); err != nil {
		t.Fatal(err)
	}
}

func assertRecoveryRejectedAndRetained(t *testing.T, fixture *fileRecoveryFixture, identity Identity, namespace *NamespaceHandle) {
	t.Helper()
	recovered, err := fixture.recoveryStore(t).AcquireRecovery(context.Background(), RecoveryRequest{Identity: identity, Namespace: namespace})
	if err == nil {
		if recovered.Namespace != nil {
			_ = recovered.Namespace.Close()
		}
		if recovered.Lease != nil {
			_ = recovered.Lease.Release()
		}
		t.Fatal("unsafe recovery unexpectedly succeeded")
	}
	if !errors.Is(err, ErrStaleTopologyUnverified) && !errors.Is(err, ErrIdentityMismatch) && !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("recovery error = %v, want sanitized fail-closed class", err)
	}
	if namespace == nil || namespace.Closed() {
		t.Fatal("failed recovery consumed caller-owned namespace")
	}
	if _, statErr := os.Lstat(fixture.journalPath); statErr != nil {
		t.Fatalf("failed recovery removed private journal: %v", statErr)
	}
}

func TestLinuxTopologyRecoveryRejectsReleasedLockWrongNamespace(t *testing.T) {
	fixture := newFileRecoveryFixture(t)
	wrong := newFakeNamespaces(t, nil).base
	if wrong.Correlates(fixture.namespace) {
		t.Fatal("wrong-namespace fixture accidentally correlates")
	}
	assertRecoveryRejectedAndRetained(t, fixture, fixture.identity, wrong)
}

func TestLinuxTopologyRecoveryRejectsBootAndProcessIdentityMismatch(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "host boot", mutate: func(raw map[string]any) { raw["hostBootId"] = "00000000-0000-4000-8000-000000000000" }},
		{name: "keeper start time", mutate: func(raw map[string]any) { raw["keeper"].(map[string]any)["startTime"] = "1" }},
		{name: "mapper start time", mutate: func(raw map[string]any) { raw["mapper"].(map[string]any)["startTime"] = "1" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFileRecoveryFixture(t)
			fixture.rewriteJournal(t, test.mutate)
			assertRecoveryRejectedAndRetained(t, fixture, fixture.identity, fixture.namespace)
		})
	}
}

func TestLinuxTopologyRecoveryAcceptsDefinitelyAbsentHelpersWithRetainedNamespace(t *testing.T) {
	fixture := newFileRecoveryFixture(t)
	terminateTestProcess(t, fixture.mapper)
	terminateTestProcess(t, fixture.keeper)
	recovered, err := fixture.recoveryStore(t).AcquireRecovery(context.Background(), RecoveryRequest{Identity: fixture.identity, Namespace: fixture.namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Namespace.Close()
	defer recovered.Lease.Release()
	if recovered.Keeper != nil || recovered.Mapper != nil || recovered.Namespace == nil || !recovered.Namespace.Correlates(fixture.namespace) {
		t.Fatalf("absent recovery = keeper %T mapper %T namespace %T", recovered.Keeper, recovered.Mapper, recovered.Namespace)
	}
}

func TestLinuxTopologyRecoveryRejectsIncompleteOrAmbiguousJournal(t *testing.T) {
	for _, test := range []struct {
		name    string
		mutate  func(map[string]any)
		rewrite func([]byte) []byte
	}{
		{name: "missing mapper", mutate: func(raw map[string]any) { delete(raw, "mapper") }},
		{name: "mapping armed", mutate: func(raw map[string]any) {
			raw["mappingArmed"] = true
			raw["mappingCreator"] = raw["keeper"]
		}},
		{name: "malformed", rewrite: func([]byte) []byte { return []byte(`{"version":`) }},
		{name: "duplicate key", rewrite: func(payload []byte) []byte {
			marker := []byte(`"version":`)
			at := bytes.Index(payload, marker)
			if at < 0 {
				return payload
			}
			end := at + len(marker)
			for end < len(payload) && payload[end] >= '0' && payload[end] <= '9' {
				end++
			}
			return append(append(append([]byte(nil), payload[:end]...), []byte(`,"version":`)...), append(payload[at+len(marker):end], payload[end:]...)...)
		}},
		{name: "case variant", rewrite: func(payload []byte) []byte {
			return bytes.Replace(payload, []byte(`"version"`), []byte(`"Version"`), 1)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFileRecoveryFixture(t)
			if test.mutate != nil {
				fixture.rewriteJournal(t, test.mutate)
			} else {
				payload, err := os.ReadFile(fixture.journalPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := writePrivateAtomic(fixture.journalPath, test.rewrite(payload)); err != nil {
					t.Fatal(err)
				}
			}
			assertRecoveryRejectedAndRetained(t, fixture, fixture.identity, fixture.namespace)
		})
	}
}

func TestLinuxTopologyRecoveryRejectsStaleCompleteIdentity(t *testing.T) {
	for _, mutate := range []func(*Identity){
		func(identity *Identity) { identity.ExecutionID = "execution-replaced" },
		func(identity *Identity) { identity.TopologyGenerationID = "topology-gen-replaced" },
	} {
		fixture := newFileRecoveryFixture(t)
		identity := fixture.identity
		mutate(&identity)
		assertRecoveryRejectedAndRetained(t, fixture, identity, fixture.namespace)
	}
}

func TestLinuxTopologyRecoveryRejectsUnsafeJournalFile(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *fileRecoveryFixture)
	}{
		{name: "mode", mutate: func(t *testing.T, fixture *fileRecoveryFixture) {
			if err := os.Chmod(fixture.journalPath, 0o640); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlink", mutate: func(t *testing.T, fixture *fileRecoveryFixture) {
			payload, err := os.ReadFile(fixture.journalPath)
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(filepath.Dir(filepath.Dir(fixture.journalPath)), "outside.json")
			if err := os.WriteFile(target, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(fixture.journalPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, fixture.journalPath); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "nonregular", mutate: func(t *testing.T, fixture *fileRecoveryFixture) {
			if err := os.Remove(fixture.journalPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(fixture.journalPath, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFileRecoveryFixture(t)
			test.mutate(t, fixture)
			assertRecoveryRejectedAndRetained(t, fixture, fixture.identity, fixture.namespace)
		})
	}
}

func TestLinuxTopologyRecoverySourceRetainsPrivateOwnerAndPIDFDGuards(t *testing.T) {
	payload, err := os.ReadFile("ownership_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, required := range []string{
		"AcquireRecovery", "stat.Uid != uint32(os.Geteuid())", "sysPIDFDOpen", "readProcessStartTime",
		"recordedNamespaceMatches", "HostBootID", "DisallowUnknownFields",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("production recovery source lacks %q", required)
		}
	}
}

type serializedRecoveryStore struct {
	base       *memoryOwnershipStore
	entered    chan struct{}
	release    chan struct{}
	once       sync.Once
	mu         sync.Mutex
	recoveries int
}

func newSerializedRecoveryStore() *serializedRecoveryStore {
	return &serializedRecoveryStore{base: newMemoryOwnershipStore(), entered: make(chan struct{}), release: make(chan struct{})}
}

func (s *serializedRecoveryStore) Acquire(ctx context.Context, identity Identity) (OwnershipLease, error) {
	return s.base.Acquire(ctx, identity)
}

func (s *serializedRecoveryStore) AcquireRecovery(ctx context.Context, request RecoveryRequest) (RecoveredOwnership, error) {
	s.mu.Lock()
	s.recoveries++
	s.mu.Unlock()
	s.once.Do(func() { close(s.entered) })
	select {
	case <-s.release:
	case <-ctx.Done():
		return RecoveredOwnership{}, ctx.Err()
	}
	lease, err := s.base.Acquire(ctx, request.Identity)
	if err != nil {
		return RecoveredOwnership{}, err
	}
	namespace, err := request.Namespace.Duplicate()
	if err != nil {
		_ = lease.Release()
		return RecoveredOwnership{}, err
	}
	return RecoveredOwnership{Lease: lease, Namespace: namespace}, nil
}

func (s *serializedRecoveryStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recoveries
}

func newSerializedRecoveryLifecycle(t *testing.T, store OwnershipStore) (*Lifecycle, *NamespaceHandle) {
	t.Helper()
	starter := newFakeStarter()
	namespaces := newFakeNamespaces(t, &starter.events)
	lifecycle, err := New(Config{Enabled: true, Tools: testTools(), Starter: starter,
		Runner: &fakeRunner{output: goodLinkJSON()}, OpenNamespaces: namespaces.Open,
		Reachability: &fakeReachabilityProber{}, Ownership: store,
		CleanupTimeout: 250 * time.Millisecond, InspectionTimeout: 250 * time.Millisecond,
		InspectionInterval: time.Millisecond, OutputLimit: 8 << 10})
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := namespaces.base.Duplicate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = namespace.Close() })
	return lifecycle, namespace
}

func TestLinuxTopologySerializesStartAgainstRecovery(t *testing.T) {
	store := newSerializedRecoveryStore()
	lifecycle, namespace := newSerializedRecoveryLifecycle(t, store)
	identity := testIdentity("topology-gen-serialized-start")
	recovered := make(chan error, 1)
	go func() {
		_, err := lifecycle.Recover(context.Background(), RecoveryRequest{Identity: identity, Namespace: namespace})
		recovered <- err
	}()
	select {
	case <-store.entered:
	case err := <-recovered:
		t.Fatalf("Recover returned before ownership claim: %v", err)
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Recover did not enter ownership claim")
	}
	started := make(chan error, 1)
	go func() {
		request := testRequest(identity.TopologyGenerationID)
		_, err := lifecycle.Start(context.Background(), request)
		started <- err
	}()
	select {
	case err := <-started:
		t.Fatalf("Start bypassed same-sandbox recovery: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(store.release)
	if err := <-recovered; err != nil {
		t.Fatal(err)
	}
	if err := <-started; err == nil {
		t.Fatal("Start replaced recovered cleanup authority")
	}
	_, _ = lifecycle.Stop(context.Background(), identity)
}

func TestLinuxTopologySerializesAndCoalescesExactRecovery(t *testing.T) {
	store := newSerializedRecoveryStore()
	lifecycle, namespace := newSerializedRecoveryLifecycle(t, store)
	identity := testIdentity("topology-gen-serialized-recover")
	type result struct {
		session *Session
		err     error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			session, err := lifecycle.Recover(context.Background(), RecoveryRequest{Identity: identity, Namespace: namespace})
			results <- result{session: session, err: err}
		}()
	}
	select {
	case <-store.entered:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Recover did not enter ownership claim")
	}
	close(store.release)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.session == nil || first.session != second.session {
		t.Fatalf("coalesced recovery = (%T,%v) (%T,%v)", first.session, first.err, second.session, second.err)
	}
	if store.count() != 1 {
		t.Fatalf("durable recovery claims = %d, want one", store.count())
	}
	_, _ = lifecycle.Stop(context.Background(), identity)
}

type typedNilRecoveryStore struct{}

func (*typedNilRecoveryStore) Acquire(context.Context, Identity) (OwnershipLease, error) {
	panic("typed-nil ownership store called")
}
func (*typedNilRecoveryStore) AcquireRecovery(context.Context, RecoveryRequest) (RecoveredOwnership, error) {
	panic("typed-nil recovery store called")
}

func TestLinuxTopologyRecoverRejectsTypedNilStoreAndPreservesCallerNamespace(t *testing.T) {
	var store *typedNilRecoveryStore
	lifecycle, namespace := newSerializedRecoveryLifecycle(t, store)
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("Recover panicked through typed-nil store: %v", recovered)
		}
	}()
	if session, err := lifecycle.Recover(context.Background(), RecoveryRequest{Identity: testIdentity("topology-gen-typed-nil"), Namespace: namespace}); session != nil || !errors.Is(err, ErrStaleTopologyUnverified) {
		t.Fatalf("Recover(typed nil) = %T, %v", session, err)
	}
	if namespace.Closed() {
		t.Fatal("typed-nil failure consumed caller namespace")
	}
}
