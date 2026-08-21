//go:build linux

package linuxtopology

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
)

type adversarialRecoveryStore struct {
	base    *memoryOwnershipStore
	recover func(context.Context, RecoveryRequest) (RecoveredOwnership, error)
}

func (s *adversarialRecoveryStore) Acquire(ctx context.Context, identity Identity) (OwnershipLease, error) {
	return s.base.Acquire(ctx, identity)
}
func (s *adversarialRecoveryStore) AcquireRecovery(ctx context.Context, request RecoveryRequest) (RecoveredOwnership, error) {
	return s.recover(ctx, request)
}

type adversarialRecoveryLease struct {
	retireCalls  int
	releaseCalls int
	retireErr    error
	releaseErr   error
	retirePanic  bool
	releasePanic bool
}

func (*adversarialRecoveryLease) Reconcile(context.Context) error { return nil }
func (*adversarialRecoveryLease) Record(context.Context, ProcessHandle, ProcessHandle, *NamespaceHandle) error {
	return nil
}
func (*adversarialRecoveryLease) ArmMapping(context.Context, ProcessHandle, *NamespaceHandle) error {
	return nil
}
func (l *adversarialRecoveryLease) Retire(Identity) error {
	l.retireCalls++
	if l.retirePanic {
		panic("private retire panic")
	}
	return l.retireErr
}
func (l *adversarialRecoveryLease) Release() error {
	l.releaseCalls++
	if l.releasePanic {
		panic("private release panic")
	}
	return l.releaseErr
}

type adversarialRecoveryProcess struct {
	pid            int
	done           chan struct{}
	terminateCalls int
	terminateErr   error
	terminatePanic bool
}

func newAdversarialRecoveryProcess(pid int) *adversarialRecoveryProcess {
	return &adversarialRecoveryProcess{pid: pid, done: make(chan struct{})}
}
func (p *adversarialRecoveryProcess) PID() int { return p.pid }
func (p *adversarialRecoveryProcess) Done() <-chan struct{} {
	if p == nil {
		return nil
	}
	return p.done
}
func (p *adversarialRecoveryProcess) Terminate(context.Context) error {
	p.terminateCalls++
	if p.terminatePanic {
		panic("private process panic")
	}
	return p.terminateErr
}

func newAdversarialRecoveryLifecycle(t *testing.T, store OwnershipStore) (*Lifecycle, *NamespaceHandle) {
	t.Helper()
	return newSerializedRecoveryLifecycle(t, store)
}

func duplicateRecoveryNamespace(t *testing.T, namespace *NamespaceHandle) *NamespaceHandle {
	t.Helper()
	duplicate, err := namespace.Duplicate()
	if err != nil {
		t.Fatal(err)
	}
	return duplicate
}

func callLifecycleRecoverNoPanic(t *testing.T, lifecycle *Lifecycle, request RecoveryRequest) (session *Session, err error) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("Lifecycle.Recover panicked: %v", recovered)
		}
	}()
	return lifecycle.Recover(context.Background(), request)
}

func callLifecycleStopNoPanic(t *testing.T, lifecycle *Lifecycle, identity Identity) (metadata Metadata, err error) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("Lifecycle.Stop panicked: %v", recovered)
		}
	}()
	return lifecycle.Stop(context.Background(), identity)
}

func TestLinuxTopologyRecoveryOwnershipResultMatrix(t *testing.T) {
	privateErr := errors.New("private ownership error")
	for _, test := range []struct {
		name  string
		build func(*testing.T, RecoveryRequest, *adversarialRecoveryLease) (RecoveredOwnership, error)
	}{
		{name: "value plus error", build: func(t *testing.T, request RecoveryRequest, lease *adversarialRecoveryLease) (RecoveredOwnership, error) {
			return RecoveredOwnership{Lease: lease, Namespace: duplicateRecoveryNamespace(t, request.Namespace)}, privateErr
		}},
		{name: "nil lease", build: func(t *testing.T, request RecoveryRequest, _ *adversarialRecoveryLease) (RecoveredOwnership, error) {
			return RecoveredOwnership{Namespace: duplicateRecoveryNamespace(t, request.Namespace)}, nil
		}},
		{name: "typed nil lease", build: func(t *testing.T, request RecoveryRequest, _ *adversarialRecoveryLease) (RecoveredOwnership, error) {
			var lease *adversarialRecoveryLease
			return RecoveredOwnership{Lease: lease, Namespace: duplicateRecoveryNamespace(t, request.Namespace)}, nil
		}},
		{name: "nil namespace", build: func(_ *testing.T, _ RecoveryRequest, lease *adversarialRecoveryLease) (RecoveredOwnership, error) {
			return RecoveredOwnership{Lease: lease}, nil
		}},
		{name: "closed namespace", build: func(t *testing.T, request RecoveryRequest, lease *adversarialRecoveryLease) (RecoveredOwnership, error) {
			namespace := duplicateRecoveryNamespace(t, request.Namespace)
			if err := namespace.Close(); err != nil {
				t.Fatal(err)
			}
			return RecoveredOwnership{Lease: lease, Namespace: namespace}, nil
		}},
		{name: "caller namespace alias", build: func(_ *testing.T, request RecoveryRequest, lease *adversarialRecoveryLease) (RecoveredOwnership, error) {
			return RecoveredOwnership{Lease: lease, Namespace: request.Namespace}, nil
		}},
		{name: "unusable duplicate", build: func(t *testing.T, request RecoveryRequest, lease *adversarialRecoveryLease) (RecoveredOwnership, error) {
			namespace := duplicateRecoveryNamespace(t, request.Namespace)
			namespace.mu.Lock()
			_ = syscall.Close(int(namespace.user.Fd()))
			_ = syscall.Close(int(namespace.network.Fd()))
			namespace.mu.Unlock()
			return RecoveredOwnership{Lease: lease, Namespace: namespace}, nil
		}},
		{name: "typed nil keeper", build: func(t *testing.T, request RecoveryRequest, lease *adversarialRecoveryLease) (RecoveredOwnership, error) {
			var process *adversarialRecoveryProcess
			return RecoveredOwnership{Lease: lease, Keeper: process, Namespace: duplicateRecoveryNamespace(t, request.Namespace)}, nil
		}},
		{name: "duplicate process handle", build: func(t *testing.T, request RecoveryRequest, lease *adversarialRecoveryLease) (RecoveredOwnership, error) {
			process := newAdversarialRecoveryProcess(8101)
			return RecoveredOwnership{Lease: lease, Keeper: process, Mapper: process, Namespace: duplicateRecoveryNamespace(t, request.Namespace)}, nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			lease := &adversarialRecoveryLease{}
			store := &adversarialRecoveryStore{base: newMemoryOwnershipStore()}
			store.recover = func(ctx context.Context, request RecoveryRequest) (RecoveredOwnership, error) {
				return test.build(t, request, lease)
			}
			lifecycle, namespace := newAdversarialRecoveryLifecycle(t, store)
			session, err := callLifecycleRecoverNoPanic(t, lifecycle, RecoveryRequest{Identity: testIdentity("topology-gen-result-matrix"), Namespace: namespace})
			if session != nil || !errors.Is(err, ErrStaleTopologyUnverified) {
				t.Fatalf("Recover(adversarial result) = %T, %v", session, err)
			}
			if namespace.Closed() {
				t.Fatal("adversarial result consumed caller namespace")
			}
			if test.name != "nil lease" && test.name != "typed nil lease" && lease.releaseCalls != 1 {
				t.Fatalf("invalid recovery lease releases = %d, want one", lease.releaseCalls)
			}
		})
	}
}

func TestLinuxTopologyRecoveryStorePanicAndCleanupPanicMatrix(t *testing.T) {
	for _, test := range []struct {
		name    string
		panicAt string
	}{
		{name: "store panic", panicAt: "store"},
		{name: "value error release panic", panicAt: "release"},
	} {
		t.Run(test.name, func(t *testing.T) {
			lease := &adversarialRecoveryLease{releasePanic: test.panicAt == "release"}
			store := &adversarialRecoveryStore{base: newMemoryOwnershipStore()}
			store.recover = func(_ context.Context, request RecoveryRequest) (RecoveredOwnership, error) {
				if test.panicAt == "store" {
					panic("private store panic")
				}
				return RecoveredOwnership{Lease: lease, Namespace: duplicateRecoveryNamespace(t, request.Namespace)}, errors.New("private value error")
			}
			lifecycle, namespace := newAdversarialRecoveryLifecycle(t, store)
			session, err := callLifecycleRecoverNoPanic(t, lifecycle, RecoveryRequest{Identity: testIdentity("topology-gen-panic-matrix"), Namespace: namespace})
			if session != nil || !errors.Is(err, ErrStaleTopologyUnverified) {
				t.Fatalf("Recover(%s) = %T, %v", test.name, session, err)
			}
			if namespace.Closed() {
				t.Fatal("panic path consumed caller namespace")
			}
		})
	}
}

func TestLinuxTopologyRecoveredStopAdversarialMatrix(t *testing.T) {
	privateErr := errors.New("private cleanup error")
	for _, test := range []struct {
		name      string
		configure func(*adversarialRecoveryLease, *adversarialRecoveryProcess)
	}{
		{name: "process error", configure: func(_ *adversarialRecoveryLease, process *adversarialRecoveryProcess) {
			process.terminateErr = privateErr
		}},
		{name: "process panic", configure: func(_ *adversarialRecoveryLease, process *adversarialRecoveryProcess) { process.terminatePanic = true }},
		{name: "retire error", configure: func(lease *adversarialRecoveryLease, _ *adversarialRecoveryProcess) { lease.retireErr = privateErr }},
		{name: "retire panic", configure: func(lease *adversarialRecoveryLease, _ *adversarialRecoveryProcess) { lease.retirePanic = true }},
		{name: "release error", configure: func(lease *adversarialRecoveryLease, _ *adversarialRecoveryProcess) { lease.releaseErr = privateErr }},
		{name: "release panic", configure: func(lease *adversarialRecoveryLease, _ *adversarialRecoveryProcess) { lease.releasePanic = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			lease := &adversarialRecoveryLease{}
			process := newAdversarialRecoveryProcess(8201)
			test.configure(lease, process)
			store := &adversarialRecoveryStore{base: newMemoryOwnershipStore()}
			store.recover = func(_ context.Context, request RecoveryRequest) (RecoveredOwnership, error) {
				return RecoveredOwnership{Lease: lease, Keeper: process, Namespace: duplicateRecoveryNamespace(t, request.Namespace)}, nil
			}
			lifecycle, namespace := newAdversarialRecoveryLifecycle(t, store)
			identity := testIdentity("topology-gen-stop-adversarial")
			session, err := callLifecycleRecoverNoPanic(t, lifecycle, RecoveryRequest{Identity: identity, Namespace: namespace})
			if err != nil || session == nil {
				t.Fatalf("Recover() = %T, %v", session, err)
			}
			metadata, stopErr := callLifecycleStopNoPanic(t, lifecycle, identity)
			if !errors.Is(stopErr, ErrCleanupIncomplete) || metadata.Status != StatusCleanupIncomplete {
				t.Fatalf("Stop(%s) = %#v, %v", test.name, metadata, stopErr)
			}
			if namespace.Closed() {
				t.Fatal("failed Stop consumed caller namespace")
			}
		})
	}
}

func TestLinuxTopologyRecoveredStopRetainsNamespaceCloseFailure(t *testing.T) {
	lease := &adversarialRecoveryLease{}
	store := &adversarialRecoveryStore{base: newMemoryOwnershipStore()}
	store.recover = func(_ context.Context, request RecoveryRequest) (RecoveredOwnership, error) {
		return RecoveredOwnership{Lease: lease, Namespace: duplicateRecoveryNamespace(t, request.Namespace)}, nil
	}
	lifecycle, namespace := newAdversarialRecoveryLifecycle(t, store)
	identity := testIdentity("topology-gen-close-failure")
	session, err := lifecycle.Recover(context.Background(), RecoveryRequest{Identity: identity, Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}
	session.namespace.mu.Lock()
	_ = syscall.Close(int(session.namespace.user.Fd()))
	_ = syscall.Close(int(session.namespace.network.Fd()))
	session.namespace.mu.Unlock()
	metadata, err := callLifecycleStopNoPanic(t, lifecycle, identity)
	if !errors.Is(err, ErrCleanupIncomplete) || metadata.Status != StatusCleanupIncomplete || lease.retireCalls != 0 {
		t.Fatalf("Stop(namespace close failure) = %#v, %v; retire=%d", metadata, err, lease.retireCalls)
	}
	if namespace.Closed() {
		t.Fatal("namespace close failure consumed caller namespace")
	}
}

func TestLinuxTopologyRecoveredStopHandlesNilProcessAsPositiveAbsence(t *testing.T) {
	lease := &adversarialRecoveryLease{}
	store := &adversarialRecoveryStore{base: newMemoryOwnershipStore()}
	store.recover = func(_ context.Context, request RecoveryRequest) (RecoveredOwnership, error) {
		return RecoveredOwnership{Lease: lease, Namespace: duplicateRecoveryNamespace(t, request.Namespace)}, nil
	}
	lifecycle, namespace := newAdversarialRecoveryLifecycle(t, store)
	identity := testIdentity("topology-gen-nil-process")
	if _, err := lifecycle.Recover(context.Background(), RecoveryRequest{Identity: identity, Namespace: namespace}); err != nil {
		t.Fatal(err)
	}
	metadata, err := lifecycle.Stop(context.Background(), identity)
	if err != nil || metadata.Status != StatusStopped || lease.retireCalls != 1 || lease.releaseCalls != 1 {
		t.Fatalf("Stop(absent processes) = %#v, %v; retire=%d release=%d", metadata, err, lease.retireCalls, lease.releaseCalls)
	}
}

func makeNamespaceCloseFailure(t *testing.T) *NamespaceHandle {
	t.Helper()
	user, err := os.CreateTemp(t.TempDir(), "close-user-")
	if err != nil {
		t.Fatal(err)
	}
	network, err := os.CreateTemp(t.TempDir(), "close-net-")
	if err != nil {
		user.Close()
		t.Fatal(err)
	}
	handle, err := NewNamespaceHandle(user, network)
	if err != nil {
		t.Fatal(err)
	}
	return handle
}
