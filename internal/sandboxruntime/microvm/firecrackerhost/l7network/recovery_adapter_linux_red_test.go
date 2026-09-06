//go:build linux

package l7network

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology"
)

type adapterRecoveryProvider struct {
	namespace *linuxtopology.NamespaceHandle
	err       error
	returned  *linuxtopology.NamespaceHandle
}

type adversarialRecoveryProvider struct {
	acquire func(context.Context, Identity) (*linuxtopology.NamespaceHandle, error)
}

func (p *adversarialRecoveryProvider) AcquireLinuxRecoveryNamespace(ctx context.Context, identity Identity) (*linuxtopology.NamespaceHandle, error) {
	return p.acquire(ctx, identity)
}

func (p *adapterRecoveryProvider) AcquireLinuxRecoveryNamespace(context.Context, Identity) (*linuxtopology.NamespaceHandle, error) {
	if p.namespace == nil {
		return nil, p.err
	}
	duplicate, err := p.namespace.Duplicate()
	if err != nil {
		return nil, err
	}
	p.returned = duplicate
	return duplicate, p.err
}

type adapterRecoveryOwnershipStore struct{}

func (*adapterRecoveryOwnershipStore) Acquire(context.Context, linuxtopology.Identity) (linuxtopology.OwnershipLease, error) {
	return &adapterRecoveryOwnershipLease{}, nil
}

func (*adapterRecoveryOwnershipStore) AcquireRecovery(_ context.Context, request linuxtopology.RecoveryRequest) (linuxtopology.RecoveredOwnership, error) {
	namespace, err := request.Namespace.Duplicate()
	if err != nil {
		return linuxtopology.RecoveredOwnership{}, err
	}
	return linuxtopology.RecoveredOwnership{Lease: &adapterRecoveryOwnershipLease{}, Namespace: namespace}, nil
}

type adapterRecoveryOwnershipLease struct{}

func (*adapterRecoveryOwnershipLease) Reconcile(context.Context) error { return nil }
func (*adapterRecoveryOwnershipLease) Record(context.Context, linuxtopology.ProcessHandle, linuxtopology.ProcessHandle, *linuxtopology.NamespaceHandle) error {
	return nil
}
func (*adapterRecoveryOwnershipLease) ArmMapping(context.Context, linuxtopology.ProcessHandle, *linuxtopology.NamespaceHandle) error {
	return nil
}
func (*adapterRecoveryOwnershipLease) Retire(linuxtopology.Identity) error { return nil }
func (*adapterRecoveryOwnershipLease) Release() error                      { return nil }

type adapterUnusedStarter struct{}

func (adapterUnusedStarter) Start(context.Context, linuxtopology.ProcessSpec) (linuxtopology.ProcessHandle, error) {
	return nil, errors.New("unused")
}

type adapterUnusedRunner struct{}

func (adapterUnusedRunner) Run(context.Context, linuxtopology.ProcessSpec) ([]byte, error) {
	return nil, errors.New("unused")
}

type adapterUnusedProber struct{}

func (adapterUnusedProber) Probe(context.Context, *linuxtopology.NamespaceHandle, linuxtopology.Identity, linuxtopology.Mapping) error {
	return errors.New("unused")
}

func TestLinuxRecoveryTopologyAdaptsSupervisorNamespaceForCleanupOnly(t *testing.T) {
	namespace := newAdapterRecoveryNamespace(t)
	provider := &adapterRecoveryProvider{namespace: namespace}
	lifecycle, err := linuxtopology.New(linuxtopology.Config{
		Enabled: true,
		Tools:   linuxtopology.ToolPaths{Unshare: "/bin/unused", Pasta: "/bin/unused", Nsenter: "/bin/unused", IP: "/bin/unused", NC: "/bin/unused", Keeper: "/bin/unused"},
		Starter: adapterUnusedStarter{}, Runner: adapterUnusedRunner{},
		OpenNamespaces: func(int) (*linuxtopology.NamespaceHandle, error) { return nil, errors.New("unused") },
		Reachability:   adapterUnusedProber{}, Ownership: &adapterRecoveryOwnershipStore{},
	})
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := NewLinuxRecoveryTopology(lifecycle, provider)
	if err != nil {
		t.Fatal(err)
	}
	identity := testIdentity()
	topology, session, err := recovery.Recover(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	metadata := session.Metadata()
	if metadata.Identity != topologyIdentity(identity) || metadata.Status != linuxtopology.StatusRecoveryOnly || metadata.StructuralInspected || metadata.MappingReachable {
		t.Fatalf("recovery metadata = %#v, want cleanup-only", metadata)
	}
	if provider.returned == nil || !provider.returned.Closed() {
		t.Fatal("adapter did not close provider-owned transfer after lifecycle duplicated it")
	}
	lease, err := session.BorrowNamespace()
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	stopped, err := topology.Stop(context.Background(), topologyIdentity(identity))
	if err != nil || stopped.Status != linuxtopology.StatusStopped {
		t.Fatalf("Stop(recovery) = %#v, %v", stopped, err)
	}
}

func TestLinuxRecoveryTopologyClosesNamespaceReturnedWithError(t *testing.T) {
	namespace := newAdapterRecoveryNamespace(t)
	provider := &adapterRecoveryProvider{namespace: namespace, err: errors.New("private supervisor endpoint")}
	lifecycle, err := linuxtopology.New(linuxtopology.Config{})
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := NewLinuxRecoveryTopology(lifecycle, provider)
	if err != nil {
		t.Fatal(err)
	}
	if topology, session, recoverErr := recovery.Recover(context.Background(), testIdentity()); topology != nil || session != nil ||
		!errors.Is(recoverErr, ErrStaleTopologyUnverified) || recoverErr.Error() != ErrStaleTopologyUnverified.Error() {
		t.Fatalf("Recover(provider error) = %T, %T, %v", topology, session, recoverErr)
	}
	if provider.returned == nil || !provider.returned.Closed() {
		t.Fatal("adapter retained namespace returned with provider error")
	}
}

func TestLinuxRecoveryTopologyRejectsTypedNilProvider(t *testing.T) {
	var provider *adapterRecoveryProvider
	lifecycle, err := linuxtopology.New(linuxtopology.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if recovery, err := NewLinuxRecoveryTopology(lifecycle, provider); recovery != nil || !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("NewLinuxRecoveryTopology(typed nil) = %T, %v", recovery, err)
	}
}

func TestLinuxRecoveryTopologyProviderAdversarialMatrix(t *testing.T) {
	privateErr := errors.New("private provider detail")
	for _, test := range []struct {
		name    string
		acquire func(*testing.T) (*linuxtopology.NamespaceHandle, error)
	}{
		{name: "panic", acquire: func(*testing.T) (*linuxtopology.NamespaceHandle, error) { panic("private provider panic") }},
		{name: "nil", acquire: func(*testing.T) (*linuxtopology.NamespaceHandle, error) { return nil, nil }},
		{name: "nil plus error", acquire: func(*testing.T) (*linuxtopology.NamespaceHandle, error) { return nil, privateErr }},
		{name: "closed", acquire: func(t *testing.T) (*linuxtopology.NamespaceHandle, error) {
			namespace := newAdapterRecoveryNamespace(t)
			if err := namespace.Close(); err != nil {
				t.Fatal(err)
			}
			return namespace, nil
		}},
		{name: "value plus error", acquire: func(t *testing.T) (*linuxtopology.NamespaceHandle, error) {
			return newAdapterRecoveryNamespace(t), privateErr
		}},
		{name: "close failure", acquire: func(t *testing.T) (*linuxtopology.NamespaceHandle, error) {
			user, err := os.CreateTemp(t.TempDir(), "provider-user-")
			if err != nil {
				t.Fatal(err)
			}
			network, err := os.CreateTemp(t.TempDir(), "provider-net-")
			if err != nil {
				t.Fatal(err)
			}
			namespace, err := linuxtopology.NewNamespaceHandle(user, network)
			if err != nil {
				t.Fatal(err)
			}
			_ = syscall.Close(int(user.Fd()))
			_ = syscall.Close(int(network.Fd()))
			return namespace, privateErr
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := &adversarialRecoveryProvider{acquire: func(context.Context, Identity) (*linuxtopology.NamespaceHandle, error) {
				return test.acquire(t)
			}}
			lifecycle, err := linuxtopology.New(linuxtopology.Config{})
			if err != nil {
				t.Fatal(err)
			}
			recovery, err := NewLinuxRecoveryTopology(lifecycle, provider)
			if err != nil {
				t.Fatal(err)
			}
			var topology TopologyLifecycle
			var session TopologySession
			var recoverErr error
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Fatalf("LinuxRecoveryTopology.Recover panicked: %v", recovered)
					}
				}()
				topology, session, recoverErr = recovery.Recover(context.Background(), testIdentity())
			}()
			if topology != nil || session != nil || !errors.Is(recoverErr, ErrStaleTopologyUnverified) || recoverErr.Error() != ErrStaleTopologyUnverified.Error() {
				t.Fatalf("Recover(%s) = %T, %T, %v", test.name, topology, session, recoverErr)
			}
		})
	}
}

func TestLinuxRecoveryTopologyRejectsReusedProviderHandle(t *testing.T) {
	namespace := newAdapterRecoveryNamespace(t)
	provider := &adversarialRecoveryProvider{acquire: func(context.Context, Identity) (*linuxtopology.NamespaceHandle, error) {
		return namespace, nil
	}}
	lifecycle, err := linuxtopology.New(linuxtopology.Config{})
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := NewLinuxRecoveryTopology(lifecycle, provider)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if topology, session, err := recovery.Recover(context.Background(), testIdentity()); topology != nil || session != nil ||
			!errors.Is(err, ErrStaleTopologyUnverified) {
			t.Fatalf("Recover(reused handle %d) = %T, %T, %v", attempt, topology, session, err)
		}
	}
	if !namespace.Closed() {
		t.Fatal("adapter did not consume first provider transfer")
	}
}

func newAdapterRecoveryNamespace(t *testing.T) *linuxtopology.NamespaceHandle {
	t.Helper()
	user, err := os.CreateTemp(t.TempDir(), "user-ns-")
	if err != nil {
		t.Fatal(err)
	}
	network, err := os.CreateTemp(t.TempDir(), "net-ns-")
	if err != nil {
		user.Close()
		t.Fatal(err)
	}
	handle, err := linuxtopology.NewNamespaceHandle(user, network)
	if err != nil {
		user.Close()
		network.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	return handle
}
