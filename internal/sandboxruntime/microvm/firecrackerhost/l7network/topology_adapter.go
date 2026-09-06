package l7network

import (
	"context"
	"errors"
	"os"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology"
)

type LinuxTopology struct{ lifecycle *linuxtopology.Lifecycle }

// LinuxRecoveryNamespaceProvider returns a fresh caller-owned duplicate of the
// exact supervisor-retained user/network namespace authority for one recovery.
type LinuxRecoveryNamespaceProvider interface {
	AcquireLinuxRecoveryNamespace(context.Context, Identity) (*linuxtopology.NamespaceHandle, error)
}

// LinuxRecoveryTopology adapts cleanup-only linuxtopology recovery to the
// Reconciler's exact-ownership boundary.
type LinuxRecoveryTopology struct {
	lifecycle *linuxtopology.Lifecycle
	provider  LinuxRecoveryNamespaceProvider
}

type linuxTopologySession struct{ session *linuxtopology.Session }

type linuxNamespaceLease struct {
	handle *linuxtopology.NamespaceHandle
	files  *linuxtopology.NamespaceFiles
}

func NewLinuxTopology(lifecycle *linuxtopology.Lifecycle) (*LinuxTopology, error) {
	if lifecycle == nil {
		return nil, ErrInvalidConfiguration
	}
	return &LinuxTopology{lifecycle: lifecycle}, nil
}

func NewLinuxRecoveryTopology(lifecycle *linuxtopology.Lifecycle, provider LinuxRecoveryNamespaceProvider) (*LinuxRecoveryTopology, error) {
	if lifecycle == nil || interfaceIsNil(provider) {
		return nil, ErrInvalidConfiguration
	}
	return &LinuxRecoveryTopology{lifecycle: lifecycle, provider: provider}, nil
}

func (t *LinuxRecoveryTopology) Recover(ctx context.Context, identity Identity) (topology TopologyLifecycle, session TopologySession, err error) {
	defer func() {
		if panicked := recover(); panicked != nil {
			topology, session, err = nil, nil, ErrStaleTopologyUnverified
		}
	}()
	if t == nil || t.lifecycle == nil || interfaceIsNil(t.provider) || !validIdentity(identity) {
		return nil, nil, ErrStaleTopologyUnverified
	}
	namespace, acquireErr := t.provider.AcquireLinuxRecoveryNamespace(ctx, identity)
	if namespace != nil {
		defer func() { _ = namespace.Close() }()
	}
	if acquireErr != nil || namespace == nil || namespace.Closed() {
		return nil, nil, ErrStaleTopologyUnverified
	}
	recovered, recoverErr := t.lifecycle.Recover(ctx, linuxtopology.RecoveryRequest{
		Identity: topologyIdentity(identity), Namespace: namespace,
	})
	if recoverErr != nil || recovered == nil {
		return nil, nil, ErrStaleTopologyUnverified
	}
	return &LinuxTopology{lifecycle: t.lifecycle}, &linuxTopologySession{session: recovered}, nil
}

func (t *LinuxTopology) Start(ctx context.Context, request linuxtopology.StartRequest) (TopologySession, error) {
	if t == nil || t.lifecycle == nil {
		return nil, ErrTopologyPrepareFailed
	}
	session, err := t.lifecycle.Start(ctx, request)
	if err != nil {
		if session != nil {
			return &linuxTopologySession{session: session}, sanitizeTopologyError(err)
		}
		return nil, sanitizeTopologyError(err)
	}
	return &linuxTopologySession{session: session}, nil
}

func (t *LinuxTopology) Stop(ctx context.Context, identity linuxtopology.Identity) (linuxtopology.Metadata, error) {
	if t == nil || t.lifecycle == nil {
		return linuxtopology.Metadata{}, ErrCleanupIncomplete
	}
	metadata, err := t.lifecycle.Stop(ctx, identity)
	if err != nil {
		return metadata, sanitizeTopologyError(err)
	}
	return metadata, nil
}

func (s *linuxTopologySession) Metadata() linuxtopology.Metadata {
	if s == nil || s.session == nil {
		return linuxtopology.Metadata{}
	}
	return s.session.Metadata()
}

func (s *linuxTopologySession) Losses() <-chan linuxtopology.Loss {
	if s == nil || s.session == nil {
		return nil
	}
	return s.session.Losses()
}

func (s *linuxTopologySession) BorrowNamespace() (NamespaceLease, error) {
	if s == nil || s.session == nil {
		return nil, ErrTopologyPrepareFailed
	}
	handle, err := s.session.NamespaceHandle()
	if err != nil {
		return nil, ErrTopologyPrepareFailed
	}
	files, err := handle.BorrowFiles()
	if err != nil {
		_ = handle.Close()
		return nil, ErrTopologyPrepareFailed
	}
	return &linuxNamespaceLease{handle: handle, files: files}, nil
}

func (l *linuxNamespaceLease) RuleNamespace() linuxrules.NamespaceHandle {
	if l == nil || l.files == nil {
		return linuxrules.NamespaceHandle{}
	}
	return linuxrules.NewNamespaceHandle(l.files.UserFD(), l.files.NetworkFD())
}

func (l *linuxNamespaceLease) commandFiles() *linuxtopology.NamespaceFiles {
	if l == nil {
		return nil
	}
	return l.files
}

func (l *linuxNamespaceLease) DuplicateForNamespaceProcess() (*os.File, *os.File, error) {
	if l == nil || l.files == nil {
		return nil, nil, ErrTopologyPrepareFailed
	}
	user, network, err := l.files.DuplicateForCommand()
	if err != nil {
		return nil, nil, ErrTopologyPrepareFailed
	}
	return user, network, nil
}

func (l *linuxNamespaceLease) Close() error {
	if l == nil {
		return nil
	}
	// Close child-command descriptors before returning the tracked Session
	// borrow. Lifecycle.Stop cannot pass its borrow barrier until both steps
	// have completed.
	err := errors.Join(l.files.Close(), l.handle.Close())
	if err == nil {
		l.files = nil
		l.handle = nil
	}
	return err
}

func sanitizeTopologyError(err error) error {
	switch {
	case errors.Is(err, linuxtopology.ErrUnsupported):
		return ErrUnsupported
	case errors.Is(err, linuxtopology.ErrTopologyCollision):
		return ErrTopologyCollision
	case errors.Is(err, linuxtopology.ErrStaleTopologyUnverified), errors.Is(err, linuxtopology.ErrStaleGeneration):
		return ErrStaleTopologyUnverified
	case errors.Is(err, linuxtopology.ErrIdentityMismatch), errors.Is(err, linuxtopology.ErrInvalidIdentity):
		return ErrInvalidIdentity
	case errors.Is(err, linuxtopology.ErrCleanupIncomplete):
		return ErrCleanupIncomplete
	default:
		return ErrTopologyPrepareFailed
	}
}
