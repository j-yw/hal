package l7network

import (
	"context"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology"
)

type LinuxTopology struct{ lifecycle *linuxtopology.Lifecycle }

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

func (t *LinuxTopology) Start(ctx context.Context, request linuxtopology.StartRequest) (TopologySession, error) {
	if t == nil || t.lifecycle == nil {
		return nil, ErrTopologyPrepareFailed
	}
	session, err := t.lifecycle.Start(ctx, request)
	if err != nil {
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
