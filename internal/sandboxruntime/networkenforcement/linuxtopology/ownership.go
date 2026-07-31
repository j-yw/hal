package linuxtopology

import (
	"context"
	"sync"
)

type memoryOwnershipStore struct {
	mu      sync.Mutex
	locked  map[string]bool
	retired map[string]map[string]struct{}
}

type memoryOwnershipLease struct {
	store      *memoryOwnershipStore
	sandboxID  string
	generation string
	released   bool
}

func newMemoryOwnershipStore() *memoryOwnershipStore {
	return &memoryOwnershipStore{
		locked:  make(map[string]bool),
		retired: make(map[string]map[string]struct{}),
	}
}

func (s *memoryOwnershipStore) Acquire(_ context.Context, identity Identity) (OwnershipLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked[identity.SandboxID] {
		return nil, ErrTopologyCollision
	}
	if _, found := s.retired[identity.SandboxID][identity.TopologyGenerationID]; found {
		return nil, ErrStaleGeneration
	}
	s.locked[identity.SandboxID] = true
	return &memoryOwnershipLease{store: s, sandboxID: identity.SandboxID, generation: identity.TopologyGenerationID}, nil
}

func (*memoryOwnershipLease) Reconcile(context.Context) error { return nil }

func (*memoryOwnershipLease) Record(context.Context, ProcessHandle, ProcessHandle, *NamespaceHandle) error {
	return nil
}

func (l *memoryOwnershipLease) Retire(identity Identity) error {
	if l == nil || l.store == nil || identity.SandboxID != l.sandboxID || identity.TopologyGenerationID != l.generation {
		return ErrIdentityMismatch
	}
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	if l.store.retired[l.sandboxID] == nil {
		l.store.retired[l.sandboxID] = make(map[string]struct{})
	}
	l.store.retired[l.sandboxID][l.generation] = struct{}{}
	return nil
}

func (l *memoryOwnershipLease) Release() error {
	if l == nil || l.store == nil {
		return nil
	}
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	if l.released {
		return nil
	}
	l.released = true
	delete(l.store.locked, l.sandboxID)
	return nil
}
