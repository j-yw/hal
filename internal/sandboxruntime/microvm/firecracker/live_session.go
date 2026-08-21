package firecracker

import (
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
)

const (
	unverifiedProcessGeneration = "opaque-unverified"
	unverifiedProcessSource     = "unverified"
)

type liveSessionProof struct {
	RuntimeID         string
	ProcessGeneration string
	ProcessSource     string
	BridgeGeneration  string
}

type liveProcessProof struct {
	RuntimeID         string
	ProcessGeneration string
	ProcessSource     string
	unverified        bool
}

type liveProcessKey struct {
	runtimeID         string
	processGeneration string
	processSource     string
}

type l8OwnedAssetLease struct {
	proof     liveProcessProof
	lease     *localresolver.VerifiedL8AssetLease
	authority l8AuthorityOperations
}

func liveProcessProofFromHandle(runtimeID string, handle ProcessHandleMetadata) (liveProcessProof, bool) {
	proof := liveProcessProof{
		RuntimeID:         runtimeID,
		ProcessGeneration: handle.ID,
		ProcessSource:     handle.Source,
	}
	if proof.RuntimeID != "" && proof.ProcessGeneration != "" && proof.ProcessSource != "" {
		return proof, true
	}
	proof.ProcessGeneration = unverifiedProcessGeneration
	proof.ProcessSource = unverifiedProcessSource
	proof.unverified = true
	return proof, false
}

type liveSessionRegistry struct {
	mu        sync.RWMutex
	sessions  map[string]liveSessionProof
	processes map[string]liveProcessProof
	lifecycle map[string]struct{}
	l8Leases  map[liveProcessKey]l8OwnedAssetLease
}

func newLiveSessionRegistry() *liveSessionRegistry {
	return &liveSessionRegistry{
		sessions:  make(map[string]liveSessionProof),
		processes: make(map[string]liveProcessProof),
		lifecycle: make(map[string]struct{}),
		l8Leases:  make(map[liveProcessKey]l8OwnedAssetLease),
	}
}

func (registry *liveSessionRegistry) TrackL8Lease(
	proof liveProcessProof,
	lease *localresolver.VerifiedL8AssetLease,
	authority l8AuthorityOperations,
) bool {
	if registry == nil || proof.RuntimeID == "" || proof.ProcessGeneration == "" ||
		proof.ProcessSource == "" || lease == nil || !authority.valid() {
		return false
	}
	key := liveProcessKey{
		runtimeID:         proof.RuntimeID,
		processGeneration: proof.ProcessGeneration,
		processSource:     proof.ProcessSource,
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.l8Leases[key]; exists {
		return false
	}
	registry.l8Leases[key] = l8OwnedAssetLease{proof: proof, lease: lease, authority: authority}
	return true
}

func (registry *liveSessionRegistry) HasAnyL8Lease(runtimeID string) bool {
	if registry == nil || runtimeID == "" {
		return false
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	for key := range registry.l8Leases {
		if key.runtimeID == runtimeID {
			return true
		}
	}
	return false
}

func (registry *liveSessionRegistry) HasL8Lease(runtimeID, processGeneration string) bool {
	if registry == nil {
		return false
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	for key := range registry.l8Leases {
		if key.runtimeID == runtimeID && key.processGeneration == processGeneration {
			return true
		}
	}
	return false
}

func (registry *liveSessionRegistry) takeL8Lease(proof liveProcessProof) (l8OwnedAssetLease, bool) {
	if registry == nil {
		return l8OwnedAssetLease{}, false
	}
	key := liveProcessKey{
		runtimeID:         proof.RuntimeID,
		processGeneration: proof.ProcessGeneration,
		processSource:     proof.ProcessSource,
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	owned, ok := registry.l8Leases[key]
	if ok {
		delete(registry.l8Leases, key)
	}
	return owned, ok
}

func (registry *liveSessionRegistry) l8LeaseForProcess(proof liveProcessProof) (l8OwnedAssetLease, bool) {
	if registry == nil {
		return l8OwnedAssetLease{}, false
	}
	key := liveProcessKey{
		runtimeID:         proof.RuntimeID,
		processGeneration: proof.ProcessGeneration,
		processSource:     proof.ProcessSource,
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	owned, ok := registry.l8Leases[key]
	return owned, ok
}

func (registry *liveSessionRegistry) ReserveLifecycle(runtimeID string) bool {
	if registry == nil || runtimeID == "" {
		return false
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, ok := registry.lifecycle[runtimeID]; ok {
		return false
	}
	registry.lifecycle[runtimeID] = struct{}{}
	return true
}

func (registry *liveSessionRegistry) ReleaseLifecycle(runtimeID string) {
	if registry == nil {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	delete(registry.lifecycle, runtimeID)
}

func (registry *liveSessionRegistry) Activate(proof liveSessionProof) {
	if registry == nil || proof.RuntimeID == "" || proof.ProcessGeneration == "" || proof.BridgeGeneration == "" {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.sessions[proof.RuntimeID] = proof
	registry.processes[proof.RuntimeID] = liveProcessProof{
		RuntimeID:         proof.RuntimeID,
		ProcessGeneration: proof.ProcessGeneration,
		ProcessSource:     proof.ProcessSource,
	}
}

func (registry *liveSessionRegistry) TrackProcess(proof liveProcessProof) {
	if registry == nil || proof.RuntimeID == "" || proof.ProcessGeneration == "" || proof.ProcessSource == "" {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.processes[proof.RuntimeID] = proof
}

func (registry *liveSessionRegistry) Authorize(proof liveSessionProof) bool {
	if registry == nil {
		return false
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	active, ok := registry.sessions[proof.RuntimeID]
	return ok && active == proof
}

func (registry *liveSessionRegistry) Proof(runtimeID, processGeneration string) (liveSessionProof, bool) {
	if registry == nil {
		return liveSessionProof{}, false
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	proof, ok := registry.sessions[runtimeID]
	return proof, ok && proof.ProcessGeneration == processGeneration
}

func (registry *liveSessionRegistry) ProofForRuntime(runtimeID string) (liveSessionProof, bool) {
	if registry == nil {
		return liveSessionProof{}, false
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	proof, ok := registry.sessions[runtimeID]
	return proof, ok
}

func (registry *liveSessionRegistry) Process(runtimeID, processGeneration string) (liveProcessProof, bool) {
	if registry == nil {
		return liveProcessProof{}, false
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	proof, ok := registry.processes[runtimeID]
	return proof, ok && proof.ProcessGeneration == processGeneration
}

func (registry *liveSessionRegistry) ProcessForRuntime(runtimeID string) (liveProcessProof, bool) {
	if registry == nil {
		return liveProcessProof{}, false
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	proof, ok := registry.processes[runtimeID]
	return proof, ok
}

func (registry *liveSessionRegistry) Invalidate(proof liveSessionProof) {
	if registry == nil {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if active, ok := registry.sessions[proof.RuntimeID]; ok && active == proof {
		delete(registry.sessions, proof.RuntimeID)
	}
}

func (registry *liveSessionRegistry) InvalidateRuntime(runtimeID string) {
	if registry == nil {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	delete(registry.sessions, runtimeID)
}

func (registry *liveSessionRegistry) InvalidateProcess(proof liveProcessProof) {
	if registry == nil {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if active, ok := registry.processes[proof.RuntimeID]; ok && active == proof {
		delete(registry.processes, proof.RuntimeID)
	}
}
