package firecracker

import "sync"

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
	return proof, false
}

type liveSessionRegistry struct {
	mu        sync.RWMutex
	sessions  map[string]liveSessionProof
	processes map[string]liveProcessProof
	lifecycle map[string]struct{}
}

func newLiveSessionRegistry() *liveSessionRegistry {
	return &liveSessionRegistry{
		sessions:  make(map[string]liveSessionProof),
		processes: make(map[string]liveProcessProof),
		lifecycle: make(map[string]struct{}),
	}
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
