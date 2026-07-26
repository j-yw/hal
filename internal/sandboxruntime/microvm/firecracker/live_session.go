package firecracker

import "sync"

type liveSessionProof struct {
	RuntimeID         string
	ProcessGeneration string
	ProcessSource     string
	BridgeGeneration  string
}

type liveSessionRegistry struct {
	mu       sync.RWMutex
	sessions map[string]liveSessionProof
}

func newLiveSessionRegistry() *liveSessionRegistry {
	return &liveSessionRegistry{sessions: make(map[string]liveSessionProof)}
}

func (registry *liveSessionRegistry) Activate(proof liveSessionProof) {
	if registry == nil || proof.RuntimeID == "" || proof.ProcessGeneration == "" || proof.BridgeGeneration == "" {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.sessions[proof.RuntimeID] = proof
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
