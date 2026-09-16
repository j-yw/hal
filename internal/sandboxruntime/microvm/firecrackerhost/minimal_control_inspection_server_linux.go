//go:build linux

package firecrackerhost

import (
	"encoding/json"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

// Continuing selected identity, not the already-spent publication P/A/D gate.
// Actual manager/socket observations and I/O occur outside bookkeeping locks.
func (s *minimalControlWorkServer) inspectionCurrent() bool {
	serving := s.serving
	owned, ready := serving.owned, s.ready
	prep, selected := owned.minimalPreparation, owned.selected
	if !minimalWorkloadContextCurrent(s.ctx) || !prep.workCurrent() || !ready.Current() {
		return false
	}
	serving.mu.Lock()
	valid := !serving.closing && serving.server == s && serving.controller == ready.controller
	serving.mu.Unlock()
	if !valid || selected == nil {
		return false
	}
	selected.mu.Lock()
	coordinator, lifecycle := selected.coordinator, selected.lifecycle
	valid = selected.minimalPreparation == prep && selected.store == owned.store && selected.attempted && !selected.terminal && coordinator != nil && lifecycle != nil
	if valid {
		coordinator.mu.Lock()
		generation := coordinator.generation
		valid = generation != nil && generation.state == strictJailerCoordinatorActive && generation.hasProcess &&
			selected.session.coordinator == coordinator && selected.session.generation == generation.id && coordinator.deps.lifecycle == lifecycle &&
			lifecycle.manager == ready.controller.transport.manager && generation.process.handle == ready.handle
		coordinator.mu.Unlock()
	}
	selected.mu.Unlock()
	return valid && minimalWorkloadContextCurrent(s.ctx) && prep.workCurrent() && ready.Current()
}

func (s *minimalControlWorkServer) inspectionReply(payload []byte) ([]byte, error) {
	ready := s.ready
	reply, err := decodeMinimalGuestInspection(payload, ready.inspectionTopology, ready.inspectionRuntime)
	if err != nil || !s.inspectionCurrent() {
		return nil, errL8RuntimeOwnerInvalid
	}
	remaining := time.Until(ready.hardExpiry)
	if remaining <= 0 || remaining > session.MaxGuestCredentialSessionLifetime {
		return nil, errL8RuntimeOwnerInvalid
	}
	wire, err := json.Marshal(minimalHostInspectionReply{minimalGuestInspectionReply: reply,
		HardExpiryUnixNano: ready.hardExpiry.UnixNano(), RemainingLifetimeNanos: int64(remaining)})
	if err != nil || len(wire) == 0 || len(wire) > minimalInspectionMaximum || !s.inspectionCurrent() {
		clear(wire)
		return nil, errL8RuntimeOwnerInvalid
	}
	return wire, nil
}
