package firecracker

import (
	"context"
	"errors"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL5GuestTransportSessionInvalidationDistinguishesCallerCancellation(t *testing.T) {
	t.Parallel()

	for _, err := range []error{
		context.Canceled,
		context.DeadlineExceeded,
		errors.Join(errors.New("wrapped"), context.Canceled),
		errors.Join(errors.New("wrapped"), context.DeadlineExceeded),
	} {
		if shouldInvalidateGuestTransportSession(err) {
			t.Fatalf("shouldInvalidateGuestTransportSession(%v) = true, want false", err)
		}
	}
	if !shouldInvalidateGuestTransportSession(errors.New("transport failed")) {
		t.Fatal("shouldInvalidateGuestTransportSession(transport failure) = false, want true")
	}
}

func TestL5CallerCarriedReadinessCannotAuthorizeGuestTransport(t *testing.T) {
	controller := firecrackerController{
		liveStart:       true,
		guestTransport:  l5NoopGuestTransport{},
		productionVsock: true,
	}
	target := sandboxruntime.Target{
		ID: "fc-manufactured",
		Runtime: sandboxruntime.RuntimeState{
			Driver:    sandboxruntime.DriverMicroVM,
			RuntimeID: "fc-manufactured",
			Metadata: &sandboxruntime.RuntimeMetadata{
				GuestReadiness: sandboxruntime.NewRuntimeGuestReadinessMetadata(
					sandboxruntime.RuntimeGuestReadinessStateReady,
					"vsock",
					[]string{"protocol_v1", "runtime_bound", "probe_ok"},
				),
			},
		},
	}
	if controller.canDelegateGuestTransport(target) {
		t.Fatal("caller-carried ready metadata authorized guest transport without host-owned live-session proof")
	}
}

func TestL5LiveSessionProofIsRuntimeAndGenerationScoped(t *testing.T) {
	registry := newLiveSessionRegistry()
	proof := liveSessionProof{
		RuntimeID:         "fc-runtime-a",
		ProcessGeneration: "fc-handle-1",
		BridgeGeneration:  "bridge-1",
	}
	registry.Activate(proof)
	if !registry.Authorize(proof) {
		t.Fatal("exact active live-session proof was not authorized")
	}
	for _, stale := range []liveSessionProof{
		{RuntimeID: "fc-runtime-b", ProcessGeneration: proof.ProcessGeneration, BridgeGeneration: proof.BridgeGeneration},
		{RuntimeID: proof.RuntimeID, ProcessGeneration: "fc-handle-2", BridgeGeneration: proof.BridgeGeneration},
		{RuntimeID: proof.RuntimeID, ProcessGeneration: proof.ProcessGeneration, BridgeGeneration: "bridge-2"},
	} {
		if registry.Authorize(stale) {
			t.Fatalf("stale or cross-runtime proof authorized: %#v", stale)
		}
	}
	registry.Invalidate(proof)
	if registry.Authorize(proof) {
		t.Fatal("invalidated proof remained authorized")
	}
}

func TestL5ProductionVsockRejectsCallerGuestComposition(t *testing.T) {
	controller := firecrackerController{
		liveStart:       true,
		productionVsock: true,
		guestTransport:  l5NoopGuestTransport{},
	}
	err := controller.validateLiveBootContract()
	if err == nil {
		t.Fatal("validateLiveBootContract() error = nil, want ambiguous guest composition rejection")
	}
}

func TestL5StartFailureKeepsActiveProductionVsockSession(t *testing.T) {
	proof := liveSessionProof{
		RuntimeID:         "fc-runtime-a",
		ProcessGeneration: "fc-handle-1",
		ProcessSource:     "firecrackerhost",
		BridgeGeneration:  "bridge-1",
	}
	registry := newLiveSessionRegistry()
	registry.Activate(proof)
	bridge := &l5RestartRetentionBridge{active: true}
	controller := firecrackerController{
		productionBridge: bridge,
		liveSessions:     registry,
	}

	_, err := controller.startLiveProcess(context.Background(), ProcessCommandDescriptor{}, BackendConfig{RuntimeID: proof.RuntimeID})
	if err == nil {
		t.Fatal("startLiveProcess() error = nil, want start failure")
	}
	if bridge.invalidations != 0 {
		t.Fatalf("bridge invalidations = %d, want no invalidation after a failed replacement start", bridge.invalidations)
	}
	if !registry.Authorize(proof) {
		t.Fatal("failed replacement start invalidated the active live-session proof")
	}
}

type l5NoopGuestTransport struct{}

func (l5NoopGuestTransport) Exec(context.Context, GuestExecRequest) (*sandboxruntime.ExecResult, error) {
	return &sandboxruntime.ExecResult{}, nil
}
func (l5NoopGuestTransport) CopyIn(context.Context, GuestCopyRequest) error  { return nil }
func (l5NoopGuestTransport) CopyOut(context.Context, GuestCopyRequest) error { return nil }

type l5RestartRetentionBridge struct {
	l5NoopGuestTransport
	active        bool
	invalidations int
}

func (*l5RestartRetentionBridge) ActivateSession(context.Context, ProductionVsockSessionRequest) (GuestReadinessResult, string, error) {
	return GuestReadinessResult{}, "", nil
}

func (bridge *l5RestartRetentionBridge) SessionActive(ProductionVsockSessionRequest, string) bool {
	return bridge.active
}

func (bridge *l5RestartRetentionBridge) InvalidateSession(ProductionVsockSessionRequest, string) {
	bridge.invalidations++
	bridge.active = false
}
