package firecracker

import (
	"context"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL5CallerCarriedReadinessCannotAuthorizeGuestTransport(t *testing.T) {
	controller := firecrackerController{
		liveStart:      true,
		guestTransport: l5NoopGuestTransport{},
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

type l5NoopGuestTransport struct{}

func (l5NoopGuestTransport) Exec(context.Context, GuestExecRequest) (*sandboxruntime.ExecResult, error) {
	return &sandboxruntime.ExecResult{}, nil
}
func (l5NoopGuestTransport) CopyIn(context.Context, GuestCopyRequest) error  { return nil }
func (l5NoopGuestTransport) CopyOut(context.Context, GuestCopyRequest) error { return nil }
