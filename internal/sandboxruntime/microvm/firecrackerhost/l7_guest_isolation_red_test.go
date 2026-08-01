package firecrackerhost

import (
	"context"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

func TestL7GuestAgentReadinessProbeRequiresBoundIsolationProof(t *testing.T) {
	client := &recordingGuestAgentReadinessClient{}
	client.response = &guestagent.ReadinessResponse{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationReadiness,
		Ready:           true,
		Status:          guestagent.ReadinessStatusReady,
		IsolationProof: &guestagent.IsolationProof{
			Generation:                 "topology-generation-1",
			RuntimeGeneration:          "runtime-generation-1",
			Status:                     guestagent.IsolationProofStatusVerified,
			CapabilitiesCleared:        true,
			NoNewPrivileges:            true,
			SupplementaryGroupsCleared: true,
			RawPacketSocketDenied:      true,
			Network: &guestagent.NetworkIsolationProof{
				Status:          guestagent.IsolationProofStatusVerified,
				SingleInterface: true,
				StaticRoutes:    true,
				ProxyReachable:  true,
			},
		},
	}
	probe := NewGuestAgentReadinessProbe(GuestAgentReadinessProbeOptions{
		Client:                   client,
		RequireIsolationProof:    true,
		RequireNetworkProof:      true,
		IsolationProofGeneration: "topology-generation-1",
	})
	result, err := probe.ProbeGuestReadiness(context.Background(), firecracker.GuestReadinessRequest{RuntimeID: "runtime-generation-1"})
	if err != nil {
		t.Fatalf("ProbeGuestReadiness() error = %v", err)
	}
	if result.State != sandboxruntime.RuntimeGuestReadinessStateReady || strings.Join(result.Labels, ",") != "ready,protocol,guest_isolation_verified,guest_network_verified" {
		t.Fatalf("result = %#v, want sanitized L7 proof labels", result)
	}
	if client.request.IsolationProof == nil || client.request.IsolationProof.Generation != "topology-generation-1" || client.request.IsolationProof.RuntimeGeneration != "runtime-generation-1" || !client.request.IsolationProof.RequireNetworkProof {
		t.Fatalf("readiness request = %#v, want exact proof binding", client.request)
	}
}

func TestL7GuestAgentReadinessProbeRejectsMissingPartialAndStaleProof(t *testing.T) {
	valid := &guestagent.IsolationProof{
		Generation:                 "topology-generation-2",
		RuntimeGeneration:          "runtime-generation-2",
		Status:                     guestagent.IsolationProofStatusVerified,
		CapabilitiesCleared:        true,
		NoNewPrivileges:            true,
		SupplementaryGroupsCleared: true,
		RawPacketSocketDenied:      true,
	}
	tests := []struct {
		name   string
		mutate func(*guestagent.ReadinessResponse)
	}{
		{name: "missing", mutate: func(r *guestagent.ReadinessResponse) { r.IsolationProof = nil }},
		{name: "stale", mutate: func(r *guestagent.ReadinessResponse) { r.IsolationProof.Generation = "stale" }},
		{name: "partial", mutate: func(r *guestagent.ReadinessResponse) { r.IsolationProof.RawPacketSocketDenied = false }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof := *valid
			response := &guestagent.ReadinessResponse{ProtocolVersion: guestagent.ProtocolVersionV1, Operation: guestagent.OperationReadiness, Ready: true, Status: guestagent.ReadinessStatusReady, IsolationProof: &proof}
			tt.mutate(response)
			client := &recordingGuestAgentReadinessClient{response: response}
			probe := NewGuestAgentReadinessProbe(GuestAgentReadinessProbeOptions{Client: client, RequireIsolationProof: true, IsolationProofGeneration: "topology-generation-2"})
			_, err := probe.ProbeGuestReadiness(context.Background(), firecracker.GuestReadinessRequest{RuntimeID: "runtime-generation-2"})
			if err == nil {
				t.Fatal("ProbeGuestReadiness() error = nil, want fail-closed rejection")
			}
			for _, leaked := range []string{"/proc/", "CapEff", "0000000000000000", "10.0.0.2", "ghp_secret"} {
				if strings.Contains(err.Error(), leaked) {
					t.Fatalf("error leaked %q: %v", leaked, err)
				}
			}
		})
	}
}
