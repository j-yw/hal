package guestagent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestL7ReadinessIsolationProofJSONCompatibilityAndValidation(t *testing.T) {
	legacy := []byte(`{"protocolVersion":"guest-agent-v1","operation":"readiness","ready":true,"status":"ready"}`)
	var oldResponse ReadinessResponse
	if err := json.Unmarshal(legacy, &oldResponse); err != nil {
		t.Fatal(err)
	}
	if err := ValidateReadinessResponse(oldResponse); err != nil {
		t.Fatalf("legacy readiness response rejected: %v", err)
	}

	request := ReadinessRequest{
		ProtocolVersion: ProtocolVersionV1,
		Operation:       OperationReadiness,
		IsolationProof: &IsolationProofRequest{
			Generation:          "proof-generation-1",
			RuntimeGeneration:   "runtime-generation-1",
			RequireNetworkProof: true,
		},
	}
	if err := ValidateReadinessRequest(request); err != nil {
		t.Fatalf("ValidateReadinessRequest() error = %v", err)
	}
	response := ReadinessResponse{
		ProtocolVersion: ProtocolVersionV1,
		Operation:       OperationReadiness,
		Ready:           true,
		Status:          ReadinessStatusReady,
		IsolationProof: &IsolationProof{
			Generation:                 "proof-generation-1",
			RuntimeGeneration:          "runtime-generation-1",
			Status:                     IsolationProofStatusVerified,
			RestrictedIdentity:         true,
			CapabilitiesCleared:        true,
			NoNewPrivileges:            true,
			SupplementaryGroupsCleared: true,
			RawPacketSocketDenied:      true,
			Network: &NetworkIsolationProof{
				Status:          IsolationProofStatusVerified,
				SingleInterface: true,
				StaticRoutes:    true,
				ProxyReachable:  true,
			},
		},
	}
	if err := ValidateReadinessResponseForRequest(response, request); err != nil {
		t.Fatalf("ValidateReadinessResponseForRequest() error = %v", err)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"CapEff", "0000000000000000", "/proc/", "uid", "gid", "interfaceName", "address", "routeValue", "endpoint", "socketError", "pid"} {
		if strings.Contains(strings.ToLower(string(encoded)), strings.ToLower(forbidden)) {
			t.Fatalf("proof JSON leaked forbidden field/value %q: %s", forbidden, encoded)
		}
	}
}

func TestL7ReadinessIsolationProofRejectsPartialMalformedAndStaleProof(t *testing.T) {
	request := ReadinessRequest{
		ProtocolVersion: ProtocolVersionV1,
		Operation:       OperationReadiness,
		IsolationProof: &IsolationProofRequest{
			Generation:        "proof-generation-2",
			RuntimeGeneration: "runtime-generation-2",
		},
	}
	valid := ReadinessResponse{
		ProtocolVersion: ProtocolVersionV1,
		Operation:       OperationReadiness,
		Ready:           true,
		Status:          ReadinessStatusReady,
		IsolationProof: &IsolationProof{
			Generation:                 "proof-generation-2",
			RuntimeGeneration:          "runtime-generation-2",
			Status:                     IsolationProofStatusVerified,
			RestrictedIdentity:         true,
			CapabilitiesCleared:        true,
			NoNewPrivileges:            true,
			SupplementaryGroupsCleared: true,
			RawPacketSocketDenied:      true,
			Network:                    &NetworkIsolationProof{Status: IsolationProofStatusUnavailable},
		},
	}
	mutations := []struct {
		name   string
		mutate func(*ReadinessResponse)
	}{
		{name: "stale proof generation", mutate: func(r *ReadinessResponse) { r.IsolationProof.Generation = "stale" }},
		{name: "stale runtime generation", mutate: func(r *ReadinessResponse) { r.IsolationProof.RuntimeGeneration = "stale" }},
		{name: "identity not restricted", mutate: func(r *ReadinessResponse) { r.IsolationProof.RestrictedIdentity = false }},
		{name: "capabilities not clear", mutate: func(r *ReadinessResponse) { r.IsolationProof.CapabilitiesCleared = false }},
		{name: "no new privileges absent", mutate: func(r *ReadinessResponse) { r.IsolationProof.NoNewPrivileges = false }},
		{name: "supplementary groups present", mutate: func(r *ReadinessResponse) { r.IsolationProof.SupplementaryGroupsCleared = false }},
		{name: "raw packet attempt not denied", mutate: func(r *ReadinessResponse) { r.IsolationProof.RawPacketSocketDenied = false }},
		{name: "proof missing", mutate: func(r *ReadinessResponse) { r.IsolationProof = nil }},
	}
	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			candidate := valid
			proof := *valid.IsolationProof
			candidate.IsolationProof = &proof
			tt.mutate(&candidate)
			if err := ValidateReadinessResponseForRequest(candidate, request); err == nil {
				t.Fatal("ValidateReadinessResponseForRequest() error = nil, want fail-closed rejection")
			}
		})
	}

	for _, generation := range []string{"", "../unsafe", "contains space", strings.Repeat("a", MaxIsolationProofGenerationBytes+1)} {
		candidate := request
		proof := *request.IsolationProof
		proof.Generation = generation
		candidate.IsolationProof = &proof
		if err := ValidateReadinessRequest(candidate); err == nil {
			t.Fatalf("ValidateReadinessRequest(%q) error = nil, want rejection", generation)
		}
	}
}

func TestL7ClientStrictIsolationProofResponseHandling(t *testing.T) {
	request := ReadinessRequest{IsolationProof: &IsolationProofRequest{Generation: "generation", RuntimeGeneration: "runtime"}}
	tests := []struct {
		name string
		body string
		code ErrorCode
	}{
		{name: "unknown nested field", body: `{"protocolVersion":"guest-agent-v1","operation":"readiness","ready":true,"status":"ready","isolationProof":{"generation":"generation","runtimeGeneration":"runtime","status":"verified","restrictedIdentity":true,"capabilitiesCleared":true,"noNewPrivileges":true,"supplementaryGroupsCleared":true,"rawPacketSocketDenied":true,"unknown":true}}`, code: ErrorCodeMalformedResponse},
		{name: "duplicate nested field", body: `{"protocolVersion":"guest-agent-v1","operation":"readiness","ready":true,"status":"ready","isolationProof":{"generation":"generation","generation":"generation","runtimeGeneration":"runtime","status":"verified","restrictedIdentity":true,"capabilitiesCleared":true,"noNewPrivileges":true,"supplementaryGroupsCleared":true,"rawPacketSocketDenied":true}}`, code: ErrorCodeMalformedResponse},
		{name: "oversized generation", body: `{"protocolVersion":"guest-agent-v1","operation":"readiness","ready":true,"status":"ready","isolationProof":{"generation":"` + strings.Repeat("a", MaxIsolationProofGenerationBytes+1) + `","runtimeGeneration":"runtime","status":"verified","restrictedIdentity":true,"capabilitiesCleared":true,"noNewPrivileges":true,"supplementaryGroupsCleared":true,"rawPacketSocketDenied":true}}`, code: ErrorCodeOversizedPayloadMetadata},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(ClientOptions{Transport: TransportFunc(func(context.Context, TransportRequest) (TransportResponse, error) {
				return TransportResponse{Encoded: []byte(tt.body)}, nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Readiness(context.Background(), request)
			var protocolErr *ProtocolError
			if !errors.As(err, &protocolErr) || protocolErr.Code != tt.code {
				t.Fatalf("Readiness() error = %v, want %s", err, tt.code)
			}
		})
	}
}
