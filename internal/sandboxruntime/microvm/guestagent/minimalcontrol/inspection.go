package minimalcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
)

const inspectionRequest = `{"operation":"inspect_isolation","protocolVersion":"guest-agent-minimal-v1"}`
const inspectionUnavailable = `{"operation":"inspect_isolation","protocolVersion":"guest-agent-minimal-v1","error":"unavailable"}`
const maximumInspectionResponseBytes = 2048

type workloadInspector interface {
	InspectWorkloadIsolation(context.Context) (server.IsolationProofResult, error)
}

// Recognition grants no admission: the caller still requires exact canonical
// bytes after the secure tuple/session/ordinal gate. Inspect every root occurrence
// so duplicate/escaped markers cannot fall back to the legacy classifier. Values
// nested inside ordinary exec/copy fields do not select inspection.
func selectsInspection(encoded []byte) bool {
	if bytes.Equal(encoded, []byte(inspectionRequest)) {
		return true
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return false
	}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return false
		}
		name, _ := key.(string)
		operation := strings.EqualFold(name, "operation")
		version := strings.EqualFold(name, "protocolVersion")
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			clear(value)
			return false
		}
		var marker string
		if operation || version {
			_ = json.Unmarshal(value, &marker)
		}
		clear(value)
		if operation && marker == "inspect_isolation" || version && marker == ProtocolVersion {
			return true
		}
	}
	return false
}

func (binding Binding) encodeInspection(result server.IsolationProofResult) ([]byte, error) {
	if !result.RestrictedIdentity || !result.CapabilitiesCleared || !result.NoNewPrivileges ||
		!result.SupplementaryGroupsCleared || !result.RawPacketSocketDenied ||
		result.Network.Status != guestagent.IsolationProofStatusVerified || !result.Network.SingleInterface ||
		!result.Network.StaticRoutes || !result.Network.ProxyReachable {
		return nil, ErrUnavailable
	}
	proof := guestagent.IsolationProof{Generation: binding.fields["topologyGenerationId"],
		RuntimeGeneration: binding.fields["runtimeGeneration"], Status: guestagent.IsolationProofStatusVerified,
		RestrictedIdentity: true, CapabilitiesCleared: true, NoNewPrivileges: true,
		SupplementaryGroupsCleared: true, RawPacketSocketDenied: true,
		Network: &guestagent.NetworkIsolationProof{Status: guestagent.IsolationProofStatusVerified,
			SingleInterface: true, StaticRoutes: true, ProxyReachable: true}}
	encoded, err := json.Marshal(struct {
		Operation       string                    `json:"operation"`
		ProtocolVersion string                    `json:"protocolVersion"`
		IsolationProof  guestagent.IsolationProof `json:"isolationProof"`
	}{"inspect_isolation", ProtocolVersion, proof})
	if err != nil || len(encoded) == 0 || len(encoded) > maximumInspectionResponseBytes {
		clear(encoded)
		return nil, ErrInvalid
	}
	return encoded, nil
}
