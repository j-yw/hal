// Package minimalcontrol implements injected authenticated minimal readiness.
// It does not select a runtime, bind a listener, execute work or activate
// credentials. Readiness is not network enforcement or terminal cleanup proof.
package minimalcontrol

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strconv"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

const (
	ProtocolVersion = "guest-agent-minimal-v1"
	MaxMessageBytes = 8192
	prelude         = `{"protocolVersion":"guest-agent-minimal-v1","operation":"readiness"}`
	bindingDomain   = "hal/guest-agent-minimal-v1/readiness-binding/v1\x00"
)

var ErrInvalid = errors.New("minimal control input is invalid")

var bindingFields = []string{
	"sandboxId", "executionId", "workerId", "hostId", "runtimeDriver", "runtimeId", "runtimeGeneration",
	"processGeneration", "vsockGeneration", "bootGeneration", "imageGeneration", "imageDigest",
	"workerJobId", "submissionId", "planId", "jobGeneration", "admissionGrantId", "admissionRevision",
	"principalId", "templatePolicyId", "workspacePolicyId", "networkPlanId", "policySnapshotId",
	"proxySessionId", "proxyGenerationId", "topologyGenerationId", "ruleGenerationId",
}

// Binding is a validated immutable copy, with no runtime authority of its own.
type Binding struct{ fields map[string]string }

func NewBinding(identity session.Identity, fields map[string]string) (Binding, error) {
	if identity.Channel != session.ChannelControl || identity.GuestBootNonce == ([32]byte{}) || identity.ImageSHA256 == ([32]byte{}) || !safeID(identity.ControllerKeyGeneration) {
		return Binding{}, ErrInvalid
	}
	if _, err := session.MarshalGuestHello(session.GuestHello{Suite: session.HandshakeSuite1, Identity: identity}); err != nil {
		return Binding{}, ErrInvalid
	}
	if err := validateBindingFields(identity, fields, false); err != nil {
		return Binding{}, err
	}
	return Binding{fields: maps.Clone(fields)}, nil
}

// Prelaunch validation omits only the two generations unavailable before the
// host owns the actual process and control stream. It never synthesizes them.
func validateBindingFields(identity session.Identity, fields map[string]string, prelaunch bool) error {
	count := len(bindingFields)
	if prelaunch {
		count -= 2
		if _, exists := fields["processGeneration"]; exists {
			return ErrInvalid
		}
		if _, exists := fields["vsockGeneration"]; exists {
			return ErrInvalid
		}
	}
	if len(fields) != count {
		return ErrInvalid
	}
	for _, key := range bindingFields {
		if prelaunch && lateBindingField(key) {
			continue
		}
		if err := validateBindingField(identity, key, fields[key]); err != nil {
			return err
		}
	}
	if fields["runtimeDriver"] != "microvm" || fields["runtimeId"] != identity.RuntimeID ||
		fields["runtimeGeneration"] != identity.RuntimeGeneration || fields["bootGeneration"] != identity.BootGeneration || fields["imageGeneration"] != identity.ImageGeneration ||
		!prelaunch && (fields["processGeneration"] != identity.FirecrackerProcessGeneration || fields["vsockGeneration"] != identity.VsockGeneration) {
		return ErrInvalid
	}
	return nil
}

func lateBindingField(key string) bool { return key == "processGeneration" || key == "vsockGeneration" }

func validateBindingField(identity session.Identity, key, value string) error {
	switch key {
	case "imageDigest":
		if value != "sha256-"+hex.EncodeToString(identity.ImageSHA256[:]) {
			return ErrInvalid
		}
	case "admissionRevision":
		revision, err := strconv.ParseUint(value, 10, 64)
		if err != nil || revision == 0 || strconv.FormatUint(revision, 10) != value {
			return ErrInvalid
		}
	default:
		if !safeID(value) {
			return ErrInvalid
		}
	}
	return nil
}

func safeID(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for i := range len(value) {
		ch := value[i]
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || i > 0 && (ch == '.' || ch == '_' || ch == '-') {
			continue
		}
		return false
	}
	return true
}

// Digest binds this immutable tuple to one established public session ID.
func (binding Binding) Digest(sessionID [32]byte) (string, error) {
	if binding.fields == nil || sessionID == ([32]byte{}) {
		return "", ErrInvalid
	}
	var canonical bytes.Buffer
	canonical.WriteString(bindingDomain)
	canonical.Write(sessionID[:])
	writeUint16(&canonical, uint16(len(binding.fields)))
	for _, key := range slices.Sorted(maps.Keys(binding.fields)) {
		for _, value := range []string{key, binding.fields[key]} {
			writeUint16(&canonical, uint16(len(value)))
			canonical.WriteString(value)
		}
	}
	digest := sha256.Sum256(canonical.Bytes())
	return "sha256-" + hex.EncodeToString(digest[:]), nil
}

func writeUint16(buffer *bytes.Buffer, value uint16) {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	buffer.Write(encoded[:])
}

type readinessRequest struct {
	Body struct {
		Binding       map[string]string `json:"binding"`
		BindingDigest string            `json:"bindingDigest"`
	} `json:"body"`
	Operation       string `json:"operation"`
	ProtocolVersion string `json:"protocolVersion"`
	RequestID       string `json:"requestId"`
}

// EncodeReadinessRequest is unavailable until the shared host codec is implemented.
func (binding Binding) EncodeReadinessRequest(requestID string, sessionID [32]byte) ([]byte, error) {
	return nil, ErrUnavailable
}

// ValidateReadinessResponse is unavailable until the shared host codec is implemented.
func (binding Binding) ValidateReadinessResponse(payload []byte, requestID string, sessionID [32]byte) error {
	return ErrUnavailable
}

func (binding Binding) decodeReadiness(payload []byte, sessionID [32]byte) (readinessRequest, error) {
	var request readinessRequest
	if !boundedJSON(payload) || json.Unmarshal(payload, &request) != nil {
		return readinessRequest{}, ErrInvalid
	}
	canonical, err := json.Marshal(request)
	if err != nil || !bytes.Equal(canonical, payload) || request.ProtocolVersion != ProtocolVersion || request.Operation != "readiness" || !canonicalRequestID(request.RequestID) || !maps.Equal(request.Body.Binding, binding.fields) {
		return readinessRequest{}, ErrInvalid
	}
	digest, err := binding.Digest(sessionID)
	if err != nil || request.Body.BindingDigest != digest {
		return readinessRequest{}, ErrInvalid
	}
	return request, nil
}

func canonicalRequestID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == value
}

// The schema only permits ASCII scalar values without escapes or brackets.
// Comparing with the typed canonical encoding also rejects unknown, duplicate,
// aliased and missing keys at every depth, not just encoding/json's last value.
func boundedJSON(payload []byte) bool {
	if len(payload) == 0 || len(payload) > MaxMessageBytes || bytes.IndexByte(payload, '\\') >= 0 {
		return false
	}
	depth := 0
	for _, ch := range payload {
		switch ch {
		case '{', '[':
			depth++
			if depth > 3 {
				return false
			}
		case '}', ']':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}

func encodeReadiness(request readinessRequest, sessionID [32]byte) ([]byte, error) {
	response := struct {
		Body struct {
			BindingDigest          string   `json:"bindingDigest"`
			Capabilities           []string `json:"capabilities"`
			GuestSessionGeneration string   `json:"guestSessionGeneration"`
		} `json:"body"`
		OK              bool   `json:"ok"`
		Operation       string `json:"operation"`
		ProtocolVersion string `json:"protocolVersion"`
		RequestID       string `json:"requestId"`
	}{OK: true, Operation: "readiness", ProtocolVersion: ProtocolVersion, RequestID: request.RequestID}
	response.Body.BindingDigest = request.Body.BindingDigest
	response.Body.Capabilities = []string{"authenticated_minimal_control"}
	response.Body.GuestSessionGeneration = base64.RawURLEncoding.EncodeToString(sessionID[:])
	return json.Marshal(response)
}
