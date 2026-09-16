package firecrackerhost

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

const minimalInspectionOperation = guestagent.Operation("inspect_isolation")
const minimalInspectionRequest = `{"operation":"inspect_isolation","protocolVersion":"guest-agent-minimal-v1"}`
const minimalInspectionMaximum = 2048
const minimalInspectionTimeout = 5 * time.Second

// Both forms are strict canonical schemas. Timing belongs to the host-only IPC
// reply, never a guest proof. These comparison values confer no owner authority.
type minimalGuestInspectionReply struct {
	Operation       guestagent.Operation      `json:"operation"`
	ProtocolVersion string                    `json:"protocolVersion"`
	IsolationProof  guestagent.IsolationProof `json:"isolationProof"`
}

type minimalHostInspectionReply struct {
	minimalGuestInspectionReply
	HardExpiryUnixNano     int64 `json:"hardExpiryUnixNano"`
	RemainingLifetimeNanos int64 `json:"remainingLifetimeNanos"`
}

func validMinimalInspectionProof(reply minimalGuestInspectionReply, topology, runtime string) bool {
	p := reply.IsolationProof
	return topology != "" && runtime != "" && reply.Operation == minimalInspectionOperation && reply.ProtocolVersion == minimalcontrol.ProtocolVersion &&
		p.Generation == topology && p.RuntimeGeneration == runtime && p.Status == guestagent.IsolationProofStatusVerified &&
		p.RestrictedIdentity && p.CapabilitiesCleared && p.NoNewPrivileges && p.SupplementaryGroupsCleared && p.RawPacketSocketDenied &&
		p.Network != nil && p.Network.Status == guestagent.IsolationProofStatusVerified && p.Network.SingleInterface && p.Network.StaticRoutes && p.Network.ProxyReachable
}

func decodeMinimalGuestInspection(payload []byte, topology, runtime string) (minimalGuestInspectionReply, error) {
	var reply minimalGuestInspectionReply
	if len(payload) == 0 || len(payload) > minimalInspectionMaximum || json.Unmarshal(payload, &reply) != nil || !validMinimalInspectionProof(reply, topology, runtime) {
		return minimalGuestInspectionReply{}, errL8RuntimeOwnerProtocol
	}
	canonical, err := json.Marshal(reply)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, payload) {
		return minimalGuestInspectionReply{}, errL8RuntimeOwnerProtocol
	}
	return reply, nil
}

func decodeMinimalHostInspection(payload []byte, topology, runtime string) (minimalHostInspectionReply, error) {
	var reply minimalHostInspectionReply
	if len(payload) == 0 || len(payload) > minimalInspectionMaximum || json.Unmarshal(payload, &reply) != nil || !validMinimalInspectionProof(reply.minimalGuestInspectionReply, topology, runtime) {
		return minimalHostInspectionReply{}, errL8RuntimeOwnerProtocol
	}
	canonical, err := json.Marshal(reply)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, payload) {
		return minimalHostInspectionReply{}, errL8RuntimeOwnerProtocol
	}
	return reply, nil
}

// Inspect every root occurrence, including escaped/duplicate/case-folded keys.
// Recognition only rejects a mismatched carrier; it never normalizes admission.
// Nested ordinary arguments/data containing these strings stay ordinary work.
func selectsMinimalInspection(payload []byte) bool {
	if bytes.Equal(payload, []byte(minimalInspectionRequest)) {
		return true
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
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
		operation, version := strings.EqualFold(name, "operation"), strings.EqualFold(name, "protocolVersion")
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
		if operation && marker == string(minimalInspectionOperation) || version && marker == minimalcontrol.ProtocolVersion {
			return true
		}
	}
	return false
}

// Guard code-specific lengths before payload allocation; the wire codec itself
// remains opaque to JSON, preserving old Exec/Copy framing behavior.
func validMinimalInspectionSize(header minimalWorkHeader, size int64) bool {
	if header.operation != minimalInspectionOperation {
		return true
	}
	return header.maximum == minimalInspectionMaximum &&
		(header.direction == minimalWorkRequest && size == int64(len(minimalInspectionRequest)) ||
			header.direction == minimalWorkResponse && size > 0 && size <= minimalInspectionMaximum)
}

// Protected by the original producer mutex. The absolute session H is pinned;
// the monotonic bound only shortens. Neither is an operation timeout or proof.
type minimalInspectionLifetime struct {
	hardExpiry int64
	notAfter   time.Time
}

func (lifetime minimalInspectionLifetime) current(now time.Time) bool {
	return lifetime.currentAt(now, now.UnixNano())
}

// Separate wall observation makes the two-clock arithmetic directly testable;
// production always supplies both observations from the SAME time.Now value.
func (lifetime minimalInspectionLifetime) currentAt(now time.Time, wallNanos int64) bool {
	return lifetime.hardExpiry > wallNanos && !lifetime.notAfter.IsZero() && now.Before(lifetime.notAfter)
}

func (lifetime minimalInspectionLifetime) accept(admitted, now time.Time, hardExpiry, remaining int64) (minimalInspectionLifetime, error) {
	if admitted.IsZero() || now.Before(admitted) || hardExpiry <= now.UnixNano() || remaining <= 0 || remaining > int64(session.MaxGuestCredentialSessionLifetime) ||
		lifetime.hardExpiry != 0 && (lifetime.hardExpiry != hardExpiry || !lifetime.current(now)) {
		return minimalInspectionLifetime{}, errL8RuntimeOwnerProtocol
	}
	bound := admitted.Add(time.Duration(remaining))
	if !bound.After(admitted) || !now.Before(bound) {
		return minimalInspectionLifetime{}, errL8RuntimeOwnerProtocol
	}
	if !lifetime.notAfter.IsZero() && lifetime.notAfter.Before(bound) {
		bound = lifetime.notAfter
	}
	return minimalInspectionLifetime{hardExpiry: hardExpiry, notAfter: bound}, nil
}
