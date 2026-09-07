package firecrackerhost

import (
	"encoding/base64"
	"encoding/binary"
)

const (
	minimalControlReadinessEventMagic = "HLMINRD1"
	minimalControlReadinessEventBase  = 174
	minimalControlReadinessEventMin   = 175
	minimalControlReadinessEventMax   = 238
)

// This value is decoded public metadata, never current readiness authority.
type minimalControlReadinessEventV1 struct {
	configSHA256           [32]byte
	supervisorGeneration   string
	processGeneration      string
	transportGeneration    uint64
	sessionID              [32]byte
	readinessBindingSHA256 [32]byte
}

func encodeMinimalControlReadinessEvent(event minimalControlReadinessEventV1) ([]byte, error) {
	if !validMinimalControlReadinessEvent(event) {
		return nil, errL8RuntimeOwnerProtocol
	}
	n := len(event.processGeneration)
	wire := make([]byte, minimalControlReadinessEventBase+n)
	copy(wire[:8], minimalControlReadinessEventMagic)
	binary.BigEndian.PutUint16(wire[8:10], 1)
	binary.BigEndian.PutUint64(wire[10:18], 1)
	binary.BigEndian.PutUint64(wire[18:26], 2)
	copy(wire[26:58], event.configSHA256[:])
	copy(wire[58:101], event.supervisorGeneration)
	wire[101] = byte(n)
	copy(wire[102:102+n], event.processGeneration)
	binary.BigEndian.PutUint64(wire[102+n:110+n], event.transportGeneration)
	copy(wire[110+n:142+n], event.sessionID[:])
	copy(wire[142+n:], event.readinessBindingSHA256[:])
	return wire, nil
}

func decodeMinimalControlReadinessEvent(wire []byte) (minimalControlReadinessEventV1, error) {
	if len(wire) < minimalControlReadinessEventMin || len(wire) > minimalControlReadinessEventMax ||
		string(wire[:8]) != minimalControlReadinessEventMagic || binary.BigEndian.Uint16(wire[8:10]) != 1 ||
		binary.BigEndian.Uint64(wire[10:18]) != 1 || binary.BigEndian.Uint64(wire[18:26]) != 2 {
		return minimalControlReadinessEventV1{}, errL8RuntimeOwnerProtocol
	}
	n := int(wire[101])
	if n < 1 || n > 64 || len(wire) != minimalControlReadinessEventBase+n {
		return minimalControlReadinessEventV1{}, errL8RuntimeOwnerProtocol
	}
	event := minimalControlReadinessEventV1{supervisorGeneration: string(wire[58:101]),
		processGeneration: string(wire[102 : 102+n]), transportGeneration: binary.BigEndian.Uint64(wire[102+n : 110+n])}
	copy(event.configSHA256[:], wire[26:58])
	copy(event.sessionID[:], wire[110+n:142+n])
	copy(event.readinessBindingSHA256[:], wire[142+n:])
	if !validMinimalControlReadinessEvent(event) {
		return minimalControlReadinessEventV1{}, errL8RuntimeOwnerProtocol
	}
	return event, nil
}

func validMinimalControlReadinessEvent(event minimalControlReadinessEventV1) bool {
	if event.configSHA256 == ([32]byte{}) || event.sessionID == ([32]byte{}) || event.readinessBindingSHA256 == ([32]byte{}) ||
		event.transportGeneration == 0 || len(event.supervisorGeneration) != 43 || !validL8RuntimeOwnerToken(event.supervisorGeneration) ||
		len(event.processGeneration) < 1 || len(event.processGeneration) > 64 || !validL8RuntimeOwnerSafeID(event.processGeneration) {
		return false
	}
	first := event.processGeneration[0]
	if !(first >= 'a' && first <= 'z' || first >= 'A' && first <= 'Z' || first >= '0' && first <= '9') {
		return false
	}
	// The existing helper already checked canonical encoding and 32-byte size.
	// Only this selected event rejects a decoded-zero supervisor generation.
	supervisor, _ := base64.RawURLEncoding.DecodeString(event.supervisorGeneration)
	for _, b := range supervisor {
		if b != 0 {
			return true
		}
	}
	return false
}
