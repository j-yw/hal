package firecrackerhost

import "encoding/binary"

const minimalWorkReadyMagic = "HLMINRD2"

// Distinct public metadata discriminator. It is never a ready/current result;
// only the original producer receiver can associate its one owned endpoint.
func encodeMinimalWorkReady(event minimalControlReadinessEventV1) ([]byte, error) {
	wire, err := encodeMinimalControlReadinessEvent(event)
	if err != nil {
		return nil, err
	}
	copy(wire[:8], minimalWorkReadyMagic)
	binary.BigEndian.PutUint16(wire[8:10], 2)
	return wire, nil
}

func decodeMinimalWorkReady(wire []byte) (minimalControlReadinessEventV1, error) {
	if len(wire) < minimalControlReadinessEventMin || len(wire) > minimalControlReadinessEventMax ||
		string(wire[:8]) != minimalWorkReadyMagic || binary.BigEndian.Uint16(wire[8:10]) != 2 ||
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
