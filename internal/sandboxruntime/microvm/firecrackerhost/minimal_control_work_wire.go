package firecrackerhost

import (
	"encoding/binary"
	"io"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
)

const (
	minimalWorkMagic       = "HLMINWK1"
	minimalWorkHeaderBytes = 88
	minimalWorkRequest     = 1
	minimalWorkResponse    = 2
)

// Private work carrier framing, not a new guest protocol or authority issuer.
type minimalWorkHeader struct {
	direction uint8
	operation guestagent.Operation
	ordinal   uint64
	maximum   int64
	session   [32]byte
	binding   [32]byte
}

func minimalWorkOperationCode(operation guestagent.Operation) byte {
	switch operation {
	case guestagent.OperationExec:
		return 1
	case guestagent.OperationCopyIn:
		return 2
	case guestagent.OperationCopyOut:
		return 3
	case minimalInspectionOperation:
		return 4
	default:
		return 0
	}
}

func (header minimalWorkHeader) valid() bool {
	return (header.direction == minimalWorkRequest || header.direction == minimalWorkResponse) &&
		minimalWorkOperationCode(header.operation) != 0 && header.ordinal != 0 && header.maximum > 0 &&
		header.maximum <= minimalcontrol.MaxWorkloadPayloadBytes && header.session != ([32]byte{}) && header.binding != ([32]byte{})
}

func encodeMinimalWorkFrame(header minimalWorkHeader, payload []byte) ([]byte, error) {
	if !header.valid() || len(payload) == 0 || len(payload) > minimalcontrol.MaxWorkloadPayloadBytes || !validMinimalInspectionSize(header, int64(len(payload))) ||
		header.direction == minimalWorkResponse && int64(len(payload)) > header.maximum {
		return nil, errL8RuntimeOwnerProtocol
	}
	wire := make([]byte, 4+minimalWorkHeaderBytes+len(payload))
	binary.BigEndian.PutUint32(wire[:4], uint32(len(wire)-4))
	copy(wire[4:12], minimalWorkMagic)
	wire[12], wire[13] = header.direction, minimalWorkOperationCode(header.operation)
	binary.BigEndian.PutUint64(wire[16:24], header.ordinal)
	binary.BigEndian.PutUint32(wire[24:28], uint32(header.maximum))
	copy(wire[28:60], header.session[:])
	copy(wire[60:92], header.binding[:])
	copy(wire[92:], payload)
	return wire, nil
}

// The sole endpoint reader observes the first byte before reserving its bounded
// receive slot. Fixed-header and expected-peer validation precede allocation.
func readMinimalWorkFrame(reader io.Reader, first byte, validate func(minimalWorkHeader) bool) (minimalWorkHeader, []byte, error) {
	var fixed [4 + minimalWorkHeaderBytes]byte
	defer clear(fixed[:])
	fixed[0] = first
	if _, err := io.ReadFull(reader, fixed[1:4]); err != nil {
		return minimalWorkHeader{}, nil, errL8RuntimeOwnerProtocol
	}
	size := binary.BigEndian.Uint32(fixed[:4])
	if size <= minimalWorkHeaderBytes || size > minimalWorkHeaderBytes+minimalcontrol.MaxWorkloadPayloadBytes {
		return minimalWorkHeader{}, nil, errL8RuntimeOwnerProtocol
	}
	if _, err := io.ReadFull(reader, fixed[4:]); err != nil || string(fixed[4:12]) != minimalWorkMagic || fixed[14] != 0 || fixed[15] != 0 {
		return minimalWorkHeader{}, nil, errL8RuntimeOwnerProtocol
	}
	header := minimalWorkHeader{direction: fixed[12], ordinal: binary.BigEndian.Uint64(fixed[16:24]), maximum: int64(binary.BigEndian.Uint32(fixed[24:28]))}
	switch fixed[13] {
	case 1:
		header.operation = guestagent.OperationExec
	case 2:
		header.operation = guestagent.OperationCopyIn
	case 3:
		header.operation = guestagent.OperationCopyOut
	case 4:
		header.operation = minimalInspectionOperation
	}
	copy(header.session[:], fixed[28:60])
	copy(header.binding[:], fixed[60:92])
	if !header.valid() || !validMinimalInspectionSize(header, int64(size-minimalWorkHeaderBytes)) || validate == nil || !validate(header) || header.direction == minimalWorkResponse && int64(size-minimalWorkHeaderBytes) > header.maximum {
		return minimalWorkHeader{}, nil, errL8RuntimeOwnerProtocol
	}
	payload := make([]byte, int(size)-minimalWorkHeaderBytes)
	handedOff := false
	defer func() {
		if !handedOff {
			clear(payload)
		}
	}()
	if _, err := io.ReadFull(reader, payload); err != nil {
		return minimalWorkHeader{}, nil, errL8RuntimeOwnerProtocol
	}
	handedOff = true
	return header, payload, nil
}

func writeMinimalWorkFrame(writer io.Writer, header minimalWorkHeader, payload []byte) error {
	wire, err := encodeMinimalWorkFrame(header, payload)
	defer clear(wire)
	if err != nil {
		return errL8RuntimeOwnerProtocol
	}
	n, err := writer.Write(wire)
	if err != nil || n != len(wire) {
		return errL8RuntimeOwnerProtocol
	}
	return nil
}
