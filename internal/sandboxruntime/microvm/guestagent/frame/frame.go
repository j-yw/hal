// Package frame implements the bounded one-request/one-response stream framing
// shared by the L5 Firecracker host bridge and guest vsock listener.
package frame

import (
	"encoding/binary"
	"errors"
	"io"
)

const headerBytes = 4

var (
	// ErrPayloadTooLarge means a frame declared or supplied more payload bytes
	// than its caller-approved bound.
	ErrPayloadTooLarge = errors.New("guest frame payload exceeds limit")
	// ErrInvalidLimit means a caller did not supply a usable frame bound.
	ErrInvalidLimit = errors.New("guest frame limit is invalid")
)

// Write writes one length-prefixed payload without requiring a stream
// half-close to delimit the request.
func Write(writer io.Writer, payload []byte, limit int64) error {
	maximum, err := maximumPayload(limit)
	if err != nil {
		return err
	}
	if uint64(len(payload)) > maximum {
		return ErrPayloadTooLarge
	}
	var header [headerBytes]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeFull(writer, header[:]); err != nil {
		return err
	}
	return writeFull(writer, payload)
}

// Read reads exactly one length-prefixed payload without relying on a stream
// half-close. It rejects oversized declarations before allocating payload data.
func Read(reader io.Reader, limit int64) ([]byte, error) {
	maximum, err := maximumPayload(limit)
	if err != nil {
		return nil, err
	}
	var header [headerBytes]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := uint64(binary.BigEndian.Uint32(header[:]))
	if length > maximum {
		return nil, ErrPayloadTooLarge
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func maximumPayload(limit int64) (uint64, error) {
	if limit < 0 {
		return 0, ErrInvalidLimit
	}
	const maximumFramePayload = uint64(^uint32(0))
	if uint64(limit) > maximumFramePayload {
		return maximumFramePayload, nil
	}
	return uint64(limit), nil
}

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}
