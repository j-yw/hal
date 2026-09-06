package frame

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestL5FramesRoundTripWithoutEOF(t *testing.T) {
	var stream bytes.Buffer
	payload := []byte(`{"protocolVersion":"guest-agent-v1"}`)
	if err := Write(&stream, payload, 1024); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	got, err := Read(&stream, 1024)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

func TestL5FramesFailClosedForOversizeAndTruncation(t *testing.T) {
	var oversized bytes.Buffer
	if err := Write(&oversized, bytes.Repeat([]byte("x"), 9), 9); err != nil {
		t.Fatalf("Write(oversized setup) error = %v", err)
	}
	if _, err := Read(&oversized, 8); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("Read(oversized) error = %v, want ErrPayloadTooLarge", err)
	}

	truncated := bytes.NewBuffer([]byte{0, 0, 0, 4, '{'})
	if _, err := Read(truncated, 8); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Read(truncated) error = %v, want io.ErrUnexpectedEOF", err)
	}
}
