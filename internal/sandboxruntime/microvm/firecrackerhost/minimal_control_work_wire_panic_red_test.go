package firecrackerhost

import (
	"bytes"
	"io"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

type minimalWorkWirePanicReader struct {
	source   io.Reader
	reads    int
	retained []byte
}

func (reader *minimalWorkWirePanicReader) Read(payload []byte) (int, error) {
	reader.reads++
	if reader.reads == 3 {
		reader.retained = payload
		payload[0] = 0x73
		panic("private fixture payload read failure")
	}
	return reader.source.Read(payload)
}

func TestMinimalWorkWirePanicClearsPartialPayload(t *testing.T) {
	header := minimalWorkHeader{direction: 1, operation: guestagent.OperationExec, ordinal: 1, maximum: 64,
		session: [32]byte{1}, binding: [32]byte{2}}
	wire, err := encodeMinimalWorkFrame(header, bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	reader := &minimalWorkWirePanicReader{source: bytes.NewReader(wire[1:])}
	panicked := false
	func() {
		defer func() { panicked = recover() != nil }()
		_, _, _ = readMinimalWorkFrame(reader, wire[0], func(h minimalWorkHeader) bool { return h == header })
	}()
	if !panicked || reader.reads != 3 || len(reader.retained) != 32 {
		t.Fatal("actual allocated payload read/panic prerequisite was not reached")
	}
	if !bytes.Equal(reader.retained, make([]byte, len(reader.retained))) {
		t.Fatal("frame reader panic retained partially filled owned payload")
	}
}
