package firecrackerhost

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

func TestMinimalWorkWireExactLayoutAndBounds(t *testing.T) {
	for _, direction := range []uint8{1, 2} {
		for _, operation := range []guestagent.Operation{guestagent.OperationExec, guestagent.OperationCopyIn, guestagent.OperationCopyOut} {
			for _, size := range []int{1, 1 << 20} {
				header := minimalWorkHeader{direction: direction, operation: operation, ordinal: 7, maximum: 1 << 20, session: [32]byte{4}, binding: [32]byte{5}}
				payload := bytes.Repeat([]byte{0x73}, size)
				wire, err := encodeMinimalWorkFrame(header, payload)
				if err != nil || len(wire) != 92+size || binary.BigEndian.Uint32(wire[:4]) != uint32(88+size) ||
					string(wire[4:12]) != "HLMINWK1" || wire[12] != direction || wire[14] != 0 || wire[15] != 0 ||
					binary.BigEndian.Uint64(wire[16:24]) != 7 || binary.BigEndian.Uint32(wire[24:28]) != 1<<20 ||
					!bytes.Equal(wire[28:60], header.session[:]) || !bytes.Equal(wire[60:92], header.binding[:]) || !bytes.Equal(wire[92:], payload) {
					t.Fatal("private work layout differs", err)
				}
				got, body, err := readMinimalWorkFrame(bytes.NewReader(wire[1:]), wire[0], func(h minimalWorkHeader) bool { return h == header })
				if err != nil || got != header || !bytes.Equal(body, payload) {
					t.Fatal("private work round trip differs", err)
				}
				clear(body)
			}
		}
	}
}

func TestMinimalWorkWireRejectsHeaderBeforePayload(t *testing.T) {
	header := minimalWorkHeader{direction: 2, operation: guestagent.OperationCopyIn, ordinal: 1, maximum: 64, session: [32]byte{1}, binding: [32]byte{2}}
	wire, err := encodeMinimalWorkFrame(header, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{4, 12, 13, 14, 15, 23, 27, 28, 60} {
		bad := bytes.Clone(wire)
		bad[index] ^= 0xff
		reader := bytes.NewReader(bad[1:])
		_, body, err := readMinimalWorkFrame(reader, bad[0], func(h minimalWorkHeader) bool { return h == header })
		if err == nil || body != nil || reader.Len() != 2 {
			t.Fatalf("header byte %d did not reject before payload", index)
		}
	}
	for _, size := range []uint32{0, 88, 1048665, ^uint32(0)} {
		bad := bytes.Clone(wire)
		binary.BigEndian.PutUint32(bad[:4], size)
		reader := bytes.NewReader(bad[1:])
		_, body, err := readMinimalWorkFrame(reader, bad[0], func(minimalWorkHeader) bool { return true })
		if err == nil || body != nil || reader.Len() != len(wire)-4 {
			t.Fatal("length did not reject before header/body", size)
		}
	}
	for n := 1; n < len(wire); n++ {
		_, body, err := readMinimalWorkFrame(bytes.NewReader(wire[1:n]), wire[0], func(minimalWorkHeader) bool { return true })
		if err == nil || body != nil {
			t.Fatal("partial frame accepted", n)
		}
	}
	if err := writeMinimalWorkFrame(io.Discard, header, bytes.Repeat([]byte{1}, 65)); err == nil {
		t.Fatal("response exceeded its requested maximum")
	}
}

func TestMinimalWorkReadyKeepsDistinctDiscriminator(t *testing.T) {
	oldWire, event := minimalReadinessGolden(t)
	wire, err := encodeMinimalWorkReady(event)
	if err != nil || string(wire[:8]) != "HLMINRD2" || binary.BigEndian.Uint16(wire[8:10]) != 2 || !bytes.Equal(wire[10:], oldWire[10:]) {
		t.Fatal("work-ready discriminator/layout differs", err)
	}
	got, err := decodeMinimalWorkReady(wire)
	if err != nil || got != event {
		t.Fatal("work-ready metadata differs", err)
	}
	if _, err := decodeMinimalControlReadinessEvent(wire); err == nil {
		t.Fatal("old decoder admitted new work-ready discriminator")
	}
	if _, err := decodeMinimalWorkReady(oldWire); err == nil {
		t.Fatal("work-ready decoder admitted old readiness discriminator")
	}
	for n := 0; n < len(wire); n++ {
		if _, err := decodeMinimalWorkReady(wire[:n]); err == nil {
			t.Fatal("partial work-ready metadata accepted", n)
		}
	}
}
