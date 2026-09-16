//go:build linux

package firecrackerhost

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

func TestMinimalHostInspectionWireExactCodeFour(t *testing.T) {
	for _, direction := range []uint8{minimalWorkRequest, minimalWorkResponse} {
		t.Run(map[uint8]string{minimalWorkRequest: "request", minimalWorkResponse: "response"}[direction], func(t *testing.T) {
			header := minimalWorkHeader{direction: direction, operation: minimalHostInspectionOperation,
				ordinal: 9, maximum: 2048, session: [32]byte{1}, binding: [32]byte{2}}
			payload := []byte(minimalHostInspectionRequest)
			if direction == minimalWorkResponse {
				payload = bytes.Repeat([]byte{'x'}, 2048) // Opaque codec bound, not a proof.
			}
			// Build actual code-4 input independently so the old encoder's refusal
			// cannot prevent reaching the real fixed-header decoder.
			legacy := header
			legacy.operation = guestagent.OperationExec
			wire, err := encodeMinimalWorkFrame(legacy, payload)
			if err != nil || len(minimalHostInspectionRequest) != 76 {
				t.Fatal("original wire/canonical request prerequisite")
			}
			defer clear(wire)
			wire[13] = 4
			got, body, err := readMinimalWorkFrame(bytes.NewReader(wire[1:]), wire[0], func(h minimalWorkHeader) bool { return h == header })
			defer clear(body)
			if err != nil || got != header || !bytes.Equal(body, payload) {
				t.Error("actual private decoder rejected selected code 4")
			}
			encoded, err := encodeMinimalWorkFrame(header, payload)
			defer clear(encoded)
			if err != nil || !bytes.Equal(encoded, wire) {
				t.Error("actual private encoder does not emit exact code-4 framing")
			}
		})
	}
}

func TestMinimalHostInspectionWireRejectsBoundsBeforeBody(t *testing.T) {
	for _, direction := range []uint8{minimalWorkRequest, minimalWorkResponse} {
		header := minimalWorkHeader{direction: direction, operation: guestagent.OperationExec,
			ordinal: 1, maximum: 2048, session: [32]byte{1}, binding: [32]byte{2}}
		wire, err := encodeMinimalWorkFrame(header, []byte(minimalHostInspectionRequest))
		if err != nil {
			t.Fatal("original codec fixture")
		}
		defer clear(wire)
		wire[13] = 4
		type headerFault struct {
			name   string
			mutate func([]byte)
		}
		cases := []headerFault{
			{"zero-maximum", func(b []byte) { binary.BigEndian.PutUint32(b[24:28], 0) }},
			{"smaller-maximum", func(b []byte) { binary.BigEndian.PutUint32(b[24:28], 2047) }},
			{"larger-maximum", func(b []byte) { binary.BigEndian.PutUint32(b[24:28], 2049) }},
			{"zero-ordinal", func(b []byte) { clear(b[16:24]) }},
			{"empty-session", func(b []byte) { clear(b[28:60]) }},
			{"empty-binding", func(b []byte) { clear(b[60:92]) }},
			{"reserved", func(b []byte) { b[14] = 1 }},
		}
		if direction == minimalWorkRequest {
			cases = append(cases,
				headerFault{"short-request", func(b []byte) { binary.BigEndian.PutUint32(b[:4], 88+75) }},
				headerFault{"long-request", func(b []byte) { binary.BigEndian.PutUint32(b[:4], 88+77) }})
		} else {
			cases = append(cases, headerFault{"oversized-response", func(b []byte) { binary.BigEndian.PutUint32(b[:4], 88+2049) }})
		}
		for _, test := range cases {
			name := map[uint8]string{minimalWorkRequest: "request/", minimalWorkResponse: "response/"}[direction] + test.name
			t.Run(name, func(t *testing.T) {
				bad := bytes.Clone(wire)
				defer clear(bad)
				test.mutate(bad)
				reader := bytes.NewReader(bad[1:])
				_, body, err := readMinimalWorkFrame(reader, bad[0], func(minimalWorkHeader) bool { return true })
				defer clear(body)
				if err == nil || body != nil || reader.Len() != len(minimalHostInspectionRequest) {
					t.Fatal("invalid inspection header consumed body or yielded data")
				}
			})
		}
	}
}
