package minimalcontrol

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

type workloadReadFunc func([]byte) (int, error)

func (read workloadReadFunc) Read(value []byte) (int, error) { return read(value) }

func TestWorkloadTransportPartialReadOwnership(t *testing.T) {
	for _, boundary := range []string{"header-error", "header-panic", "body-error", "body-panic", "complete"} {
		t.Run(boundary, func(t *testing.T) {
			var aliases [][]byte
			calls := 0
			read := workloadReadFunc(func(value []byte) (int, error) {
				calls++
				aliases = append(aliases, value)
				if calls == 1 {
					if len(value) != session.SecureRecordHeaderBytes {
						t.Fatal("reader did not bound header first")
					}
					copy(value, "HL8F")
					value[4], value[5] = session.WireVersion, byte(session.FrameTypeControlRequest)
					binary.BigEndian.PutUint32(value[16:20], 20)
					if boundary == "header-error" {
						return 3, io.ErrUnexpectedEOF
					}
					if boundary == "header-panic" {
						panic("private-reader-panic")
					}
					return len(value), nil
				}
				if calls != 2 || len(value) != 20 {
					t.Fatal("body was not bounded by exact parsed header")
				}
				copy(value, "private-body-canary")
				if boundary == "body-error" {
					return 7, io.ErrUnexpectedEOF
				}
				if boundary == "body-panic" {
					panic("private-reader-panic")
				}
				return len(value), nil
			})
			var result []byte
			var err error
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				result, err = readWorkloadRecord(read)
			}()
			if panicked {
				t.Error("reader panic escaped selected transport boundary")
			}
			if boundary == "complete" {
				if err != nil || len(result) != session.SecureRecordHeaderBytes+20 || !bytes.Contains(result, []byte("private-body-canary")) {
					t.Fatal("successful read did not transfer exact record ownership")
				}
				clear(result)
			} else if result != nil || err != ErrUnavailable {
				t.Errorf("partial read did not return only fixed unavailable error: %v", err)
			}
			for _, alias := range aliases {
				if !bytes.Equal(alias, make([]byte, len(alias))) {
					t.Error("owned partial/header scratch survived return")
				}
			}
		})
	}
}
