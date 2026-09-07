//go:build linux

package firecrackerhost

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

// Retain aliases of the actual destination buffers, not copies of expected
// cleanup output. A Reader may use all of p as scratch even on a short read.
type minimalControllerAliasingReader struct {
	prefix  []byte
	aliases [][]byte
	failAt  int
	panicAt int
}

func (r *minimalControllerAliasingReader) Read(p []byte) (int, error) {
	r.aliases = append(r.aliases, p)
	for i := range p {
		p[i] = 0x73
	}
	call := len(r.aliases)
	if call == r.panicAt {
		panic("private fixture panic")
	}
	if call == r.failAt {
		return len(p) / 2, io.ErrUnexpectedEOF
	}
	if call == 1 {
		return copy(p, r.prefix), nil
	}
	return len(p), nil
}

func minimalControllerTestPrefix(record bool, length uint32) []byte {
	if !record {
		prefix := make([]byte, 4)
		binary.BigEndian.PutUint32(prefix, length)
		return prefix
	}
	prefix := make([]byte, session.SecureRecordHeaderBytes)
	copy(prefix, "HL8F")
	prefix[4], prefix[5] = session.WireVersion, byte(session.FrameTypeControlResponse)
	binary.BigEndian.PutUint32(prefix[16:20], length)
	return prefix
}

func TestMinimalControlControllerWirePartialBuffersAreCleared(t *testing.T) {
	for _, record := range []bool{false, true} {
		name := "handshake"
		read := readMinimalControllerHandshake
		if record {
			name, read = "record", readMinimalControllerRecord
		}
		for _, failure := range []string{"prefix-error", "body-error", "prefix-panic", "body-panic"} {
			t.Run(name+"/"+failure, func(t *testing.T) {
				r := &minimalControllerAliasingReader{prefix: minimalControllerTestPrefix(record, 32)}
				switch failure {
				case "prefix-error":
					r.failAt = 1
				case "body-error":
					r.failAt = 2
				case "prefix-panic":
					r.panicAt = 1
				case "body-panic":
					r.panicAt = 2
				}
				panicked := false
				func() {
					defer func() { panicked = recover() != nil }()
					wire, err := read(r)
					if err == nil || wire != nil {
						t.Error("partial wire escaped")
					}
				}()
				if panicked != (r.panicAt != 0) {
					t.Fatal("panic branch not reached")
				}
				wantCalls := r.failAt + r.panicAt
				if len(r.aliases) != wantCalls {
					t.Fatalf("read calls=%d want=%d", len(r.aliases), wantCalls)
				}
				for _, alias := range r.aliases {
					if !bytes.Equal(alias, make([]byte, len(alias))) {
						t.Fatal("owned partial buffer retained bytes")
					}
				}
			})
		}
	}
}

func TestMinimalControlControllerWireLimitsBeforeBodyRead(t *testing.T) {
	for _, record := range []bool{false, true} {
		name, read := "handshake", readMinimalControllerHandshake
		minimum, maximum := uint32(1), uint32(session.MaxHandshakeInnerBytes)
		if record {
			name, read = "record", readMinimalControllerRecord
			minimum, maximum = session.GCMTagBytes, minimalcontrol.MaxMessageBytes+session.GCMTagBytes
		}
		for _, size := range []uint32{0, minimum - 1, minimum, maximum, maximum + 1, ^uint32(0)} {
			t.Run(name+"/"+strconv.FormatUint(uint64(size), 10), func(t *testing.T) {
				r := &minimalControllerAliasingReader{prefix: minimalControllerTestPrefix(record, size)}
				wire, err := read(r)
				defer clear(wire)
				valid := size >= minimum && size <= maximum
				if (err == nil) != valid {
					t.Fatalf("size=%d error=%v", size, err)
				}
				if !valid && (wire != nil || len(r.aliases) != 1) {
					t.Fatal("invalid declaration reached body allocation/read")
				}
				if valid && (len(r.aliases) != 2 || len(wire) != len(r.prefix)+int(size)) {
					t.Fatal("exact accepted bound not read")
				}
				if !bytes.Equal(r.aliases[0], make([]byte, len(r.prefix))) {
					t.Fatal("prefix scratch not cleared")
				}
			})
		}
	}
}

type minimalControllerShortWriter struct {
	n     int
	err   error
	calls int
}

func (w *minimalControllerShortWriter) Write([]byte) (int, error) { w.calls++; return w.n, w.err }

func TestMinimalControlControllerWireRejectsPartialWrites(t *testing.T) {
	for _, test := range []struct {
		name string
		n    int
		err  error
	}{
		{"zero", 0, nil}, {"partial", 1, nil}, {"oversized", 4, nil}, {"transport", 3, errors.New("private transport detail")}, {"complete", 3, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := &minimalControllerShortWriter{n: test.n, err: test.err}
			err := writeMinimalControllerWire(w, []byte{1, 2, 3})
			if (err == nil) != (test.name == "complete") || w.calls != 1 {
				t.Fatal("write retried or ignored unknown completion")
			}
			if err != nil && err != errMinimalControlController {
				t.Fatal("raw write error escaped")
			}
		})
	}
}

func TestMinimalControlControllerEntropyRejectsWrongExtent(t *testing.T) {
	for _, size := range []int{0, 1, 31, 33, 64} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			buffer := bytes.Repeat([]byte{0x73}, size)
			n, err := (minimalControlControllerEntropy{}).Read(buffer)
			if n != 0 || err != errMinimalControlController || !bytes.Equal(buffer, make([]byte, size)) {
				t.Fatal("invalid entropy extent accepted or retained scratch")
			}
		})
	}
}
