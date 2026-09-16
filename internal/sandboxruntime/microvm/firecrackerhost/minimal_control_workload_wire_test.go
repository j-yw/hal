//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

func TestMinimalHostWorkloadPartialWireOwnership(t *testing.T) {
	for _, fault := range []string{"header_error", "body_error", "header_panic", "body_panic"} {
		t.Run(fault, func(t *testing.T) {
			prefix := minimalControllerTestPrefix(true, 32)
			reader := &minimalControllerAliasingReader{prefix: prefix[1:]}
			switch fault {
			case "header_error":
				reader.failAt = 1
			case "body_error":
				reader.failAt = 2
			case "header_panic":
				reader.panicAt = 1
			case "body_panic":
				reader.panicAt = 2
			}
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				wire, err := readMinimalWorkloadResponse(reader, prefix[0])
				if err == nil || wire != nil {
					t.Error("partial wire escaped")
				}
			}()
			if panicked != (reader.panicAt != 0) || len(reader.aliases) != reader.panicAt+reader.failAt {
				t.Fatal("actual read failure boundary was not reached")
			}
			for _, alias := range reader.aliases {
				if !bytes.Equal(alias, make([]byte, len(alias))) {
					t.Fatal("partial owned buffer was not cleared")
				}
			}
		})
	}
}

func TestMinimalHostWorkloadWireBoundBeforeBody(t *testing.T) {
	for _, length := range []uint32{0, session.GCMTagBytes - 1, minimalcontrol.MaxWorkloadMessageBytes + session.GCMTagBytes + 1, ^uint32(0)} {
		prefix := minimalControllerTestPrefix(true, length)
		reader := &minimalControllerAliasingReader{prefix: prefix[1:]}
		if wire, err := readMinimalWorkloadResponse(reader, prefix[0]); err == nil || wire != nil || len(reader.aliases) != 1 {
			t.Fatal("invalid header reached body allocation/read", length)
		}
	}
	for _, length := range []uint32{session.GCMTagBytes, minimalcontrol.MaxWorkloadMessageBytes + session.GCMTagBytes} {
		prefix := minimalControllerTestPrefix(true, length)
		reader := &minimalControllerAliasingReader{prefix: prefix[1:]}
		wire, err := readMinimalWorkloadResponse(reader, prefix[0])
		if err != nil || len(wire) != session.SecureRecordHeaderBytes+int(length) || len(reader.aliases) != 2 {
			t.Fatal("valid bounded extent rejected", length, err)
		}
		clear(wire)
	}
}

func TestMinimalHostWorkloadInvalidCallsPreserveOwner(t *testing.T) {
	a := newMinimalControlAdmissionFixture(t)
	code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		f := newMinimalControllerFixture(t, admission)
		return withMinimalWorkloadController(context.Background(), f.transport, admission, time.Now().Add(3*time.Second), func(c *minimalControlController) error {
			ready := minimalControllerRequireReady(t, c)
			transport, err := ready.workloadTransport()
			if err != nil {
				t.Fatal(err)
			}
			for _, fault := range []string{"nil_context", "canceled", "expired", "version", "readiness", "operation", "empty", "oversized", "zero_response", "large_response"} {
				t.Run(fault, func(t *testing.T) {
					ctx := context.Background()
					request := guestagent.TransportRequest{ProtocolVersion: guestagent.ProtocolVersionV1, Operation: guestagent.OperationExec, Encoded: []byte("opaque"), MaxResponseBytes: 1024}
					switch fault {
					case "nil_context":
						ctx = nil
					case "canceled":
						var cancel context.CancelFunc
						ctx, cancel = context.WithCancel(ctx)
						cancel()
					case "expired":
						var cancel context.CancelFunc
						ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
						defer cancel()
					case "version":
						request.ProtocolVersion = "unsupported"
					case "readiness":
						request.Operation = guestagent.OperationReadiness
					case "operation":
						request.Operation = "unsupported"
					case "empty":
						request.Encoded = nil
					case "oversized":
						request.Encoded = make([]byte, minimalcontrol.MaxWorkloadPayloadBytes+1)
					case "zero_response":
						request.MaxResponseBytes = 0
					case "large_response":
						request.MaxResponseBytes = minimalcontrol.MaxWorkloadPayloadBytes + 1
					}
					if response, err := transport.RoundTrip(ctx, request); err == nil || response.Encoded != nil || !ready.Current() {
						t.Fatal("invalid caller dispatched or consumed live owner", err)
					}
					c.mu.Lock()
					consumed := c.pendingWork != nil || c.workOrdinal != 0
					c.mu.Unlock()
					if consumed {
						t.Fatal("invalid caller consumed an ordinal/operation")
					}
				})
			}
			return nil
		})
	})
	if code != 0 {
		t.Fatal("valid original owner control", code)
	}
}
