//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"io"
	"math"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

// Work support is selected before authentication; it is not inferred from the
// unchanged readiness capability and cannot be enabled by a later request.
func withMinimalWorkloadController(ctx context.Context, transport *minimalControlTransport, admission *minimalControlSupervisorAdmission, deadline time.Time, consume func(*minimalControlController) error) error {
	return withMinimalControlControllerMode(ctx, transport, admission, deadline, true, consume)
}

func (r *minimalControlReadiness) workloadTransport() (guestagent.Transport, error) {
	if !r.Current() || !r.controller.workload {
		return nil, errMinimalControlController
	}
	return minimalControlWorkloadTransport{ready: r}, nil
}

type minimalControlWorkloadTransport struct{ ready *minimalControlReadiness }

// Mutable fields and the response buffer belong to controller.mu. The caller
// takes ownership of the decoded response only after the exchange ends.
type minimalControlWork struct {
	ordinal  uint64
	maximum  int64
	done     chan struct{}
	response []byte
	received bool
}

func (transport minimalControlWorkloadTransport) RoundTrip(ctx context.Context, request guestagent.TransportRequest) (response guestagent.TransportResponse, resultErr error) {
	r := transport.ready
	if !minimalWorkloadContextCurrent(ctx) || !validMinimalWorkloadRequest(request) || !r.Current() || !r.controller.workload {
		return response, errMinimalControlController
	}
	c := r.controller
	c.mu.Lock()
	if c.retired || c.ready != r || c.ctx.Err() != nil || !time.Now().Before(r.hardExpiry) || c.workState == nil || !minimalWorkloadContextCurrent(ctx) {
		c.mu.Unlock()
		return response, errMinimalControlController
	}
	if c.pendingWork != nil {
		c.mu.Unlock()
		return response, guestagent.NewProtocolError(guestagent.ErrorCodeServerBusy, request.Operation, "transport", errMinimalControlController)
	}
	if c.workOrdinal == math.MaxUint64 {
		c.mu.Unlock()
		return response, errMinimalControlController
	}
	c.workOrdinal++
	op := &minimalControlWork{ordinal: c.workOrdinal, maximum: request.MaxResponseBytes, done: make(chan struct{})}
	c.pendingWork = op
	stream, state := c.stream, c.workState
	c.workWriters.Add(1) // Serialized with retire before the owner's Wait.
	c.mu.Unlock()

	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(interrupted)
		c.interruptWorkload(stream)
	})
	defer func() {
		if !stop() {
			<-interrupted
		}
		if request.Operation == minimalInspectionOperation {
			// The synchronous request writer and cancellation callback have
			// joined; only now may a fresh inspection response be accepted.
			_, proofErr := decodeMinimalGuestInspection(response.Encoded, r.inspectionTopology, r.inspectionRuntime)
			if resultErr != nil || proofErr != nil || !minimalWorkloadContextCurrent(ctx) || !r.Current() {
				c.interruptWorkload(stream)
				<-c.done
				response, resultErr = guestagent.TransportResponse{}, errMinimalControlController
			}
		}
		c.mu.Lock()
		if c.pendingWork == op {
			c.pendingWork = nil
		}
		if resultErr != nil {
			clear(op.response)
		}
		c.mu.Unlock()
	}()
	if c.writeWorkload(ctx, stream, state, r, op, request.Encoded) != nil {
		c.interruptWorkload(stream)
	}
	select {
	case <-op.done:
	case <-ctx.Done():
		c.interruptWorkload(stream)
		<-c.done // Writer already joined; retain any completely decoded reply.
	case <-c.done:
	}
	c.mu.Lock()
	received := op.received
	response.Encoded = op.response
	c.mu.Unlock()
	if !received {
		return guestagent.TransportResponse{}, errMinimalControlController
	}
	// Keep a correlated completed reply even if caller cancellation wins the
	// select. The existing Client decides whether it proves CopyIn publication.
	if minimalWorkloadContextCurrent(ctx) && r.Current() {
		if stream.SetDeadline(r.hardExpiry) != nil {
			c.interruptWorkload(stream)
		}
	} else {
		c.interruptWorkload(stream)
	}
	return response, nil
}

func minimalWorkloadContextCurrent(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	return !ok || time.Now().Before(deadline)
}

func validMinimalWorkloadRequest(request guestagent.TransportRequest) bool {
	if request.ProtocolVersion != guestagent.ProtocolVersionV1 || len(request.Encoded) == 0 ||
		len(request.Encoded) > minimalcontrol.MaxWorkloadPayloadBytes || request.MaxResponseBytes <= 0 || request.MaxResponseBytes > minimalcontrol.MaxWorkloadPayloadBytes {
		return false
	}
	if request.Operation == minimalInspectionOperation {
		return request.MaxResponseBytes == minimalInspectionMaximum && bytes.Equal(request.Encoded, []byte(minimalInspectionRequest))
	}
	return (request.Operation == guestagent.OperationExec || request.Operation == guestagent.OperationCopyIn || request.Operation == guestagent.OperationCopyOut) && !selectsMinimalInspection(request.Encoded)
}

func (c *minimalControlController) interruptWorkload(stream *minimalControlStream) {
	c.retire()
	if stream != nil {
		_ = stream.Close()
	}
}

func (c *minimalControlController) writeWorkload(ctx context.Context, stream *minimalControlStream, state *session.State, r *minimalControlReadiness, op *minimalControlWork, payload []byte) (err error) {
	defer c.workWriters.Done()
	defer func() {
		if recover() != nil {
			err = errMinimalControlController
		}
	}()
	deadline := r.hardExpiry
	if caller, ok := ctx.Deadline(); ok {
		deadline = earlierMinimalControlTime(deadline, caller)
	}
	if !minimalWorkloadContextCurrent(ctx) || !r.Current() || stream.SetDeadline(deadline) != nil {
		return errMinimalControlController
	}
	encoded, err := r.binding.EncodeWorkload(payload, op.ordinal, r.sessionID)
	defer clear(encoded)
	if err != nil || !minimalWorkloadContextCurrent(ctx) || state.WriteApplication(stream, session.FrameTypeControlRequest, encoded) != nil {
		return errMinimalControlController
	}
	return nil
}

// Sole selected reader for the entire post-readiness lifetime. Only bounded
// decoding runs under the session mutex; publication uses the controller mutex
// after OpenApplication returns. No competing RoundTrip reader is started.
func (c *minimalControlController) readWorkloadResponses(stream *minimalControlStream, state *session.State, r *minimalControlReadiness) {
	defer func() { _ = recover() }()
	for {
		var first [1]byte
		if _, err := io.ReadFull(stream, first[:]); err != nil {
			return
		}
		c.mu.Lock()
		op := c.pendingWork
		valid := !c.retired && op != nil && !op.received
		c.mu.Unlock()
		if !valid {
			return
		}
		wire, err := readMinimalWorkloadResponse(stream, first[0])
		if err != nil {
			return
		}
		var inner []byte
		plaintext, err := state.OpenApplication(wire, func(kind session.FrameType, payload []byte) error {
			var decodeErr error
			inner, decodeErr = r.binding.DecodeWorkloadResponse(kind, payload, op.ordinal, r.sessionID)
			if decodeErr != nil || int64(len(inner)) > op.maximum {
				return errMinimalControlController
			}
			return nil
		})
		clear(wire)
		clear(plaintext)
		if err != nil {
			clear(inner)
			return
		}
		c.mu.Lock()
		if c.pendingWork != op || op.received {
			c.mu.Unlock()
			clear(inner)
			return
		}
		op.response, op.received = inner, true
		close(op.done)
		c.mu.Unlock()
	}
}

func readMinimalWorkloadResponse(reader io.Reader, first byte) ([]byte, error) {
	var header [session.SecureRecordHeaderBytes]byte
	defer clear(header[:])
	header[0] = first
	if _, err := io.ReadFull(reader, header[1:]); err != nil {
		return nil, errMinimalControlController
	}
	parsed, err := session.ParseRecordHeaderPrefix(header[:], session.ChannelControl)
	if err != nil || parsed.CiphertextLength > minimalcontrol.MaxWorkloadMessageBytes+session.GCMTagBytes {
		return nil, errMinimalControlController
	}
	wire := make([]byte, len(header)+int(parsed.CiphertextLength))
	complete := false
	defer func() {
		if !complete {
			clear(wire)
		}
	}()
	copy(wire, header[:])
	if _, err := io.ReadFull(reader, wire[len(header):]); err != nil {
		return nil, errMinimalControlController
	}
	complete = true
	return wire, nil
}
