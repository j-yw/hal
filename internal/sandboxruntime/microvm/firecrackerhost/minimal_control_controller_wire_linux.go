//go:build linux

package firecrackerhost

import (
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"strconv"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/frame"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

func (c *minimalControlController) authenticate(stream *minimalControlStream, pins minimalControlControllerPins, key ed25519.PrivateKey, originalDeadline time.Time, ownedState **session.State) (state *session.State, ready *minimalControlReadiness, deadline time.Time, err error) {
	defer func() {
		// Preserve the outer task's state ownership even when a panic prevents
		// normal return assignment. Only that task closes/joins and then revokes.
		*ownedState = state
	}()
	handle, generation := stream.Correlation()
	pins.identity.FirecrackerProcessGeneration = handle.ID
	pins.identity.VsockGeneration = strconv.FormatUint(generation, 10)
	pins.fields["processGeneration"], pins.fields["vsockGeneration"] = handle.ID, pins.identity.VsockGeneration
	binding, bindingErr := minimalcontrol.NewBinding(pins.identity, pins.fields)
	deadline = earlierMinimalControlTime(originalDeadline, stream.admissionDeadline)
	if bindingErr != nil || !c.admissionCurrent(stream, deadline, handle, generation) {
		return state, nil, deadline, errMinimalControlController
	}
	prelude, preludeErr := binding.BootstrapPrelude()
	defer clear(prelude)
	if preludeErr != nil {
		return state, nil, deadline, errMinimalControlController
	}
	// One absolute admission bound, never reset by partial I/O, observations,
	// Finished or readiness. The transport's earlier D is retained as well.
	deadline = earlierMinimalControlTime(deadline, time.Now().Add(session.HandshakeDeadline))
	if stream.SetDeadline(deadline) != nil || !c.admissionCurrent(stream, deadline, handle, generation) ||
		frame.Write(stream, prelude, minimalcontrol.MaxMessageBytes) != nil || !c.admissionCurrent(stream, deadline, handle, generation) {
		return state, nil, deadline, errMinimalControlController
	}
	handshake, handshakeErr := session.NewControllerHandshake(session.ControllerHandshakeConfig{ExpectedIdentity: pins.identity,
		SigningKey: key, Dependencies: session.Dependencies{Random: minimalControlControllerEntropy{}}})
	clear(key) // The shared handshake now owns its only scoped signing copy.
	if handshakeErr != nil {
		return state, nil, deadline, errMinimalControlController
	}
	defer func() { _, _, _ = handshake.AcceptGuestHello(nil) }()
	deadline = earlierMinimalControlTime(deadline, handshake.Deadline())
	if stream.SetDeadline(deadline) != nil || !c.admissionCurrent(stream, deadline, handle, generation) {
		return state, nil, deadline, errMinimalControlController
	}
	hello, readErr := readMinimalControllerHandshake(stream)
	defer clear(hello)
	if readErr != nil || !c.admissionCurrent(stream, deadline, handle, generation) {
		return state, nil, deadline, errMinimalControlController
	}
	var auth []byte
	state, auth, handshakeErr = handshake.AcceptGuestHello(hello)
	defer clear(auth)
	if handshakeErr != nil || state == nil || !c.admissionCurrent(stream, deadline, handle, generation) ||
		writeMinimalControllerWire(stream, auth) != nil || !c.admissionCurrent(stream, deadline, handle, generation) {
		return state, nil, deadline, errMinimalControlController
	}
	guestFinished, readErr := readMinimalControllerRecord(stream)
	defer clear(guestFinished)
	if readErr != nil || !c.admissionCurrent(stream, deadline, handle, generation) || state.OpenFinished(guestFinished) != nil ||
		!c.admissionCurrent(stream, deadline, handle, generation) {
		return state, nil, deadline, errMinimalControlController
	}
	controllerFinished, finishedErr := state.SealFinished()
	defer clear(controllerFinished)
	if finishedErr != nil || !c.admissionCurrent(stream, deadline, handle, generation) ||
		writeMinimalControllerWire(stream, controllerFinished) != nil || !c.admissionCurrent(stream, deadline, handle, generation) || !state.Established() {
		return state, nil, deadline, errMinimalControlController
	}
	var random [32]byte
	defer clear(random[:])
	if _, randomErr := (minimalControlControllerEntropy{}).Read(random[:]); randomErr != nil || !c.admissionCurrent(stream, deadline, handle, generation) {
		return state, nil, deadline, errMinimalControlController
	}
	requestID := hex.EncodeToString(random[:16])
	clear(random[:])
	sessionID := state.SessionID()
	request, requestErr := binding.EncodeReadinessRequest(requestID, sessionID)
	defer clear(request)
	if requestErr != nil || !c.admissionCurrent(stream, deadline, handle, generation) ||
		state.WriteApplication(stream, session.FrameTypeControlRequest, request) != nil || !c.admissionCurrent(stream, deadline, handle, generation) {
		return state, nil, deadline, errMinimalControlController
	}
	response, readErr := readMinimalControllerRecord(stream)
	defer clear(response)
	if readErr != nil || !c.admissionCurrent(stream, deadline, handle, generation) {
		return state, nil, deadline, errMinimalControlController
	}
	// SessionID is read above: OpenApplication holds State.mu while validating.
	plaintext, openErr := state.OpenApplication(response, func(kind session.FrameType, payload []byte) error {
		if kind != session.FrameTypeControlResponse {
			return errMinimalControlController
		}
		return binding.ValidateReadinessResponse(payload, requestID, sessionID)
	})
	defer clear(plaintext)
	if openErr != nil || !state.Established() || !c.admissionCurrent(stream, deadline, handle, generation) {
		return state, nil, deadline, errMinimalControlController
	}
	return state, &minimalControlReadiness{binding: binding, sessionID: sessionID, handle: handle, transportGeneration: generation}, deadline, nil
}

// These helpers retain and wipe the complete allocation on partial reads;
// shared generic framing cannot return that partial allocation to its caller.
func readMinimalControllerHandshake(reader io.Reader) ([]byte, error) {
	var prefix [4]byte
	defer clear(prefix[:])
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, errMinimalControlController
	}
	length, err := session.ParseHandshakeLength(prefix[:])
	if err != nil {
		return nil, errMinimalControlController
	}
	wire := make([]byte, len(prefix)+int(length))
	complete := false
	defer func() {
		if !complete {
			clear(wire)
		}
	}()
	copy(wire, prefix[:])
	if _, err := io.ReadFull(reader, wire[len(prefix):]); err != nil {
		return nil, errMinimalControlController
	}
	complete = true
	return wire, nil
}

func readMinimalControllerRecord(reader io.Reader) ([]byte, error) {
	var prefix [session.SecureRecordHeaderBytes]byte
	defer clear(prefix[:])
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, errMinimalControlController
	}
	header, err := session.ParseRecordHeaderPrefix(prefix[:], session.ChannelControl)
	if err != nil || header.CiphertextLength > minimalcontrol.MaxMessageBytes+session.GCMTagBytes {
		return nil, errMinimalControlController
	}
	wire := make([]byte, len(prefix)+int(header.CiphertextLength))
	complete := false
	defer func() {
		if !complete {
			clear(wire)
		}
	}()
	copy(wire, prefix[:])
	if _, err := io.ReadFull(reader, wire[len(prefix):]); err != nil {
		return nil, errMinimalControlController
	}
	complete = true
	return wire, nil
}

func writeMinimalControllerWire(writer io.Writer, wire []byte) error {
	if len(wire) == 0 {
		return errMinimalControlController
	}
	if n, err := writer.Write(wire); err != nil || n != len(wire) {
		return errMinimalControlController
	}
	return nil
}
