package session

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFinishedOrderAndApplicationAdmission(t *testing.T) {
	_, controller := newEstablishedPairBeforeFinished(t, ChannelControl)
	if _, err := controller.SealFinished(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("controller early SealFinished() error = %v", err)
	}
	if !controller.Revoked() {
		t.Fatal("controller remains live after Finished order violation")
	}

	guest, _ := newEstablishedPairBeforeFinished(t, ChannelControl)
	if err := guest.OpenFinished(mustHex(t, vectorControllerFinishedHex)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("guest early OpenFinished() error = %v", err)
	}
	if !guest.Revoked() {
		t.Fatal("guest remains live after Finished order violation")
	}

	_, controller = newEstablishedPairBeforeFinished(t, ChannelControl)
	if _, err := controller.SealApplication(FrameTypeControlRequest, nil); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("pre-Finished SealApplication() error = %v", err)
	}
	if !controller.Revoked() {
		t.Fatal("application-before-Finished did not revoke")
	}
}

func TestRecordHeaderAndAuthenticationMutationsAreTerminal(t *testing.T) {
	for _, tt := range []struct {
		name    string
		mutate  func([]byte)
		wantErr error
	}{
		{name: "magic", mutate: func(w []byte) { w[0] ^= 1 }, wantErr: ErrInvalidFrame},
		{name: "version", mutate: func(w []byte) { w[4]++ }, wantErr: ErrInvalidFrame},
		{name: "flags", mutate: func(w []byte) { w[7] = 1 }, wantErr: ErrInvalidFrame},
		{name: "wrong direction type", mutate: func(w []byte) { w[5] = byte(FrameTypeControlResponse) }, wantErr: ErrUnexpectedFrame},
		{name: "replay", mutate: func(w []byte) { binary.BigEndian.PutUint64(w[8:16], 0) }, wantErr: ErrReplay},
		{name: "gap", mutate: func(w []byte) { binary.BigEndian.PutUint64(w[8:16], 2) }, wantErr: ErrSequenceGap},
		{name: "short ciphertext", mutate: func(w []byte) { binary.BigEndian.PutUint32(w[16:20], 15) }, wantErr: ErrInvalidFrame},
		{name: "length mismatch", mutate: func(w []byte) { binary.BigEndian.PutUint32(w[16:20], binary.BigEndian.Uint32(w[16:20])+1) }, wantErr: ErrInvalidFrame},
		{name: "session ID", mutate: func(w []byte) { w[20] ^= 1 }, wantErr: ErrInvalidFrame},
		{name: "ciphertext", mutate: func(w []byte) { w[SecureRecordHeaderBytes] ^= 1 }, wantErr: ErrAuthentication},
		{name: "tag", mutate: func(w []byte) { w[len(w)-1] ^= 1 }, wantErr: ErrAuthentication},
	} {
		t.Run(tt.name, func(t *testing.T) {
			guest, controller := newEstablishedPair(t, ChannelControl)
			wire, err := controller.SealApplication(FrameTypeControlRequest, []byte("safe"))
			if err != nil {
				t.Fatal(err)
			}
			tt.mutate(wire)
			plaintext, err := guest.OpenApplication(wire, nil)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("OpenApplication() error = %v, want %v", err, tt.wantErr)
			}
			if plaintext != nil {
				t.Fatalf("OpenApplication() plaintext = %x after failure", plaintext)
			}
			if !guest.Revoked() {
				t.Fatal("failed record did not revoke receive state")
			}
		})
	}

	for _, tt := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "truncated header", mutate: func(w []byte) []byte { return w[:SecureRecordHeaderBytes-1] }},
		{name: "truncated ciphertext", mutate: func(w []byte) []byte { return w[:len(w)-1] }},
		{name: "trailing", mutate: func(w []byte) []byte { return append(w, 0) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			guest, controller := newEstablishedPair(t, ChannelControl)
			wire, _ := controller.SealApplication(FrameTypeControlRequest, []byte("safe"))
			if _, err := guest.OpenApplication(tt.mutate(wire), nil); !errors.Is(err, ErrInvalidFrame) {
				t.Fatalf("OpenApplication() error = %v, want ErrInvalidFrame", err)
			}
			if !guest.Revoked() {
				t.Fatal("malformed frame did not revoke receive state")
			}
		})
	}
}

func TestFinishedHeaderSequenceSessionAndTagMutationsAreTerminal(t *testing.T) {
	for _, tt := range []struct {
		name    string
		mutate  func([]byte)
		wantErr error
	}{
		{name: "type", mutate: func(w []byte) { w[5] = byte(FrameTypeControllerFinished) }, wantErr: ErrUnexpectedFrame},
		{name: "sequence", mutate: func(w []byte) { binary.BigEndian.PutUint64(w[8:16], 1) }, wantErr: ErrSequenceGap},
		{name: "length", mutate: func(w []byte) { binary.BigEndian.PutUint32(w[16:20], 47) }, wantErr: ErrInvalidFrame},
		{name: "session ID", mutate: func(w []byte) { w[20] ^= 1 }, wantErr: ErrInvalidFrame},
		{name: "tag", mutate: func(w []byte) { w[len(w)-1] ^= 1 }, wantErr: ErrAuthentication},
	} {
		t.Run(tt.name, func(t *testing.T) {
			guest, controller := newEstablishedPairBeforeFinished(t, ChannelControl)
			wire, err := guest.SealFinished()
			if err != nil {
				t.Fatal(err)
			}
			tt.mutate(wire)
			if err := controller.OpenFinished(wire); !errors.Is(err, tt.wantErr) {
				t.Fatalf("OpenFinished() error = %v, want %v", err, tt.wantErr)
			}
			if !controller.Revoked() {
				t.Fatal("invalid Finished did not revoke")
			}
		})
	}
}

func TestRecordHeaderPrefixRejectsBeforeCiphertextAllocation(t *testing.T) {
	guest, controller := newEstablishedPair(t, ChannelControl)
	_ = guest
	wire, err := controller.SealApplication(FrameTypeControlRequest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := guest.Deadline(), vectorNow.Add(HandshakeDeadline); !got.Equal(want) {
		t.Fatalf("guest Deadline() = %v, want %v", got, want)
	}
	header := append([]byte(nil), wire[:SecureRecordHeaderBytes]...)
	if _, err := ParseRecordHeaderPrefix(header, ChannelControl); err != nil {
		t.Fatalf("ParseRecordHeaderPrefix(valid) error: %v", err)
	}
	for _, length := range []uint32{0, GCMTagBytes - 1, MaxControlPlaintextBytes + GCMTagBytes + 1, ^uint32(0)} {
		mutated := append([]byte(nil), header...)
		binary.BigEndian.PutUint32(mutated[16:20], length)
		if _, err := ParseRecordHeaderPrefix(mutated, ChannelControl); !errors.Is(err, ErrInvalidFrame) {
			t.Fatalf("ParseRecordHeaderPrefix(length %d) = %v", length, err)
		}
	}
	if _, err := ParseRecordHeaderPrefix(header[:len(header)-1], ChannelControl); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("ParseRecordHeaderPrefix(short) = %v", err)
	}
}

func TestRecordPlaintextExactBounds(t *testing.T) {
	for _, tt := range []struct {
		name       string
		channel    Channel
		frameType  FrameType
		maximum    int
		wireLength int
	}{
		{name: "control", channel: ChannelControl, frameType: FrameTypeControlRequest, maximum: MaxControlPlaintextBytes, wireLength: MaxControlWireBytes},
		{name: "relay", channel: ChannelSSHRelay, frameType: FrameTypeRelayResponse, maximum: MaxRelayPlaintextBytes, wireLength: MaxRelayWireBytes},
	} {
		t.Run(tt.name, func(t *testing.T) {
			guest, controller := newEstablishedPair(t, tt.channel)
			plaintext := make([]byte, tt.maximum)
			wire, err := controller.SealApplication(tt.frameType, plaintext)
			if err != nil {
				t.Fatalf("SealApplication(exact max) error: %v", err)
			}
			if len(wire) != tt.wireLength {
				t.Fatalf("wire length = %d, want %d", len(wire), tt.wireLength)
			}
			opened, err := guest.OpenApplication(wire, nil)
			if err != nil {
				t.Fatalf("OpenApplication(exact max) error: %v", err)
			}
			if len(opened) != tt.maximum {
				t.Fatalf("plaintext length = %d, want %d", len(opened), tt.maximum)
			}
			DestroyBytes(opened)

			_, controller = newEstablishedPair(t, tt.channel)
			if _, err := controller.SealApplication(tt.frameType, make([]byte, tt.maximum+1)); !errors.Is(err, ErrRecordTooLarge) {
				t.Fatalf("SealApplication(over max) error = %v, want ErrRecordTooLarge", err)
			}
			if !controller.Revoked() {
				t.Fatal("oversize write did not revoke state")
			}
		})
	}
}

func TestSemanticValidationPrecedesCounterCommitAndRedactsCause(t *testing.T) {
	guest, controller := newEstablishedPair(t, ChannelControl)
	wire, err := controller.SealApplication(FrameTypeControlRequest, []byte("raw-private-payload"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := controller.Deadline(), vectorNow.Add(HandshakeDeadline); !got.Equal(want) {
		t.Fatalf("controller Deadline() = %v, want %v", got, want)
	}
	_, err = guest.OpenApplication(wire, func(FrameType, []byte) error {
		return errors.New("secret token at /tmp/credential")
	})
	if !errors.Is(err, ErrSemanticValidation) || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "/tmp/") {
		t.Fatalf("OpenApplication() error = %q", err)
	}
	if guest.nextReceive != 1 {
		t.Fatalf("next receive = %d, want 1 after semantic failure", guest.nextReceive)
	}
	if !guest.Revoked() {
		t.Fatal("semantic failure did not revoke state")
	}
}

func TestSequenceCapAllowsLastRecordThenRevokesBeforeTwoTo32(t *testing.T) {
	guest, controller := newEstablishedPair(t, ChannelControl)
	controller.nextSend = MaxEncryptedRecordsPerDirection - 1
	guest.nextReceive = MaxEncryptedRecordsPerDirection - 1
	wire, err := controller.SealApplication(FrameTypeControlRequest, []byte("last"))
	if err != nil {
		t.Fatalf("SealApplication(last legal) error: %v", err)
	}
	header, err := ParseRecordHeader(wire, ChannelControl)
	if err != nil {
		t.Fatal(err)
	}
	if header.Sequence != MaxEncryptedRecordsPerDirection-1 {
		t.Fatalf("sequence = %d", header.Sequence)
	}
	if _, err := guest.OpenApplication(wire, nil); err != nil {
		t.Fatalf("OpenApplication(last legal) error: %v", err)
	}
	if _, err := controller.SealApplication(FrameTypeControlRequest, nil); !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("SealApplication(at cap) error = %v", err)
	}
	if !controller.Revoked() {
		t.Fatal("cap attempt did not revoke writer")
	}
	if _, err := guest.OpenApplication(wire, nil); !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("OpenApplication(at cap) error = %v", err)
	}
}

func TestFrameDirectionsAreStrict(t *testing.T) {
	for _, tt := range []struct {
		channel Channel
		role    Role
		typeID  FrameType
	}{
		{ChannelControl, RoleController, FrameTypeControlResponse},
		{ChannelControl, RoleGuest, FrameTypeControlRequest},
		{ChannelControl, RoleController, FrameTypeRelayResponse},
		{ChannelSSHRelay, RoleController, FrameTypeRelayRequest},
		{ChannelSSHRelay, RoleGuest, FrameTypeRelayResponse},
		{ChannelSSHRelay, RoleController, FrameTypeControlRequest},
	} {
		guest, controller := newEstablishedPair(t, tt.channel)
		state := guest
		if tt.role == RoleController {
			state = controller
		}
		if _, err := state.SealApplication(tt.typeID, nil); !errors.Is(err, ErrUnexpectedFrame) {
			t.Fatalf("channel %d role %d type %#x error = %v", tt.channel, tt.role, tt.typeID, err)
		}
	}
}

func TestPartialWriteIsTerminal(t *testing.T) {
	_, controller := newEstablishedPair(t, ChannelControl)
	writer := shortWriter{}
	if err := controller.WriteApplication(writer, FrameTypeControlRequest, []byte("payload")); !errors.Is(err, ErrPartialWrite) {
		t.Fatalf("WriteApplication() error = %v", err)
	}
	if !controller.Revoked() {
		t.Fatal("partial write did not revoke state")
	}

	_, controller = newEstablishedPair(t, ChannelControl)
	if err := controller.WriteApplication(errorWriter{}, FrameTypeControlRequest, nil); !errors.Is(err, ErrPartialWrite) {
		t.Fatalf("WriteApplication(error) = %v", err)
	}
}

func TestConcurrentWritersAreSerializedWithUniqueMonotonicSequences(t *testing.T) {
	_, controller := newEstablishedPair(t, ChannelControl)
	writer := &recordingWriter{}
	const records = 64
	var wait sync.WaitGroup
	for index := 0; index < records; index++ {
		wait.Add(1)
		go func(value byte) {
			defer wait.Done()
			if err := controller.WriteApplication(writer, FrameTypeControlRequest, []byte{value}); err != nil {
				t.Errorf("WriteApplication(%d): %v", value, err)
			}
		}(byte(index))
	}
	wait.Wait()
	if controller.Revoked() {
		t.Fatal("serialized writes revoked the state")
	}
	writer.mu.Lock()
	recorded := append([][]byte(nil), writer.records...)
	writer.mu.Unlock()
	if len(recorded) != records {
		t.Fatalf("record count = %d, want %d", len(recorded), records)
	}
	for index, wire := range recorded {
		header, err := ParseRecordHeader(wire, ChannelControl)
		if err != nil {
			t.Fatalf("ParseRecordHeader(%d): %v", index, err)
		}
		if header.Sequence != uint64(index+1) {
			t.Fatalf("record %d sequence = %d, want %d", index, header.Sequence, index+1)
		}
	}
}

func TestHandshakeDeadlineAndCredentialHardExpiry(t *testing.T) {
	now := vectorNow
	guest, hello, err := NewGuestHandshake(GuestHandshakeConfig{
		Identity: vectorIdentity(), PinnedControllerPublicKey: vectorControllerPublicKey(t),
		Dependencies: Dependencies{Random: bytes.NewReader(mustHex(t, vectorGuestPrivateHex)), Now: func() time.Time { return now }},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := guest.Deadline(), vectorNow.Add(HandshakeDeadline); !got.Equal(want) {
		t.Fatalf("guest handshake Deadline() = %v, want %v", got, want)
	}
	controller, err := NewControllerHandshake(ControllerHandshakeConfig{
		ExpectedIdentity: vectorIdentity(), SigningKey: vectorControllerPrivateKey(t),
		Dependencies: Dependencies{Random: bytes.NewReader(mustHex(t, vectorControllerPrivateHex)), Now: func() time.Time { return now }},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := controller.Deadline(), vectorNow.Add(HandshakeDeadline); !got.Equal(want) {
		t.Fatalf("controller handshake Deadline() = %v, want %v", got, want)
	}
	_, auth, err := controller.AcceptGuestHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	now = vectorNow.Add(HandshakeDeadline + time.Nanosecond)
	if _, err := guest.AcceptControllerAuth(auth); !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("AcceptControllerAuth(after deadline) = %v", err)
	}

	guestState, _ := newEstablishedPair(t, ChannelControl)
	if got, want := guestState.HardExpiry(), vectorNow.Add(MaxGuestCredentialSessionLifetime); !got.Equal(want) {
		t.Fatalf("HardExpiry() = %v, want %v", got, want)
	}
	if err := guestState.ValidateCredentialExpiry(guestState.HardExpiry()); err != nil {
		t.Fatalf("ValidateCredentialExpiry(exact hard expiry): %v", err)
	}
	if err := guestState.ValidateCredentialExpiry(guestState.HardExpiry().Add(time.Nanosecond)); !errors.Is(err, ErrCredentialLifetime) {
		t.Fatalf("ValidateCredentialExpiry(over hard expiry) = %v", err)
	}
}

func TestHandshakeDeadlineUsesHalfOpenExactBoundary(t *testing.T) {
	for _, tt := range []struct {
		name    string
		advance time.Duration
		wantErr error
	}{
		{name: "one nanosecond before", advance: HandshakeDeadline - time.Nanosecond},
		{name: "exact deadline", advance: HandshakeDeadline, wantErr: ErrHandshakeTimeout},
	} {
		t.Run(tt.name, func(t *testing.T) {
			now := vectorNow
			guest, hello, err := NewGuestHandshake(GuestHandshakeConfig{
				Identity: vectorIdentity(), PinnedControllerPublicKey: vectorControllerPublicKey(t),
				Dependencies: Dependencies{Random: bytes.NewReader(mustHex(t, vectorGuestPrivateHex)), Now: func() time.Time { return now }},
			})
			if err != nil {
				t.Fatal(err)
			}
			controller, err := NewControllerHandshake(ControllerHandshakeConfig{
				ExpectedIdentity: vectorIdentity(), SigningKey: vectorControllerPrivateKey(t),
				Dependencies: Dependencies{Random: bytes.NewReader(mustHex(t, vectorControllerPrivateHex)), Now: func() time.Time { return vectorNow }},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, auth, err := controller.AcceptGuestHello(hello)
			if err != nil {
				t.Fatal(err)
			}
			now = vectorNow.Add(tt.advance)
			state, err := guest.AcceptControllerAuth(auth)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("AcceptControllerAuth() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && state == nil {
				t.Fatal("AcceptControllerAuth() state = nil before deadline")
			}
		})
	}

	now := vectorNow
	guest, _ := newEstablishedPairBeforeFinishedWithClock(t, ChannelControl, func() time.Time { return now })
	now = vectorNow.Add(HandshakeDeadline)
	if _, err := guest.SealFinished(); !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("SealFinished(exact deadline) = %v, want ErrHandshakeTimeout", err)
	}
}

func TestEstablishedAndRevokedStateReleaseOwnedMaterial(t *testing.T) {
	guest, controller := newEstablishedPair(t, ChannelControl)
	for name, value := range map[string][]byte{
		"guest local Finished":        guest.localFinished[:],
		"guest peer Finished":         guest.peerFinished[:],
		"guest outgoing Finished key": guest.material.guestToController.finishedKey[:],
		"guest incoming Finished key": guest.material.controllerToGuest.finishedKey[:],
	} {
		if !allZero(value) {
			t.Fatalf("%s retained after establishment: %x", name, value)
		}
	}
	sessionID := controller.SessionID()
	if allZero(sessionID[:]) {
		t.Fatal("live session ID is zero")
	}
	controller.Revoke()
	for name, value := range map[string][]byte{
		"session ID":                controller.material.sessionID[:],
		"controller-to-guest key":   controller.material.controllerToGuest.key[:],
		"controller-to-guest nonce": controller.material.controllerToGuest.noncePrefix[:],
		"guest-to-controller key":   controller.material.guestToController.key[:],
		"guest-to-controller nonce": controller.material.guestToController.noncePrefix[:],
	} {
		if !allZero(value) {
			t.Fatalf("%s retained after revoke: %x", name, value)
		}
	}
	if !controller.Revoked() {
		t.Fatal("Revoke() did not mark state")
	}
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func newEstablishedPairBeforeFinished(t *testing.T, channel Channel) (*State, *State) {
	t.Helper()
	return newEstablishedPairBeforeFinishedWithClock(t, channel, func() time.Time { return vectorNow })
}

func newEstablishedPairBeforeFinishedWithClock(t *testing.T, channel Channel, now func() time.Time) (*State, *State) {
	t.Helper()
	identity := vectorIdentity()
	if channel == ChannelSSHRelay {
		identity.Channel = ChannelSSHRelay
		identity.GuestPort = SSHRelayPort
		identity.JobGeneration = "job-gen-1"
		identity.ActivationGeneration = "activation-gen-1"
		identity.RelayGeneration = "relay-gen-1"
	}
	guestHandshake, hello, err := NewGuestHandshake(GuestHandshakeConfig{
		Identity: identity, PinnedControllerPublicKey: vectorControllerPublicKey(t),
		Dependencies: Dependencies{Random: bytes.NewReader(mustHex(t, vectorGuestPrivateHex)), Now: now},
	})
	if err != nil {
		t.Fatal(err)
	}
	controllerHandshake, err := NewControllerHandshake(ControllerHandshakeConfig{
		ExpectedIdentity: identity, SigningKey: vectorControllerPrivateKey(t),
		Dependencies: Dependencies{Random: bytes.NewReader(mustHex(t, vectorControllerPrivateHex)), Now: now},
	})
	if err != nil {
		t.Fatal(err)
	}
	controllerState, auth, err := controllerHandshake.AcceptGuestHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	guestState, err := guestHandshake.AcceptControllerAuth(auth)
	if err != nil {
		t.Fatal(err)
	}
	return guestState, controllerState
}

func newEstablishedPair(t *testing.T, channel Channel) (*State, *State) {
	t.Helper()
	guest, controller := newEstablishedPairBeforeFinished(t, channel)
	guestFinished, err := guest.SealFinished()
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.OpenFinished(guestFinished); err != nil {
		t.Fatal(err)
	}
	controllerFinished, err := controller.SealFinished()
	if err != nil {
		t.Fatal(err)
	}
	if err := guest.OpenFinished(controllerFinished); err != nil {
		t.Fatal(err)
	}
	return guest, controller
}

type shortWriter struct{}

func (shortWriter) Write(payload []byte) (int, error) { return len(payload) - 1, nil }

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

type recordingWriter struct {
	mu      sync.Mutex
	records [][]byte
}

func (w *recordingWriter) Write(payload []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.records = append(w.records, append([]byte(nil), payload...))
	return len(payload), nil
}
