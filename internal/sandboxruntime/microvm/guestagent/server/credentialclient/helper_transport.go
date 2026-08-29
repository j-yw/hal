package credentialclient

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/v2control"
)

var errInvalidHelperAcceptExpectation = errors.New("credential client helper accept expectation is invalid")

const firstInjectedHelperSendSequence uint64 = 1

// HelperAcceptExpectation is the private-snapshot expectation presented only
// to the inherited, preopened helper connection owner. It carries no FD.
type HelperAcceptExpectation struct {
	liveValue
	sessionID        [32]byte
	identityDigest   [32]byte
	helperGeneration credentialprotocol.SafeID
	bootNonce        [32]byte
}

func newHelperAcceptExpectation(
	sessionID [32]byte,
	identityDigest [32]byte,
	helperGeneration credentialprotocol.SafeID,
	bootNonce [32]byte,
) (HelperAcceptExpectation, error) {
	if !validHelperAcceptExpectationValues(sessionID, identityDigest, helperGeneration, bootNonce) {
		return HelperAcceptExpectation{}, errInvalidHelperAcceptExpectation
	}
	return HelperAcceptExpectation{
		sessionID:        sessionID,
		identityDigest:   identityDigest,
		helperGeneration: helperGeneration,
		bootNonce:        bootNonce,
	}, nil
}

func validHelperAcceptExpectationValues(
	sessionID [32]byte,
	identityDigest [32]byte,
	helperGeneration credentialprotocol.SafeID,
	bootNonce [32]byte,
) bool {
	return sessionID != ([32]byte{}) &&
		identityDigest != ([32]byte{}) &&
		bootNonce != ([32]byte{}) &&
		credentialprotocol.ValidateSafeID(helperGeneration) == nil
}

func (expectation HelperAcceptExpectation) SessionID() [32]byte { return expectation.sessionID }
func (expectation HelperAcceptExpectation) IdentityDigest() [32]byte {
	return expectation.identityDigest
}
func (expectation HelperAcceptExpectation) HelperGeneration() credentialprotocol.SafeID {
	return expectation.helperGeneration
}
func (expectation HelperAcceptExpectation) BootNonce() [32]byte { return expectation.bootNonce }

func (expectation HelperAcceptExpectation) valid() bool {
	return validHelperAcceptExpectationValues(
		expectation.sessionID,
		expectation.identityDigest,
		expectation.helperGeneration,
		expectation.bootNonce,
	)
}

// VerifiedHelperStream is the exact already-connected and same-object
// revalidated helper stream. It can neither bind nor listen.
type VerifiedHelperStream interface {
	io.Reader
	io.Writer
	SetDeadline(time.Time) error
	Close() error
}

// HelperConnectionOwner owns one inherited preopened helper connection and
// returns only a stream revalidated against the supplied immutable expectation.
type HelperConnectionOwner interface {
	AcceptVerified(context.Context, HelperAcceptExpectation) (VerifiedHelperStream, error)
	Close(context.Context) error
}

type preopenedHelperConnectionOwner struct {
	mu       sync.Mutex
	stream   VerifiedHelperStream
	accepted bool
	closed   bool
}

func newPreopenedHelperConnectionOwner(stream VerifiedHelperStream) (HelperConnectionOwner, error) {
	if !configuredDependency(stream) {
		return nil, errInvalidHelperAcceptExpectation
	}
	return &preopenedHelperConnectionOwner{stream: stream}, nil
}

func (owner *preopenedHelperConnectionOwner) AcceptVerified(ctx context.Context, expectation HelperAcceptExpectation) (VerifiedHelperStream, error) {
	if ctx == nil || ctx.Err() != nil || !expectation.valid() {
		return nil, errInvalidHelperAcceptExpectation
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || owner.accepted || !configuredDependency(owner.stream) {
		return nil, ErrClientControlDependencyUnaccepted
	}
	if err := revalidateVerifiedHelperStream(owner.stream); err != nil {
		return nil, err
	}
	owner.accepted = true
	return owner.stream, nil
}

func (owner *preopenedHelperConnectionOwner) Close(context.Context) error {
	owner.mu.Lock()
	stream := owner.stream
	owner.stream = nil
	owner.closed = true
	owner.mu.Unlock()
	if stream == nil {
		return nil
	}
	return stream.Close()
}

type helperSendBodySink struct {
	buf []byte
}

func (sink *helperSendBodySink) Capacity() uint32 {
	return uint32(len(sink.buf))
}

func (sink *helperSendBodySink) WriteSegment(offset uint32, source []byte) error {
	if uint64(offset)+uint64(len(source)) > uint64(len(sink.buf)) {
		return errInvalidHelperSendPacket
	}
	copy(sink.buf[offset:], source)
	return nil
}

func writeHelperSendPacket(ctx context.Context, stream VerifiedHelperStream, packet HelperSendPacket) error {
	if ctx == nil || ctx.Err() != nil || !configuredDependency(stream) {
		return errInvalidHelperSendPacket
	}
	header := packet.headerValue()
	encodedHeader, err := credentialprotocol.EncodeHelperPacketHeader(header)
	if err != nil || header.BodyLength == 0 {
		return errInvalidHelperSendPacket
	}
	datagram := make([]byte, credentialprotocol.HelperPacketHeaderSize+int(header.BodyLength))
	copy(datagram[:credentialprotocol.HelperPacketHeaderSize], encodedHeader[:])
	if writeErr := packet.writeCanonicalBody(&helperSendBodySink{buf: datagram[credentialprotocol.HelperPacketHeaderSize:]}); writeErr != nil {
		clear(datagram)
		return writeErr
	}
	if deadline, ok := ctx.Deadline(); ok {
		if deadlineErr := stream.SetDeadline(deadline); deadlineErr != nil {
			clear(datagram)
			return errInvalidHelperSendPacket
		}
	}
	wrote, writeErr := stream.Write(datagram)
	clear(datagram)
	if writeErr != nil || wrote != credentialprotocol.HelperPacketHeaderSize+int(header.BodyLength) {
		return errInvalidHelperSendPacket
	}
	return nil
}

func helperSendPacketUnconsumed(packet HelperSendPacket) bool {
	if packet.state == nil {
		return false
	}
	packet.state.mu.Lock()
	defer packet.state.mu.Unlock()
	return !packet.state.consumed && packet.state.owner != nil
}

func helperPrepareBeginBodyFromPrepare(prepare v2control.CredentialPrepareRequest) (credentialprotocol.HelperPrepareBeginBody, error) {
	bindings := prepare.Bindings()
	records := make([]credentialprotocol.HelperBindingManifestRecord, 0, len(bindings))
	for _, binding := range bindings {
		record, err := helperBindingRecordFromManifest(binding)
		if err != nil {
			return credentialprotocol.HelperPrepareBeginBody{}, err
		}
		records = append(records, record)
	}
	body := credentialprotocol.HelperPrepareBeginBody{
		Revision:       prepare.Revision(),
		ExpiryUnixNano: prepare.ExpiresAtUnixNano(),
		Bindings:       records,
	}
	if _, err := credentialprotocol.EncodeHelperPrepareBeginBody(body); err != nil {
		return credentialprotocol.HelperPrepareBeginBody{}, err
	}
	return body, nil
}

func helperBindingRecordFromManifest(manifest v2control.BindingManifest) (credentialprotocol.HelperBindingManifestRecord, error) {
	record := credentialprotocol.HelperBindingManifestRecord{BindingID: manifest.BindingID()}
	switch manifest.Mode() {
	case v2control.DeliveryMode("http_proxy"):
		record.Mode = credentialprotocol.DeliveryModeHTTPProxy
	case v2control.DeliveryMode("file_tmpfs"):
		path, pathOK := manifest.TargetPath()
		length, lengthOK := manifest.DeclaredFileBytes()
		digestHex, digestOK := manifest.FileSHA256()
		if !pathOK || !lengthOK || !digestOK {
			return credentialprotocol.HelperBindingManifestRecord{}, errInvalidHelperSendPacket
		}
		decoded, err := hex.DecodeString(digestHex)
		if err != nil || len(decoded) != 32 {
			return credentialprotocol.HelperBindingManifestRecord{}, errInvalidHelperSendPacket
		}
		record.Mode = credentialprotocol.DeliveryModeFileTmpfs
		record.TargetPath = path
		record.DeclaredFileBytes = length
		copy(record.FileSHA256[:], decoded)
	case v2control.DeliveryMode("ssh_agent"):
		record.Mode = credentialprotocol.DeliveryModeSSHAgent
	default:
		return credentialprotocol.HelperBindingManifestRecord{}, errInvalidHelperSendPacket
	}
	return record, nil
}

var (
	_ io.Reader             = VerifiedHelperStream(nil)
	_ io.Writer             = VerifiedHelperStream(nil)
	_ HelperConnectionOwner = (*preopenedHelperConnectionOwner)(nil)
)
