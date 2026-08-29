package credentialclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
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

func readHelperResponsePacket(ctx context.Context, stream VerifiedHelperStream, request HelperReceiveRequest) (HelperPacket, error) {
	if ctx == nil || ctx.Err() != nil || !configuredDependency(stream) {
		return HelperPacket{}, errInvalidHelperReceiveRequest
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = stream.SetDeadline(time.Now())
		case <-stop:
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if deadlineErr := stream.SetDeadline(deadline); deadlineErr != nil {
			return HelperPacket{}, errInvalidHelperPacket
		}
	}
	datagram := make([]byte, credentialprotocol.MaxHelperPacketDatagramBytes)
	n, readErr := stream.Read(datagram)
	if readErr != nil || n < credentialprotocol.HelperPacketHeaderSize {
		clear(datagram)
		if ctx.Err() != nil {
			return HelperPacket{}, ctx.Err()
		}
		return HelperPacket{}, errInvalidHelperPacket
	}
	received := datagram[:n]
	header, err := credentialprotocol.ValidateHelperPacketDatagram(received)
	if err != nil || header.Type != credentialprotocol.PacketTypeResponse {
		clear(datagram)
		return HelperPacket{}, errInvalidHelperPacket
	}
	body, err := credentialprotocol.DecodeHelperResponseBody(received[credentialprotocol.HelperPacketHeaderSize:])
	if err != nil {
		clear(datagram)
		return HelperPacket{}, errInvalidHelperPacket
	}
	clear(datagram)
	return newHelperResponsePacket(request, header, nil, body)
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

func helperOrderedFileTmpfsIndexes(records []credentialprotocol.HelperBindingManifestRecord) ([]uint16, uint64, error) {
	indexes := make([]uint16, 0, len(records))
	var aggregate uint64
	for index, record := range records {
		if record.Mode != credentialprotocol.DeliveryModeFileTmpfs {
			continue
		}
		if record.DeclaredFileBytes == 0 || record.DeclaredFileBytes > credentialprotocol.MaxHelperFileBytes {
			return nil, 0, ErrClientControlDependencyUnaccepted
		}
		if aggregate > credentialprotocol.MaxHelperFileAggregateBytes-uint64(record.DeclaredFileBytes) {
			return nil, 0, ErrClientControlDependencyUnaccepted
		}
		aggregate += uint64(record.DeclaredFileBytes)
		indexes = append(indexes, uint16(index))
	}
	return indexes, aggregate, nil
}

func helperPrepareBeginBodyFromPrepare(prepare v2control.CredentialPrepareRequest) (credentialprotocol.HelperPrepareBeginBody, error) {
	records, _, err := projectV2ManifestToHelperRecords(prepare.Bindings())
	if err != nil {
		return credentialprotocol.HelperPrepareBeginBody{}, err
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

func helperPrepareCommitBodyFromPrepare(prepare v2control.CredentialPrepareRequest) (credentialprotocol.HelperPrepareCommitBody, error) {
	_, manifest, err := projectV2ManifestToHelperRecords(prepare.Bindings())
	if err != nil {
		return credentialprotocol.HelperPrepareCommitBody{}, err
	}
	body := credentialprotocol.HelperPrepareCommitBody{Revision: prepare.Revision(), ManifestSHA256: manifest}
	if _, err := credentialprotocol.EncodeHelperPrepareCommitBody(body); err != nil {
		return credentialprotocol.HelperPrepareCommitBody{}, err
	}
	return body, nil
}

func helperRenewBodyFromRenew(renew v2control.CredentialRenewRequest) (credentialprotocol.HelperRenewBody, error) {
	body := credentialprotocol.HelperRenewBody{
		Revision:       renew.Revision(),
		ExpiryUnixNano: renew.ExpiresAtUnixNano(),
		PriorProofID:   renew.PriorProofID(),
	}
	if _, err := credentialprotocol.EncodeHelperRenewBody(body); err != nil {
		return credentialprotocol.HelperRenewBody{}, err
	}
	return body, nil
}

func helperRevokeBodyFromRevoke(revoke v2control.CredentialRevokeRequest) (credentialprotocol.HelperRevokeBody, error) {
	reason, err := helperRevokeReasonFromControl(revoke.Reason())
	if err != nil {
		return credentialprotocol.HelperRevokeBody{}, err
	}
	body := credentialprotocol.HelperRevokeBody{Revision: revoke.Revision(), Reason: reason}
	if _, err := credentialprotocol.EncodeHelperRevokeBody(body); err != nil {
		return credentialprotocol.HelperRevokeBody{}, err
	}
	return body, nil
}

func helperRevokeReasonFromControl(reason v2control.CredentialRevokeReason) (credentialprotocol.RevokeReason, error) {
	switch reason {
	case v2control.CredentialRevokeReasonRequested:
		return credentialprotocol.RevokeReasonRequested, nil
	case v2control.CredentialRevokeReasonExpired:
		return credentialprotocol.RevokeReasonExpired, nil
	case v2control.CredentialRevokeReasonSessionLoss:
		return credentialprotocol.RevokeReasonSessionLoss, nil
	case v2control.CredentialRevokeReasonSourceRevoked:
		return credentialprotocol.RevokeReasonSourceRevoked, nil
	case v2control.CredentialRevokeReasonWorkerCancel:
		return credentialprotocol.RevokeReasonWorkerCancel, nil
	case v2control.CredentialRevokeReasonDaemonShutdown:
		return credentialprotocol.RevokeReasonDaemonShutdown, nil
	default:
		return 0, errInvalidHelperSendPacket
	}
}

func helperExecBodyFromExec(exec v2control.CredentialExecRequest) (credentialprotocol.HelperExecBody, error) {
	plan, err := helperExecPlanFromControl(exec.Plan())
	if err != nil {
		return credentialprotocol.HelperExecBody{}, err
	}
	length := exec.PrivateAggregateBytes()
	if length > uint64(^uint32(0)) {
		return credentialprotocol.HelperExecBody{}, errInvalidHelperSendPacket
	}
	digest, err := helperExecPrivateDigestFromControl(uint32(length), exec.PrivateAggregateSHA256())
	if err != nil {
		return credentialprotocol.HelperExecBody{}, err
	}
	body := credentialprotocol.HelperExecBody{
		Revision:             exec.Revision(),
		ExecBindingID:        exec.ExecBindingID(),
		PrivateBindingLength: uint32(length),
		PrivateBindingSHA256: digest,
		Plan:                 plan,
	}
	if _, err := credentialprotocol.EncodeHelperExecBody(body); err != nil {
		return credentialprotocol.HelperExecBody{}, err
	}
	return body, nil
}

func helperExecPrivateDigestFromControl(length uint32, digestHex string) ([32]byte, error) {
	var digest [32]byte
	if len(digestHex) != hex.EncodedLen(len(digest)) || digestHex != strings.ToLower(digestHex) {
		return [32]byte{}, errInvalidHelperSendPacket
	}
	decoded, err := hex.DecodeString(digestHex)
	if err != nil || len(decoded) != len(digest) {
		return [32]byte{}, errInvalidHelperSendPacket
	}
	copy(digest[:], decoded)
	if length == 0 {
		if digest != sha256.Sum256(nil) {
			return [32]byte{}, errInvalidHelperSendPacket
		}
		return [32]byte{}, nil
	}
	return digest, nil
}

func helperExecPlanFromControl(plan v2control.ExecPlan) (credentialprotocol.HelperExecPlan, error) {
	environment := plan.Environment()
	mapped := make([]credentialprotocol.HelperExecEnvironment, 0, len(environment))
	for _, entry := range environment {
		source, err := helperExecEnvironmentSourceFromControl(entry.Source())
		if err != nil {
			return credentialprotocol.HelperExecPlan{}, err
		}
		mapped = append(mapped, credentialprotocol.HelperExecEnvironment{
			Name:   entry.Name(),
			Source: source,
			Value:  entry.Value(),
		})
	}
	timing, err := helperExecTimingFromControl(plan.Timing())
	if err != nil {
		return credentialprotocol.HelperExecPlan{}, err
	}
	result := credentialprotocol.HelperExecPlan{
		Arguments:      plan.Args(),
		Environment:    mapped,
		WorkDirectory:  plan.WorkDirectory(),
		StdinMode:      credentialprotocol.HelperExecStreamModePipe,
		StdoutMode:     credentialprotocol.HelperExecStreamModePipe,
		StderrMode:     credentialprotocol.HelperExecStreamModePipe,
		StdinMaxBytes:  plan.StdinMaxBytes(),
		StdoutMaxBytes: plan.StdoutMaxBytes(),
		StderrMaxBytes: plan.StderrMaxBytes(),
		Timing:         timing,
	}
	if err := credentialprotocol.ValidateHelperExecPlan(result); err != nil {
		return credentialprotocol.HelperExecPlan{}, errInvalidHelperSendPacket
	}
	return result, nil
}

func helperExecEnvironmentSourceFromControl(source v2control.ExecEnvironmentSource) (credentialprotocol.HelperExecEnvironmentSource, error) {
	switch source {
	case v2control.ExecEnvironmentLiteral:
		return credentialprotocol.HelperExecEnvironmentLiteral, nil
	case v2control.ExecEnvironmentInherited:
		return credentialprotocol.HelperExecEnvironmentInherited, nil
	case v2control.ExecEnvironmentGenerated:
		return credentialprotocol.HelperExecEnvironmentGenerated, nil
	default:
		return 0, errInvalidHelperSendPacket
	}
}

func helperExecTimingFromControl(timing v2control.ExecTiming) (credentialprotocol.HelperExecTiming, error) {
	switch timing.Kind() {
	case v2control.ExecTimingTimeoutMillis:
		return credentialprotocol.HelperExecTiming{Kind: credentialprotocol.HelperExecTimingTimeoutMillis, Value: timing.Value()}, nil
	case v2control.ExecTimingDeadlineUnixMillis:
		return credentialprotocol.HelperExecTiming{Kind: credentialprotocol.HelperExecTimingDeadlineUnixMillis, Value: timing.Value()}, nil
	default:
		return credentialprotocol.HelperExecTiming{}, errInvalidHelperSendPacket
	}
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
