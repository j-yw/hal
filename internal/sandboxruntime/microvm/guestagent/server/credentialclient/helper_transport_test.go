package credentialclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/v2control"
)

func TestL8D7GuestHelperSCMRightsTryReadNoopsOnNonConnStream(t *testing.T) {
	identity := [32]byte{1}
	identity[31] = 2
	request, err := newHelperControlReceiveRequest(1, credentialprotocol.HelperSSHAcceptedFDBodyEncodedLength(), 1, [16]byte{}, false, identity)
	if err != nil {
		t.Fatal(err)
	}
	packet, received, readErr := tryReadHelperSSHAcceptedPacket(context.Background(), newFakeHelperStream(), request)
	if readErr != nil || received {
		t.Fatalf("tryReadHelperSSHAcceptedPacket(fake stream) = %#v, %v, %v", packet, received, readErr)
	}
}

func TestL8D7GuestHelperSSHAcceptedCleanupOverridesHandleError(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testSSHOnlyDispatchPrepareRequest(t, identity)
	digest := identityDigestForSession(t, testSSHOnlyDispatchSessionIdentity(t, identity))
	records, manifest, err := projectV2ManifestToHelperRecords(prepare.Bindings())
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := newHelperActiveLedger(
		digest, prepare.RequestID().Bytes(), identity.helperGeneration, manifest,
		prepare.Revision(), prepare.ExpiresAtUnixNano(),
		[]credentialprotocol.HelperBindingProof{{BindingID: "binding-ssh", Mode: credentialprotocol.DeliveryModeSSHAgent, ProofID: "proof-ssh"}},
		records, prepare.Bindings(), "active-proof", "exec-binding",
	)
	if err != nil {
		t.Fatal(err)
	}
	capabilityDigest := [32]byte{0x41}
	issuer := &sshTestIssuer{digest: capabilityDigest, closeErr: errors.New("close failed")}
	receive := mustHelperReceiveRequest(t, 1, [16]byte{}, false, digest.Bytes(), 1)
	header := testHelperHeader(credentialprotocol.PacketTypeSSHAcceptedFD, 1, [16]byte{9}, digest.Bytes(), identity.identity.GuestBootNonce, credentialprotocol.HelperSSHAcceptedFDBodyEncodedLength())
	packet, err := newHelperSSHAcceptedPacket(receive, header, nil, 1, 0, 1, capabilityDigest, issuer)
	if err != nil {
		t.Fatal(err)
	}
	session := &recordingSSHSession{handleErr: errors.New("handle failed")}
	client := newDispatchRedClientWithSSHSession(t, &dispatchRedTransport{identity: identity}, nil, session)
	err = client.dispatchHelperSSHAccepted(context.Background(), packet, digest, ledger)
	if clientContractCode(err) != ClientContractCleanup {
		t.Fatalf("dispatchHelperSSHAccepted() error = %v, want cleanup override", err)
	}
	if issuer.closes.Load() != 1 {
		t.Fatalf("issuer closes = %d, want 1", issuer.closes.Load())
	}
}

func TestL8D7GuestHelperSSHAcceptedCancellationClosesBeforeTransfer(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testSSHOnlyDispatchPrepareRequest(t, identity)
	digest := identityDigestForSession(t, testSSHOnlyDispatchSessionIdentity(t, identity))
	ledger := testSSHActiveLedger(t, identity, prepare, digest)
	capabilityDigest := [32]byte{0x43}
	issuer := &sshTestIssuer{digest: capabilityDigest}
	packet := testSSHAcceptedHelperPacket(t, identity, digest, capabilityDigest, issuer)

	ctx, cancel := context.WithCancel(context.Background())
	session := &recordingSSHSession{handleHook: cancel}
	client := newDispatchRedClientWithSSHSession(t, &dispatchRedTransport{identity: identity}, nil, session)
	err := client.dispatchHelperSSHAccepted(ctx, packet, digest, ledger)
	if err == nil {
		t.Fatal("canceled SSH dispatch transferred ownership")
	}
	if issuer.closes.Load() != 1 {
		t.Fatalf("issuer closes = %d, want 1", issuer.closes.Load())
	}
	if err := session.acceptedPacket(t).WaitTransferred(context.Background()); err == nil {
		t.Fatal("canceled SSH packet reported transferred ownership")
	}
}

func TestL8D7GuestHelperSSHAcceptedClientDrainClosesBeforeTransfer(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testSSHOnlyDispatchPrepareRequest(t, identity)
	digest := identityDigestForSession(t, testSSHOnlyDispatchSessionIdentity(t, identity))
	ledger := testSSHActiveLedger(t, identity, prepare, digest)
	capabilityDigest := [32]byte{0x44}
	issuer := &sshTestIssuer{digest: capabilityDigest}
	packet := testSSHAcceptedHelperPacket(t, identity, digest, capabilityDigest, issuer)
	session := &gatedSSHSession{
		handleStarted: make(chan struct{}),
		handleRelease: make(chan struct{}),
		closed:        make(chan struct{}),
	}
	client := newDispatchRedClientWithSSHSession(t, &dispatchRedTransport{identity: identity}, nil, session)
	if !client.beginAdmittedOperation() {
		t.Fatal("failed to admit SSH dispatch")
	}
	dispatchDone := make(chan error, 1)
	go func() {
		defer client.endAdmittedOperation()
		dispatchDone <- client.dispatchHelperSSHAccepted(context.Background(), packet, digest, ledger)
	}()
	<-session.handleStarted
	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close(context.Background()) }()
	<-session.closed
	close(session.handleRelease)
	if err := <-dispatchDone; err == nil {
		t.Fatal("draining client transferred SSH ownership after extension close")
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if issuer.closes.Load() != 1 {
		t.Fatalf("issuer closes = %d, want 1", issuer.closes.Load())
	}
	if err := session.acceptedPacket(t).WaitTransferred(context.Background()); err == nil {
		t.Fatal("drained SSH packet reported transferred ownership")
	}
}

func testSSHActiveLedger(t *testing.T, identity transportIdentity, prepare v2control.CredentialPrepareRequest, digest v2control.IdentityDigest) *helperActiveLedger {
	t.Helper()
	records, manifest, err := projectV2ManifestToHelperRecords(prepare.Bindings())
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := newHelperActiveLedger(
		digest, prepare.RequestID().Bytes(), identity.helperGeneration, manifest,
		prepare.Revision(), prepare.ExpiresAtUnixNano(),
		[]credentialprotocol.HelperBindingProof{{BindingID: "binding-ssh", Mode: credentialprotocol.DeliveryModeSSHAgent, ProofID: "proof-ssh"}},
		records, prepare.Bindings(), "active-proof", "exec-binding",
	)
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}

func testSSHAcceptedHelperPacket(t *testing.T, identity transportIdentity, digest v2control.IdentityDigest, capabilityDigest [32]byte, issuer SSHConnectionCapability) HelperPacket {
	t.Helper()
	receive := mustHelperReceiveRequest(t, 1, [16]byte{}, false, digest.Bytes(), 1)
	header := testHelperHeader(credentialprotocol.PacketTypeSSHAcceptedFD, 1, [16]byte{9}, digest.Bytes(), identity.identity.GuestBootNonce, credentialprotocol.HelperSSHAcceptedFDBodyEncodedLength())
	packet, err := newHelperSSHAcceptedPacket(receive, header, nil, 1, 0, 1, capabilityDigest, issuer)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestL8D7GuestHelperSSHAcceptedDispatchesAndTransfersOwnership(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testSSHOnlyDispatchPrepareRequest(t, identity)
	digest := identityDigestForSession(t, testSSHOnlyDispatchSessionIdentity(t, identity))
	records, manifest, err := projectV2ManifestToHelperRecords(prepare.Bindings())
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := newHelperActiveLedger(
		digest, prepare.RequestID().Bytes(), identity.helperGeneration, manifest,
		prepare.Revision(), prepare.ExpiresAtUnixNano(),
		[]credentialprotocol.HelperBindingProof{{BindingID: "binding-ssh", Mode: credentialprotocol.DeliveryModeSSHAgent, ProofID: "proof-ssh"}},
		records, prepare.Bindings(), "active-proof", "exec-binding",
	)
	if err != nil {
		t.Fatal(err)
	}
	capabilityDigest := [32]byte{0x42}
	issuer := &sshTestIssuer{digest: capabilityDigest}
	receive := mustHelperReceiveRequest(t, 2, [16]byte{}, false, digest.Bytes(), 1)
	header := testHelperHeader(credentialprotocol.PacketTypeSSHAcceptedFD, 2, [16]byte{9}, digest.Bytes(), identity.identity.GuestBootNonce, credentialprotocol.HelperSSHAcceptedFDBodyEncodedLength())
	packet, err := newHelperSSHAcceptedPacket(receive, header, nil, 1, 0, 1, capabilityDigest, issuer)
	if err != nil {
		t.Fatal(err)
	}
	session := &recordingSSHSession{}
	client := newDispatchRedClientWithSSHSession(t, &dispatchRedTransport{identity: identity}, nil, session)
	if err := client.dispatchHelperSSHAccepted(context.Background(), packet, digest, ledger); err != nil {
		t.Fatalf("dispatchHelperSSHAccepted() error = %v", err)
	}
	accepted := session.acceptedPacket(t)
	if err := accepted.WaitTransferred(context.Background()); err != nil {
		t.Fatalf("WaitTransferred() error = %v", err)
	}
	if issuer.closes.Load() != 0 {
		t.Fatal("successful dispatch closed the issuer")
	}
}

func TestL8D7GuestHelperOwnerIsVerifiedPreopened(t *testing.T) {
	owner := reflect.TypeOf((*HelperConnectionOwner)(nil)).Elem()
	if owner.NumMethod() != 2 || owner.Method(0).Name != "AcceptVerified" || owner.Method(1).Name != "Close" {
		t.Fatalf("HelperConnectionOwner methods = %v, want exact AcceptVerified/Close", owner)
	}
	stream := reflect.TypeOf((*VerifiedHelperStream)(nil)).Elem()
	for _, forbidden := range []string{"Bind", "Listen", "Dial", "Accept"} {
		if _, ok := stream.MethodByName(forbidden); ok {
			t.Fatalf("VerifiedHelperStream exposes forbidden %s authority", forbidden)
		}
	}

	sessionID := testDispatchTransportIdentity().sessionID
	digest := [32]byte{9, 8, 7}
	digest[31] = 1
	nonce := [32]byte{1, 2, 3}
	nonce[31] = 4
	expectation, err := newHelperAcceptExpectation(sessionID, digest, "helper-generation-1", nonce)
	if err != nil {
		t.Fatalf("newHelperAcceptExpectation() error = %v", err)
	}
	if expectation.SessionID() != sessionID || expectation.IdentityDigest() != digest ||
		expectation.HelperGeneration() != "helper-generation-1" || expectation.BootNonce() != nonce {
		t.Fatal("helper accept expectation lost correlation")
	}
	assertFailsClosed(t, expectation)
	if _, err := newHelperAcceptExpectation([32]byte{}, digest, "helper-generation-1", nonce); !errors.Is(err, errInvalidHelperAcceptExpectation) {
		t.Fatalf("zero session helper expectation error = %v", err)
	}
}

func TestL8D7GuestHelperPrepareBeginBodyProjectsSafeManifest(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testDispatchPrepareRequest(t, identity)
	body, err := helperPrepareBeginBodyFromPrepare(prepare)
	if err != nil {
		t.Fatalf("helperPrepareBeginBodyFromPrepare() error = %v", err)
	}
	if body.Revision != 1 || body.ExpiryUnixNano != prepare.ExpiresAtUnixNano() || len(body.Bindings) != 2 {
		t.Fatalf("prepare-begin body = %#v", body)
	}
	if body.Bindings[0].BindingID != "binding-http" || body.Bindings[0].Mode != credentialprotocol.DeliveryModeHTTPProxy ||
		body.Bindings[0].TargetPath != "" || body.Bindings[0].DeclaredFileBytes != 0 {
		t.Fatalf("http binding = %#v", body.Bindings[0])
	}
	if body.Bindings[1].BindingID != "binding-file" || body.Bindings[1].Mode != credentialprotocol.DeliveryModeFileTmpfs ||
		body.Bindings[1].TargetPath != "credentials/config" || body.Bindings[1].DeclaredFileBytes != 7 {
		t.Fatalf("file binding = %#v", body.Bindings[1])
	}
}

func TestL8D7GuestHelperServeNilOwnerRemainsUnaccepted(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testDispatchPrepareRequest(t, identity)
	var helperSends atomic.Uint32
	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
		return ControllerPacket{
			sequence:  1,
			sessionID: identity.sessionID,
			arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
		}, nil
	}
	transport.sendHelper = func(context.Context, HelperSendPacket) error {
		helperSends.Add(1)
		return errors.New("nil helper owner must not send")
	}
	err := newDispatchRedClientOpts(t, transport, nil).Serve(context.Background())
	if !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("Serve() error = %v, want helper dependency unaccepted", err)
	}
	if helperSends.Load() != 0 {
		t.Fatalf("helper sends = %d, want 0", helperSends.Load())
	}
}

func TestL8D7GuestHelperServeSendsPrepareBeginFileAndCommit(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare, payload, fileDigest := testFileBearingDispatchPrepareRequest(t, identity)
	digest := identityDigestForSession(t, testCredentialPacketSessionIdentity(t, identity.sessionID))
	stream := newFakeHelperStream()
	owner := &fakeHelperOwner{stream: stream}
	stream.queueHelperDatagram(encodeHelperResponseDatagram(
		t, 1, prepare.RequestID().Bytes(), digest.Bytes(), identity.identity.GuestBootNonce,
		matchingFileBearingPrepareHelperResponse(t, prepare),
	))
	privateBody := testControllerPrepareFileBody(payload, fileDigest)
	var helperSends atomic.Uint32
	var controllerSends atomic.Uint32
	closed := make(chan struct{})
	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = blockingControllerAfter(t, []ControllerPacket{
		{sequence: 1, sessionID: identity.sessionID, arm: controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare}},
		testControllerPrivateFilePacket(2, identity, prepare, digest, 1, payload, fileDigest, privateBody),
	}, closed)
	transport.sendController = func(context.Context, ControllerSendPacket) error {
		controllerSends.Add(1)
		return nil
	}
	transport.sendHelper = func(_ context.Context, packet HelperSendPacket) error {
		helperSends.Add(1)
		return errors.New("legacy transport helper send must stay unused")
	}
	transport.close = func(context.Context) error {
		transport.closeOnce.Do(func() { close(closed) })
		return nil
	}
	client := newDispatchRedClientOpts(t, transport, owner)
	serveDone := make(chan error, 1)
	go func() { serveDone <- client.Serve(context.Background()) }()
	waitForControllerSends(t, &controllerSends, 1, serveDone)
	if err := client.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if owner.accepts.Load() != 1 || helperSends.Load() != 0 {
		t.Fatalf("accepts/legacy transport sends = %d/%d, want 1/0", owner.accepts.Load(), helperSends.Load())
	}
	packets := decodeHelperDatagrams(t, stream.bytes())
	if len(packets) != 3 {
		t.Fatalf("helper datagrams = %d, want begin+file+commit", len(packets))
	}
	header := packets[0].header
	if header.Type != credentialprotocol.PacketTypePrepareBegin || header.Sequence != firstInjectedHelperSendSequence ||
		header.RequestID != prepare.RequestID().Bytes() || header.GuestCredentialIdentityDigest != digest.Bytes() ||
		header.BootNonce != identity.identity.GuestBootNonce {
		t.Fatalf("stream header = %#v", header)
	}
	decoded, err := credentialprotocol.DecodeHelperPrepareBeginBody(packets[0].body)
	if err != nil {
		t.Fatalf("DecodeHelperPrepareBeginBody() error = %v", err)
	}
	if decoded.Revision != 1 || len(decoded.Bindings) != 2 || decoded.Bindings[0].BindingID != "binding-http" {
		t.Fatalf("stream prepare-begin body = %#v", decoded)
	}
	fileBody, err := credentialprotocol.DecodeHelperPrepareFileBody(packets[1].body)
	if err != nil {
		t.Fatalf("DecodeHelperPrepareFileBody() error = %v", err)
	}
	defer fileBody.Wipe()
	if fileBody.BindingIndex() != 1 || fileBody.FileSHA256() != fileDigest {
		t.Fatal("prepare-file body did not match the admitted file binding")
	}
}

func TestL8D7GuestHelperWriteCanonicalPrepareBeginPacket(t *testing.T) {
	identity := testHelperPacketIdentity()
	nonce := testHelperPacketNonce()
	requestID := testHelperPacketRequestID()
	begin := credentialprotocol.HelperPrepareBeginBody{
		Revision:       1,
		ExpiryUnixNano: 1700000001123456789,
		Bindings: []credentialprotocol.HelperBindingManifestRecord{
			{BindingID: "binding-http", Mode: credentialprotocol.DeliveryModeHTTPProxy},
		},
	}
	packet, err := newHelperPrepareBeginSendPacket(testHelperHeader(0, 1, requestID, identity, nonce, 0), begin)
	if err != nil {
		t.Fatal(err)
	}
	stream := newFakeHelperStream()
	if err := writeHelperSendPacket(context.Background(), stream, packet); err != nil {
		t.Fatalf("writeHelperSendPacket() error = %v", err)
	}
	header, err := credentialprotocol.ValidateHelperPacketDatagram(stream.bytes())
	if err != nil || header.Type != credentialprotocol.PacketTypePrepareBegin || header.RequestID != requestID {
		t.Fatalf("written datagram header = %#v, %v", header, err)
	}
	if helperSendPacketUnconsumed(packet) {
		t.Fatal("writeHelperSendPacket left the send packet unconsumed")
	}
}

func TestL8D7GuestHelperMetadataBodiesProjectFromController(t *testing.T) {
	identity := testDispatchTransportIdentity()
	sessionIdentity := testCredentialPacketSessionIdentity(t, identity.sessionID)
	prepare := testDispatchPrepareRequest(t, identity)
	requestID := testPacketRequestID(t)

	commit, err := helperPrepareCommitBodyFromPrepare(prepare)
	if err != nil {
		t.Fatalf("helperPrepareCommitBodyFromPrepare() error = %v", err)
	}
	begin, err := helperPrepareBeginBodyFromPrepare(prepare)
	if err != nil {
		t.Fatal(err)
	}
	wantManifest, err := credentialprotocol.ComputeHelperManifestSHA256(begin.Bindings)
	if err != nil {
		t.Fatal(err)
	}
	if commit.Revision != prepare.Revision() || commit.ManifestSHA256 != wantManifest {
		t.Fatalf("prepare-commit body = %#v", commit)
	}

	renew := testCredentialRenewPacketRequest(t, requestID, sessionIdentity)
	renewBody, err := helperRenewBodyFromRenew(renew)
	if err != nil {
		t.Fatalf("helperRenewBodyFromRenew() error = %v", err)
	}
	if renewBody.Revision != renew.Revision() || renewBody.ExpiryUnixNano != renew.ExpiresAtUnixNano() || renewBody.PriorProofID != renew.PriorProofID() {
		t.Fatalf("renew body = %#v", renewBody)
	}

	revoke := testCredentialRevokePacketRequest(t, requestID, sessionIdentity)
	revokeBody, err := helperRevokeBodyFromRevoke(revoke)
	if err != nil {
		t.Fatalf("helperRevokeBodyFromRevoke() error = %v", err)
	}
	if revokeBody.Revision != revoke.Revision() || revokeBody.Reason != credentialprotocol.RevokeReasonRequested {
		t.Fatalf("revoke body = %#v", revokeBody)
	}

	execReq := testCredentialExecPacketRequest(t, requestID, sessionIdentity)
	execBody, err := helperExecBodyFromExec(execReq)
	if err != nil {
		t.Fatalf("helperExecBodyFromExec() error = %v", err)
	}
	if execBody.Revision != execReq.Revision() || execBody.ExecBindingID != execReq.ExecBindingID() ||
		uint64(execBody.PrivateBindingLength) != execReq.PrivateAggregateBytes() ||
		len(execBody.Plan.Arguments) != 2 || execBody.Plan.Arguments[0] != "/usr/bin/tool" {
		t.Fatalf("exec body = %#v", execBody)
	}
}

func TestL8D7GuestHelperServeDoesNotInterleaveLaterMetadataWithPrepare(t *testing.T) {
	identity := testDispatchTransportIdentity()
	sessionIdentity := testCredentialPacketSessionIdentity(t, identity.sessionID)
	prepare := testDispatchPrepareRequest(t, identity)
	digest := identityDigestForSession(t, sessionIdentity)
	laterRequestID := testPacketRequestID(t)

	type laterCase struct {
		name     string
		packet   ControllerPacket
		wantType credentialprotocol.PacketType
		wantBody func(*testing.T, []byte)
	}
	cases := []laterCase{
		{
			name: "prepare-commit",
			packet: ControllerPacket{
				sequence:  2,
				sessionID: identity.sessionID,
				arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
			},
			wantType: credentialprotocol.PacketTypePrepareCommit,
			wantBody: func(t *testing.T, body []byte) {
				t.Helper()
				decoded, err := credentialprotocol.DecodeHelperPrepareCommitBody(body)
				if err != nil {
					t.Fatalf("DecodeHelperPrepareCommitBody() error = %v", err)
				}
				want, err := helperPrepareCommitBodyFromPrepare(prepare)
				if err != nil {
					t.Fatal(err)
				}
				if decoded != want {
					t.Fatalf("prepare-commit body = %#v, want %#v", decoded, want)
				}
			},
		},
		{
			name: "renew",
			packet: ControllerPacket{
				sequence:  2,
				sessionID: identity.sessionID,
				arm:       controllerPacketArm{kind: controllerPacketArmRenew, renew: testCredentialRenewPacketRequest(t, laterRequestID, sessionIdentity)},
			},
			wantType: credentialprotocol.PacketTypeRenew,
			wantBody: func(t *testing.T, body []byte) {
				t.Helper()
				decoded, err := credentialprotocol.DecodeHelperRenewBody(body)
				if err != nil {
					t.Fatalf("DecodeHelperRenewBody() error = %v", err)
				}
				want, err := helperRenewBodyFromRenew(testCredentialRenewPacketRequest(t, laterRequestID, sessionIdentity))
				if err != nil {
					t.Fatal(err)
				}
				if decoded != want {
					t.Fatalf("renew body = %#v, want %#v", decoded, want)
				}
			},
		},
		{
			name: "revoke",
			packet: ControllerPacket{
				sequence:  2,
				sessionID: identity.sessionID,
				arm:       controllerPacketArm{kind: controllerPacketArmRevoke, revoke: testCredentialRevokePacketRequest(t, laterRequestID, sessionIdentity)},
			},
			wantType: credentialprotocol.PacketTypeRevoke,
			wantBody: func(t *testing.T, body []byte) {
				t.Helper()
				decoded, err := credentialprotocol.DecodeHelperRevokeBody(body)
				if err != nil {
					t.Fatalf("DecodeHelperRevokeBody() error = %v", err)
				}
				if decoded.Revision != 9 || decoded.Reason != credentialprotocol.RevokeReasonRequested {
					t.Fatalf("revoke body = %#v", decoded)
				}
			},
		},
		{
			name: "exec",
			packet: ControllerPacket{
				sequence:  2,
				sessionID: identity.sessionID,
				arm:       controllerPacketArm{kind: controllerPacketArmExec, exec: testCredentialExecPacketRequest(t, laterRequestID, sessionIdentity)},
			},
			wantType: credentialprotocol.PacketTypeExec,
			wantBody: func(t *testing.T, body []byte) {
				t.Helper()
				decoded, err := credentialprotocol.DecodeHelperExecBody(body)
				if err != nil {
					t.Fatalf("DecodeHelperExecBody() error = %v", err)
				}
				if decoded.Revision != 3 || decoded.ExecBindingID != "exec-binding-3" || decoded.Plan.WorkDirectory != "/workspace" {
					t.Fatalf("exec body = %#v", decoded)
				}
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			stream := newFakeHelperStream()
			owner := &fakeHelperOwner{stream: stream}
			var helperSends atomic.Uint32
			var receiveCount atomic.Uint32
			transport := &dispatchRedTransport{identity: identity}
			transport.receiveController = func(_ context.Context, receive ControllerReceiveRequest) (ControllerPacket, error) {
				count := receiveCount.Add(1)
				if count == 1 {
					return ControllerPacket{
						sequence:  1,
						sessionID: identity.sessionID,
						arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
					}, nil
				}
				expected, set := receive.expectedIdentityValue()
				if count != 2 || !set || expected != digest || receive.nextSequenceValue() != 2 {
					return ControllerPacket{}, errors.New("later metadata send was not admitted with the pinned identity")
				}
				return test.packet, nil
			}
			transport.sendController = func(context.Context, ControllerSendPacket) error {
				return errors.New("controller success must not mint proofs")
			}
			transport.sendHelper = func(context.Context, HelperSendPacket) error {
				helperSends.Add(1)
				return errors.New("legacy transport helper send must stay unused")
			}

			err := newDispatchRedClientOpts(t, transport, owner).Serve(context.Background())
			if !errors.Is(err, ErrClientControlDependencyUnaccepted) {
				t.Fatalf("Serve() error = %v, want payload/proofs unaccepted after metadata send", err)
			}
			if owner.accepts.Load() != 1 || helperSends.Load() != 0 {
				t.Fatalf("accepts/legacy helper sends = %d/%d, want 1/0", owner.accepts.Load(), helperSends.Load())
			}
			if receiveCount.Load() != 2 {
				t.Fatalf("controller receives = %d, want prepare plus rejected later %s", receiveCount.Load(), test.name)
			}
			packets := decodeHelperDatagrams(t, stream.bytes())
			if len(packets) != 1 {
				t.Fatalf("helper datagrams = %d, want prepare-begin only before %s", len(packets), test.name)
			}
			if packets[0].header.Type != credentialprotocol.PacketTypePrepareBegin || packets[0].header.Sequence != firstInjectedHelperSendSequence {
				t.Fatalf("first helper header = %#v", packets[0].header)
			}
		})
	}
}

func TestL8D7GuestHelperServeStopsBeforeControllerPayloadAfterPrepareBegin(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testDispatchPrepareRequest(t, identity)
	payload := []byte("controller-private-payload")
	digest := sha256.Sum256(payload)
	body := &testHelperBody{length: uint32(len(payload)), digest: digest}
	stream := newFakeHelperStream()
	owner := &fakeHelperOwner{stream: stream}
	var receiveCount atomic.Uint32
	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
		if receiveCount.Add(1) == 1 {
			return ControllerPacket{
				sequence:  1,
				sessionID: identity.sessionID,
				arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
			}, nil
		}
		return ControllerPacket{
			sequence:  2,
			sessionID: identity.sessionID,
			arm:       controllerPacketArm{kind: controllerPacketArmPrivate},
			body:      body,
		}, nil
	}

	err := newDispatchRedClientOpts(t, transport, owner).Serve(context.Background())
	if !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("Serve() error = %v, want prepare-file dependency unaccepted", err)
	}
	if !body.destroyed || receiveCount.Load() != 2 {
		t.Fatalf("malformed later payload was not consumed fail-closed: destroyed=%t receives=%d", body.destroyed, receiveCount.Load())
	}
	packets := decodeHelperDatagrams(t, stream.bytes())
	if len(packets) != 1 || packets[0].header.Type != credentialprotocol.PacketTypePrepareBegin {
		t.Fatalf("payload path sent extra helper packets: %#v", packets)
	}
}

type helperDatagram struct {
	header credentialprotocol.HelperPacketHeader
	body   []byte
}

func decodeHelperDatagrams(t *testing.T, datagram []byte) []helperDatagram {
	t.Helper()
	var packets []helperDatagram
	remaining := datagram
	for len(remaining) > 0 {
		if len(remaining) < credentialprotocol.HelperPacketHeaderSize {
			t.Fatalf("truncated helper header: %d bytes", len(remaining))
		}
		header, err := credentialprotocol.DecodeHelperPacketHeader(remaining[:credentialprotocol.HelperPacketHeaderSize])
		if err != nil {
			t.Fatalf("DecodeHelperPacketHeader() error = %v", err)
		}
		total := credentialprotocol.HelperPacketHeaderSize + int(header.BodyLength)
		if len(remaining) < total {
			t.Fatalf("truncated helper body: have %d, want %d", len(remaining), total)
		}
		packets = append(packets, helperDatagram{
			header: header,
			body:   append([]byte(nil), remaining[credentialprotocol.HelperPacketHeaderSize:total]...),
		})
		remaining = remaining[total:]
	}
	return packets
}

func TestL8D7GuestHelperCloseWaitsForAdmittedPrepareBegin(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testDispatchPrepareRequest(t, identity)
	stream := newFakeHelperStream()
	owner := &blockingHelperOwner{
		stream:        stream,
		acceptEntered: make(chan struct{}),
		allowAccept:   make(chan struct{}),
		closeCalled:   make(chan struct{}),
	}
	defer func() {
		select {
		case <-owner.allowAccept:
		default:
			close(owner.allowAccept)
		}
	}()
	closed := make(chan struct{})
	transport := &dispatchRedTransport{identity: identity}
	var receiveCount atomic.Uint32
	transport.receiveController = func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
		if receiveCount.Add(1) == 1 {
			return ControllerPacket{
				sequence:  1,
				sessionID: identity.sessionID,
				arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
			}, nil
		}
		select {
		case <-closed:
			return ControllerPacket{}, errors.New("closed")
		case <-time.After(2 * time.Second):
			return ControllerPacket{}, errors.New("timed out waiting for close")
		}
	}
	transport.close = func(context.Context) error {
		transport.closeOnce.Do(func() { close(closed) })
		return nil
	}

	client := newDispatchRedClientOpts(t, transport, owner)
	serveDone := make(chan error, 1)
	go func() { serveDone <- client.Serve(context.Background()) }()
	select {
	case <-owner.acceptEntered:
	case err := <-serveDone:
		t.Fatalf("Serve returned before helper admission: %v", err)
	case <-time.After(time.Second):
		t.Fatal("helper admission did not start")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close(context.Background()) }()
	select {
	case <-owner.closeCalled:
	case <-time.After(time.Second):
		t.Fatal("Close did not close the helper owner")
	}
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before the admitted helper send terminated: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(owner.allowAccept)
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve() after Close joined the in-flight helper send = %v", err)
	}
}

func newDispatchRedClientOpts(t *testing.T, transport Transport, helper HelperConnectionOwner) *Client {
	t.Helper()
	registry, err := NewExtensionRegistry()
	if err != nil {
		t.Fatal(err)
	}
	policy := NewClientPolicy()
	client, err := NewClient(ClientOptions{
		Transport: transport, Policy: policy, Extensions: registry,
		Descriptor: newLifecycleDescriptor(policy.Descriptor(), nil),
		Helper:     helper,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func newDispatchRedClientWithSSHSession(t *testing.T, transport Transport, helper HelperConnectionOwner, session ExtensionSession) *Client {
	t.Helper()
	registry, err := NewExtensionRegistry(ExtensionRegistration{
		Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor(),
		Factory:    staticSSHFactory{session: session},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := NewClientPolicy()
	client, err := NewClient(ClientOptions{
		Transport: transport, Policy: policy, Extensions: registry,
		Descriptor: newLifecycleDescriptor(policy.Descriptor(), registry.Descriptors()),
		Helper:     helper,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type staticSSHFactory struct {
	session ExtensionSession
}

func (factory staticSSHFactory) Open(context.Context, ExtensionOpenRequest) (ExtensionSession, error) {
	return factory.session, nil
}

type recordingSSHSession struct {
	mu         sync.Mutex
	handled    atomic.Uint32
	accepted   SSHAcceptedPacket
	handleErr  error
	handleHook func()
	handledCh  chan struct{}
}

func (session *recordingSSHSession) Handle(_ context.Context, packet ExtensionPacket) error {
	accepted, ok := packet.SSHAccepted()
	if !ok {
		return errors.New("missing SSH accepted arm")
	}
	session.mu.Lock()
	session.accepted = accepted
	session.mu.Unlock()
	session.handled.Add(1)
	if session.handledCh != nil {
		select {
		case <-session.handledCh:
		default:
			close(session.handledCh)
		}
	}
	if session.handleHook != nil {
		session.handleHook()
	}
	return session.handleErr
}

func (session *recordingSSHSession) Close(context.Context) error { return nil }

func (session *recordingSSHSession) acceptedPacket(t *testing.T) SSHAcceptedPacket {
	t.Helper()
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.handled.Load() == 0 {
		t.Fatal("SSH extension Handle was not called")
	}
	return session.accepted
}

type gatedSSHSession struct {
	mu            sync.Mutex
	accepted      SSHAcceptedPacket
	handleStarted chan struct{}
	handleRelease chan struct{}
	closed        chan struct{}
	closeOnce     sync.Once
}

func (session *gatedSSHSession) Handle(_ context.Context, packet ExtensionPacket) error {
	accepted, ok := packet.SSHAccepted()
	if !ok {
		return errors.New("missing SSH accepted arm")
	}
	session.mu.Lock()
	session.accepted = accepted
	session.mu.Unlock()
	close(session.handleStarted)
	<-session.handleRelease
	return nil
}

func (session *gatedSSHSession) Close(context.Context) error {
	session.closeOnce.Do(func() { close(session.closed) })
	return nil
}

func (session *gatedSSHSession) acceptedPacket(t *testing.T) SSHAcceptedPacket {
	t.Helper()
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.accepted
}

type fakeHelperStream struct {
	mu       sync.Mutex
	cond     *sync.Cond
	out      bytes.Buffer
	inbound  [][]byte
	closed   bool
	deadline time.Time
}

func newFakeHelperStream() *fakeHelperStream {
	stream := &fakeHelperStream{}
	stream.cond = sync.NewCond(&stream.mu)
	return stream
}

func (stream *fakeHelperStream) Read(p []byte) (int, error) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	for {
		if stream.closed {
			return 0, io.EOF
		}
		if stream.deadlineExpiredLocked() {
			return 0, osErrDeadline()
		}
		if len(stream.inbound) > 0 {
			datagram := stream.inbound[0]
			n := copy(p, datagram)
			if n == len(datagram) {
				stream.inbound = stream.inbound[1:]
			} else {
				stream.inbound[0] = datagram[n:]
			}
			return n, nil
		}
		stream.cond.Wait()
	}
}

func (stream *fakeHelperStream) Write(p []byte) (int, error) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closed {
		return 0, io.ErrClosedPipe
	}
	return stream.out.Write(p)
}

func (stream *fakeHelperStream) SetDeadline(deadline time.Time) error {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	stream.deadline = deadline
	stream.cond.Broadcast()
	return nil
}

func (stream *fakeHelperStream) Close() error {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	stream.closed = true
	stream.cond.Broadcast()
	return nil
}

func (stream *fakeHelperStream) bytes() []byte {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return append([]byte(nil), stream.out.Bytes()...)
}

func (stream *fakeHelperStream) queueHelperDatagram(datagram []byte) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	stream.inbound = append(stream.inbound, append([]byte(nil), datagram...))
	stream.cond.Signal()
}

func (stream *fakeHelperStream) deadlineExpiredLocked() bool {
	return !stream.deadline.IsZero() && !stream.deadline.After(time.Now())
}

func osErrDeadline() error {
	return errFakeHelperDeadline
}

var errFakeHelperDeadline = errors.New("fake helper stream deadline exceeded")

type fakeHelperOwner struct {
	stream  VerifiedHelperStream
	accepts atomic.Uint32
}

type blockingHelperOwner struct {
	stream        VerifiedHelperStream
	acceptEntered chan struct{}
	allowAccept   chan struct{}
	closeCalled   chan struct{}
	acceptOnce    sync.Once
	closeOnce     sync.Once
}

func (owner *blockingHelperOwner) AcceptVerified(_ context.Context, expectation HelperAcceptExpectation) (VerifiedHelperStream, error) {
	if !expectation.valid() || !configuredDependency(owner.stream) {
		return nil, errInvalidHelperAcceptExpectation
	}
	owner.acceptOnce.Do(func() { close(owner.acceptEntered) })
	<-owner.allowAccept
	return owner.stream, nil
}

func (owner *blockingHelperOwner) Close(context.Context) error {
	owner.closeOnce.Do(func() { close(owner.closeCalled) })
	return nil
}

func (owner *fakeHelperOwner) AcceptVerified(_ context.Context, expectation HelperAcceptExpectation) (VerifiedHelperStream, error) {
	if !expectation.valid() || !configuredDependency(owner.stream) {
		return nil, errInvalidHelperAcceptExpectation
	}
	owner.accepts.Add(1)
	return owner.stream, nil
}

func (owner *fakeHelperOwner) Close(context.Context) error {
	if owner.stream == nil {
		return nil
	}
	return owner.stream.Close()
}

var (
	_ VerifiedHelperStream  = (*fakeHelperStream)(nil)
	_ HelperConnectionOwner = (*fakeHelperOwner)(nil)
	_ HelperConnectionOwner = (*blockingHelperOwner)(nil)
)
