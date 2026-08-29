package credentialclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/v2control"
)

func TestL8D7GuestHelperMetadataOnlyPrepareResponseInstallsExactActiveLedger(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testHTTPOnlyDispatchPrepareRequest(t, identity)
	sessionIdentity := testHTTPOnlyDispatchSessionIdentity(t, identity)
	digest := identityDigestForSession(t, sessionIdentity)
	records, manifest, err := projectV2ManifestToHelperRecords(prepare.Bindings())
	if err != nil || len(records) != 1 || manifest == ([32]byte{}) {
		t.Fatalf("projected helper records = %#v digest %x err %v", records, manifest, err)
	}

	stream := newFakeHelperStream()
	owner := &fakeHelperOwner{stream: stream}
	stream.queueHelperDatagram(encodeHelperResponseDatagram(t, 1, prepare.RequestID().Bytes(), digest.Bytes(), identity.identity.GuestBootNonce, matchingHTTPPrepareHelperResponse(t, prepare)))

	var controllerSends atomic.Uint32
	closed := make(chan struct{})
	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = blockingControllerAfter(t, []ControllerPacket{{
		sequence:  1,
		sessionID: identity.sessionID,
		arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
	}}, closed)
	transport.sendController = func(_ context.Context, packet ControllerSendPacket) error {
		response, ok := packet.prepareResponseValue()
		if !ok || response.ActiveProofID() != "active-proof" || response.ExecBindingID() != "exec-binding" {
			return errors.New("prepare success lost helper proof mapping")
		}
		proofs := response.BindingProofs()
		if len(proofs) != 1 || proofs[0].BindingID() != "binding-http" || proofs[0].ProofID() != "proof-http" {
			return errors.New("prepare success proof IDs were not copied after exact match")
		}
		controllerSends.Add(1)
		return nil
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
		t.Fatalf("Serve() after ledger install = %v", err)
	}
	assertHelperPacketTypes(t, stream, credentialprotocol.PacketTypePrepareBegin, credentialprotocol.PacketTypePrepareCommit)
}

func TestL8D7GuestHelperCloseWaitsForAdmittedControllerSuccess(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testHTTPOnlyDispatchPrepareRequest(t, identity)
	digest := identityDigestForSession(t, testHTTPOnlyDispatchSessionIdentity(t, identity))
	stream := newFakeHelperStream()
	stream.queueHelperDatagram(encodeHelperResponseDatagram(
		t, 1, prepare.RequestID().Bytes(), digest.Bytes(), identity.identity.GuestBootNonce,
		matchingHTTPPrepareHelperResponse(t, prepare),
	))

	sendStarted := make(chan struct{})
	releaseSend := make(chan struct{})
	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
		return ControllerPacket{
			sequence:  1,
			sessionID: identity.sessionID,
			arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
		}, nil
	}
	transport.sendController = func(context.Context, ControllerSendPacket) error {
		close(sendStarted)
		<-releaseSend
		return nil
	}

	client := newDispatchRedClientOpts(t, transport, &fakeHelperOwner{stream: stream})
	serveDone := make(chan error, 1)
	go func() { serveDone <- client.Serve(context.Background()) }()
	select {
	case <-sendStarted:
	case err := <-serveDone:
		t.Fatalf("Serve returned before controller success admission: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("controller success send did not start")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close(context.Background()) }()
	select {
	case err := <-closeDone:
		close(releaseSend)
		<-serveDone
		t.Fatalf("Close returned before admitted controller success completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseSend)
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve() after joined controller success = %v", err)
	}
}

func TestL8D7GuestHelperPrepareResponseMismatchInstallsNoActiveLedger(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testHTTPOnlyDispatchPrepareRequest(t, identity)
	digest := identityDigestForSession(t, testHTTPOnlyDispatchSessionIdentity(t, identity))

	cases := []struct {
		name     string
		response credentialprotocol.HelperResponseBody
	}{
		{
			name: "binding-id",
			response: mutateHTTPPrepareHelperResponse(t, prepare, func(result *credentialprotocol.HelperPrepareResponseResult) {
				result.BindingProofs[0].BindingID = "binding-other"
			}),
		},
		{
			name: "mode",
			response: mutateHTTPPrepareHelperResponse(t, prepare, func(result *credentialprotocol.HelperPrepareResponseResult) {
				result.BindingProofs[0].Mode = credentialprotocol.DeliveryModeSSHAgent
			}),
		},
		{
			name: "count",
			response: mutateHTTPPrepareHelperResponse(t, prepare, func(result *credentialprotocol.HelperPrepareResponseResult) {
				result.BindingProofs = append(result.BindingProofs, credentialprotocol.HelperBindingProof{
					BindingID: "binding-ssh", Mode: credentialprotocol.DeliveryModeSSHAgent, ProofID: "proof-ssh",
				})
			}),
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			stream := newFakeHelperStream()
			owner := &fakeHelperOwner{stream: stream}
			stream.queueHelperDatagram(encodeHelperResponseDatagram(t, 1, prepare.RequestID().Bytes(), digest.Bytes(), identity.identity.GuestBootNonce, test.response))
			var sends atomic.Uint32
			transport := &dispatchRedTransport{identity: identity}
			transport.receiveController = func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
				return ControllerPacket{
					sequence:  1,
					sessionID: identity.sessionID,
					arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
				}, nil
			}
			transport.sendController = func(context.Context, ControllerSendPacket) error {
				sends.Add(1)
				return errors.New("mismatch must not send controller success or install a ledger")
			}
			err := newDispatchRedClientOpts(t, transport, owner).Serve(context.Background())
			if clientContractCode(err) != ClientContractCorrelation {
				t.Fatalf("Serve() error = %v, want correlation mismatch without active ledger", err)
			}
			if sends.Load() != 0 {
				t.Fatalf("controller sends = %d, want 0", sends.Load())
			}
			assertHelperPacketTypes(t, stream, credentialprotocol.PacketTypePrepareBegin, credentialprotocol.PacketTypePrepareCommit)
		})
	}
}

func TestL8D7GuestHelperFileBearingPrepareSendsFileThenCommitAndLedger(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare, payload, fileDigest := testFileBearingDispatchPrepareRequest(t, identity)
	sessionIdentity := testCredentialPacketSessionIdentity(t, identity.sessionID)
	digest := identityDigestForSession(t, sessionIdentity)
	stream := newFakeHelperStream()
	owner := &fakeHelperOwner{stream: stream}
	stream.queueHelperDatagram(encodeHelperResponseDatagram(
		t, 1, prepare.RequestID().Bytes(), digest.Bytes(), identity.identity.GuestBootNonce,
		matchingFileBearingPrepareHelperResponse(t, prepare),
	))
	privateBody := testControllerPrepareFileBody(payload, fileDigest)
	var controllerSends atomic.Uint32
	closed := make(chan struct{})
	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = blockingControllerAfter(t, []ControllerPacket{
		{sequence: 1, sessionID: identity.sessionID, arm: controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare}},
		testControllerPrivateFilePacket(2, identity, prepare, digest, 1, payload, fileDigest, privateBody),
	}, closed)
	transport.sendController = func(_ context.Context, packet ControllerSendPacket) error {
		response, ok := packet.prepareResponseValue()
		if !ok || response.ActiveProofID() != "active-proof" || response.ExecBindingID() != "exec-binding" {
			return errors.New("file-bearing prepare success lost helper proof mapping")
		}
		proofs := response.BindingProofs()
		if len(proofs) != 2 || proofs[0].BindingID() != "binding-http" || proofs[1].BindingID() != "binding-file" ||
			proofs[1].ProofID() != "proof-file" {
			return errors.New("file-bearing prepare proofs were not copied after exact match")
		}
		controllerSends.Add(1)
		return nil
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
		t.Fatalf("Serve() after file-bearing ledger install = %v", err)
	}
	if !privateBody.destroyed {
		t.Fatal("admitted prepare-file controller body was not destroyed")
	}
	assertHelperPacketTypes(t, stream,
		credentialprotocol.PacketTypePrepareBegin,
		credentialprotocol.PacketTypePrepareFile,
		credentialprotocol.PacketTypePrepareCommit,
	)
	packets := decodeHelperDatagrams(t, stream.bytes())
	decoded, err := credentialprotocol.DecodeHelperPrepareFileBody(packets[1].body)
	if err != nil {
		t.Fatalf("DecodeHelperPrepareFileBody() error = %v", err)
	}
	defer decoded.Wipe()
	if decoded.Revision() != 1 || decoded.BindingIndex() != 1 || decoded.FileLength() != uint32(len(payload)) || decoded.FileSHA256() != fileDigest {
		t.Fatal("prepare-file metadata did not match the begin manifest")
	}
	got := make([]byte, len(payload))
	if n, copyErr := decoded.CopyPrivateBytes(got); copyErr != nil || n != len(payload) || sha256.Sum256(got) != fileDigest {
		t.Fatal("prepare-file private bytes did not match the admitted payload digest")
	}
	if packets[0].header.RequestID != prepare.RequestID().Bytes() || packets[1].header.RequestID != prepare.RequestID().Bytes() ||
		packets[2].header.RequestID != prepare.RequestID().Bytes() || packets[1].header.Sequence != 2 || packets[2].header.Sequence != 3 {
		t.Fatalf("file-bearing helper headers = %#v %#v %#v", packets[0].header, packets[1].header, packets[2].header)
	}
}

func TestL8D7GuestHelperPrepareFileBodyCleanupFailureStopsBeforeCommit(t *testing.T) {
	for _, test := range []struct {
		name       string
		destroyErr error
		panic      bool
	}{
		{name: "error", destroyErr: errors.New("destroy failed")},
		{name: "panic", panic: true},
	} {
		t.Run(test.name, func(t *testing.T) {
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
			privateBody.destroyErr = test.destroyErr
			privateBody.destroyPanic = test.panic
			var receives atomic.Uint32
			var sends atomic.Uint32
			transport := &dispatchRedTransport{identity: identity}
			transport.receiveController = func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
				switch receives.Add(1) {
				case 1:
					return ControllerPacket{sequence: 1, sessionID: identity.sessionID, arm: controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare}}, nil
				case 2:
					return testControllerPrivateFilePacket(2, identity, prepare, digest, 1, payload, fileDigest, privateBody), nil
				default:
					return ControllerPacket{}, errors.New("stop")
				}
			}
			transport.sendController = func(context.Context, ControllerSendPacket) error {
				sends.Add(1)
				return nil
			}

			err := newDispatchRedClientOpts(t, transport, owner).Serve(context.Background())
			if clientContractCode(err) != ClientContractCleanup {
				t.Fatalf("Serve() error = %v, want cleanup", err)
			}
			if sends.Load() != 0 {
				t.Fatalf("controller sends = %d, want 0", sends.Load())
			}
			assertHelperPacketTypes(t, stream,
				credentialprotocol.PacketTypePrepareBegin,
				credentialprotocol.PacketTypePrepareFile,
			)
		})
	}
}

func TestL8D7GuestHelperNilOwnerDoesNotSendHelper(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testHTTPOnlyDispatchPrepareRequest(t, identity)
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
		t.Fatalf("Serve() error = %v, want nil owner unaccepted", err)
	}
	if helperSends.Load() != 0 {
		t.Fatalf("legacy helper sends = %d, want 0", helperSends.Load())
	}
}

func TestL8D7GuestHelperRenewRevokeExecAfterLedger(t *testing.T) {
	identity := testDispatchTransportIdentity()

	t.Run("renew", func(t *testing.T) {
		prepare := testHTTPOnlyDispatchPrepareRequest(t, identity)
		sessionIdentity := testHTTPOnlyDispatchSessionIdentity(t, identity)
		digest := identityDigestForSession(t, sessionIdentity)
		renewID := testPacketRequestIDSeed(t, 0x21)
		renew, err := v2control.NewCredentialRenewRequest(renewID, sessionIdentity, 1, 1700000001123456789, 1700000001123456789, 1700000001123456789, "active-proof")
		if err != nil {
			t.Fatal(err)
		}
		stream := newFakeHelperStream()
		nonce := identity.identity.GuestBootNonce
		stream.queueHelperDatagram(encodeHelperResponseDatagram(t, 1, prepare.RequestID().Bytes(), digest.Bytes(), nonce, matchingHTTPPrepareHelperResponse(t, prepare)))
		stream.queueHelperDatagram(encodeHelperResponseDatagram(t, 2, renew.RequestID().Bytes(), digest.Bytes(), nonce, credentialprotocol.HelperResponseBody{
			RequestType: credentialprotocol.PacketTypeRenew,
			Disposition: credentialprotocol.ResponseDispositionAccepted,
			Revision:    2,
			FailureCode: credentialprotocol.FailureCodeNone,
			Renew:       &credentialprotocol.HelperRenewResponseResult{ExpiresAtUnixNano: renew.ExpiresAtUnixNano(), ReplacementActiveProofID: "replacement-proof"},
		}))
		closed := make(chan struct{})
		var sends atomic.Uint32
		transport := &dispatchRedTransport{identity: identity}
		transport.receiveController = blockingControllerAfter(t, []ControllerPacket{
			{sequence: 1, sessionID: identity.sessionID, arm: controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare}},
			{sequence: 2, sessionID: identity.sessionID, arm: controllerPacketArm{kind: controllerPacketArmRenew, renew: renew}},
		}, closed)
		transport.sendController = func(_ context.Context, packet ControllerSendPacket) error {
			if sends.Add(1) == 1 {
				if _, ok := packet.prepareResponseValue(); !ok {
					return errors.New("first controller send must be prepare success")
				}
				return nil
			}
			response, ok := packet.renewResponseValue()
			if !ok || response.ReplacementActiveProofID() != "replacement-proof" {
				return errors.New("renew success lost helper mapping")
			}
			return nil
		}
		transport.close = func(context.Context) error {
			transport.closeOnce.Do(func() { close(closed) })
			return nil
		}
		client := newDispatchRedClientOpts(t, transport, &fakeHelperOwner{stream: stream})
		serveDone := make(chan error, 1)
		go func() { serveDone <- client.Serve(context.Background()) }()
		waitForControllerSends(t, &sends, 2, serveDone)
		if err := client.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := <-serveDone; err != nil {
			t.Fatalf("Serve() after renew = %v", err)
		}
		assertHelperPacketTypes(t, stream,
			credentialprotocol.PacketTypePrepareBegin,
			credentialprotocol.PacketTypePrepareCommit,
			credentialprotocol.PacketTypeRenew,
		)
	})

	t.Run("revoke", func(t *testing.T) {
		prepare := testHTTPOnlyDispatchPrepareRequest(t, identity)
		sessionIdentity := testHTTPOnlyDispatchSessionIdentity(t, identity)
		digest := identityDigestForSession(t, sessionIdentity)
		revokeID := testPacketRequestIDSeed(t, 0x22)
		revoke, err := v2control.NewCredentialRevokeRequest(revokeID, sessionIdentity, 1, v2control.CredentialRevokeReasonRequested)
		if err != nil {
			t.Fatal(err)
		}
		stream := newFakeHelperStream()
		nonce := identity.identity.GuestBootNonce
		stream.queueHelperDatagram(encodeHelperResponseDatagram(t, 1, prepare.RequestID().Bytes(), digest.Bytes(), nonce, matchingHTTPPrepareHelperResponse(t, prepare)))
		stream.queueHelperDatagram(encodeHelperResponseDatagram(t, 2, revoke.RequestID().Bytes(), digest.Bytes(), nonce, credentialprotocol.HelperResponseBody{
			RequestType: credentialprotocol.PacketTypeRevoke,
			Disposition: credentialprotocol.ResponseDispositionCleanupComplete,
			Revision:    1,
			FailureCode: credentialprotocol.FailureCodeNone,
			Revoke:      &credentialprotocol.HelperRevokeResponseResult{CleanupProofID: "cleanup-proof", AuthorityAbsent: true, ResourcesAbsent: true},
		}))
		closed := make(chan struct{})
		var sends atomic.Uint32
		transport := &dispatchRedTransport{identity: identity}
		transport.receiveController = blockingControllerAfter(t, []ControllerPacket{
			{sequence: 1, sessionID: identity.sessionID, arm: controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare}},
			{sequence: 2, sessionID: identity.sessionID, arm: controllerPacketArm{kind: controllerPacketArmRevoke, revoke: revoke}},
		}, closed)
		transport.sendController = func(_ context.Context, packet ControllerSendPacket) error {
			count := sends.Add(1)
			if count == 1 {
				if _, ok := packet.prepareResponseValue(); !ok {
					return errors.New("first controller send must be prepare success")
				}
				return nil
			}
			if _, ok := packet.revokeResponseValue(); !ok {
				return errors.New("revoke success lost helper mapping")
			}
			return nil
		}
		transport.close = func(context.Context) error {
			transport.closeOnce.Do(func() { close(closed) })
			return nil
		}
		client := newDispatchRedClientOpts(t, transport, &fakeHelperOwner{stream: stream})
		serveDone := make(chan error, 1)
		go func() { serveDone <- client.Serve(context.Background()) }()
		waitForControllerSends(t, &sends, 2, serveDone)
		if err := client.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := <-serveDone; err != nil {
			t.Fatalf("Serve() after revoke = %v", err)
		}
		assertHelperPacketTypes(t, stream,
			credentialprotocol.PacketTypePrepareBegin,
			credentialprotocol.PacketTypePrepareCommit,
			credentialprotocol.PacketTypeRevoke,
		)
	})

	t.Run("exec", func(t *testing.T) {
		prepare := testSSHOnlyDispatchPrepareRequest(t, identity)
		sessionIdentity := testSSHOnlyDispatchSessionIdentity(t, identity)
		digest := identityDigestForSession(t, sessionIdentity)
		execReq := testSSHOnlyDispatchExecRequest(t, testPacketRequestIDSeed(t, 0x23), sessionIdentity)
		stream := newFakeHelperStream()
		nonce := identity.identity.GuestBootNonce
		empty := sha256.Sum256(nil)
		txn := sha256.Sum256([]byte("exec-txn"))
		stream.queueHelperDatagram(encodeHelperResponseDatagram(t, 1, prepare.RequestID().Bytes(), digest.Bytes(), nonce, matchingSSHPrepareHelperResponse(t, prepare)))
		stream.queueHelperDatagram(encodeHelperResponseDatagram(t, 2, execReq.RequestID().Bytes(), digest.Bytes(), nonce, credentialprotocol.HelperResponseBody{
			RequestType: credentialprotocol.PacketTypeExec,
			Disposition: credentialprotocol.ResponseDispositionAccepted,
			Revision:    1,
			FailureCode: credentialprotocol.FailureCodeNone,
			Exec: &credentialprotocol.HelperExecResponseResult{
				ExitCode: 0, StdinBytes: 0, StdinSHA256: empty,
				StdoutBytes: 0, StdoutSHA256: empty, StderrBytes: 0, StderrSHA256: empty,
				ExecTransactionSHA256: txn,
			},
		}))
		closed := make(chan struct{})
		var sends atomic.Uint32
		transport := &dispatchRedTransport{identity: identity}
		transport.receiveController = blockingControllerAfter(t, []ControllerPacket{
			{sequence: 1, sessionID: identity.sessionID, arm: controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare}},
			{sequence: 2, sessionID: identity.sessionID, arm: controllerPacketArm{kind: controllerPacketArmExec, exec: execReq}},
		}, closed)
		transport.sendController = func(_ context.Context, packet ControllerSendPacket) error {
			count := sends.Add(1)
			if count == 1 {
				if _, ok := packet.prepareResponseValue(); !ok {
					return errors.New("first controller send must be prepare success")
				}
				return nil
			}
			response, ok := packet.execResponseValue()
			if !ok || response.RequestID() != execReq.RequestID() {
				return errors.New("exec success lost helper mapping")
			}
			return nil
		}
		transport.close = func(context.Context) error {
			transport.closeOnce.Do(func() { close(closed) })
			return nil
		}
		client := newDispatchRedClientOpts(t, transport, &fakeHelperOwner{stream: stream})
		serveDone := make(chan error, 1)
		go func() { serveDone <- client.Serve(context.Background()) }()
		waitForControllerSends(t, &sends, 2, serveDone)
		if err := client.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := <-serveDone; err != nil {
			t.Fatalf("Serve() after exec = %v", err)
		}
		assertHelperPacketTypes(t, stream,
			credentialprotocol.PacketTypePrepareBegin,
			credentialprotocol.PacketTypePrepareCommit,
			credentialprotocol.PacketTypeExec,
		)
	})
}

func TestL8D7GuestHelperNonemptyPrivateExecRemainsUnacceptedAfterLedger(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testHTTPOnlyDispatchPrepareRequest(t, identity)
	sessionIdentity := testHTTPOnlyDispatchSessionIdentity(t, identity)
	digest := identityDigestForSession(t, sessionIdentity)
	execReq := testHTTPOnlyPrivateExecRequest(t, testPacketRequestIDSeed(t, 0x24), sessionIdentity)
	stream := newFakeHelperStream()
	stream.queueHelperDatagram(encodeHelperResponseDatagram(t, 1, prepare.RequestID().Bytes(), digest.Bytes(), identity.identity.GuestBootNonce, matchingHTTPPrepareHelperResponse(t, prepare)))
	closed := make(chan struct{})
	var sends atomic.Uint32
	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = blockingControllerAfter(t, []ControllerPacket{
		{sequence: 1, sessionID: identity.sessionID, arm: controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare}},
		{sequence: 2, sessionID: identity.sessionID, arm: controllerPacketArm{kind: controllerPacketArmExec, exec: execReq}},
	}, closed)
	transport.sendController = func(_ context.Context, packet ControllerSendPacket) error {
		if _, ok := packet.prepareResponseValue(); !ok {
			return errors.New("nonempty private exec must not produce a later controller success")
		}
		sends.Add(1)
		return nil
	}
	transport.close = func(context.Context) error {
		transport.closeOnce.Do(func() { close(closed) })
		return nil
	}
	client := newDispatchRedClientOpts(t, transport, &fakeHelperOwner{stream: stream})
	err := client.Serve(context.Background())
	if !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("Serve() error = %v, want nonempty private exec unaccepted", err)
	}
	if sends.Load() != 1 {
		t.Fatalf("controller sends = %d, want prepare success only", sends.Load())
	}
	assertHelperPacketTypes(t, stream, credentialprotocol.PacketTypePrepareBegin, credentialprotocol.PacketTypePrepareCommit)
}

func TestL8D7GuestHelperResponseReceiveDrainAndCancel(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testHTTPOnlyDispatchPrepareRequest(t, identity)

	t.Run("drain", func(t *testing.T) {
		stream := newFakeHelperStream()
		owner := &fakeHelperOwner{stream: stream}
		closed := make(chan struct{})
		transport := &dispatchRedTransport{identity: identity}
		transport.receiveController = func(ctx context.Context, _ ControllerReceiveRequest) (ControllerPacket, error) {
			select {
			case <-closed:
				return ControllerPacket{}, errors.New("closed")
			default:
			}
			return ControllerPacket{
				sequence:  1,
				sessionID: identity.sessionID,
				arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
			}, nil
		}
		transport.close = func(context.Context) error {
			transport.closeOnce.Do(func() { close(closed) })
			return nil
		}
		client := newDispatchRedClientOpts(t, transport, owner)
		serveDone := make(chan error, 1)
		go func() { serveDone <- client.Serve(context.Background()) }()
		waitForHelperPacketCount(t, stream, 2, serveDone)
		if err := client.Close(context.Background()); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		select {
		case err := <-serveDone:
			if err != nil {
				t.Fatalf("Serve() after drain during helper receive = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Serve did not return after Close drained helper receive")
		}
	})

	t.Run("cancel", func(t *testing.T) {
		stream := newFakeHelperStream()
		owner := &fakeHelperOwner{stream: stream}
		transport := &dispatchRedTransport{identity: identity}
		transport.receiveController = func(ctx context.Context, _ ControllerReceiveRequest) (ControllerPacket, error) {
			if ctx.Err() != nil {
				return ControllerPacket{}, ctx.Err()
			}
			return ControllerPacket{
				sequence:  1,
				sessionID: identity.sessionID,
				arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
			}, nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		client := newDispatchRedClientOpts(t, transport, owner)
		serveDone := make(chan error, 1)
		go func() { serveDone <- client.Serve(ctx) }()
		waitForHelperPacketCount(t, stream, 2, serveDone)
		cancel()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Fatalf("Serve() after cancel during helper receive = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Serve did not return after cancel during helper receive")
		}
		if err := client.Close(context.Background()); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})
}

func TestL8D7GuestHelperMapSuccessConstructors(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testHTTPOnlyDispatchPrepareRequest(t, identity)
	digest := identityDigestForSession(t, testHTTPOnlyDispatchSessionIdentity(t, identity))
	header := testHelperHeader(credentialprotocol.PacketTypeResponse, 1, prepare.RequestID().Bytes(), digest.Bytes(), identity.identity.GuestBootNonce, 1)
	body := matchingHTTPPrepareHelperResponse(t, prepare)
	encoded, err := credentialprotocol.EncodeHelperResponseBody(body)
	if err != nil {
		t.Fatal(err)
	}
	header.BodyLength = uint32(len(encoded))
	mapped, err := mapHelperPrepareSuccessToV2(prepare, header, body)
	if err != nil || mapped.ActiveProofID() != "active-proof" {
		t.Fatalf("mapHelperPrepareSuccessToV2() = %#v, %v", mapped, err)
	}
	sessionIdentity := testHTTPOnlyDispatchSessionIdentity(t, identity)
	renew, err := v2control.NewCredentialRenewRequest(testPacketRequestIDSeed(t, 0x31), sessionIdentity, 1, 1700000001123456789, 1700000001123456789, 1700000001123456789, "active-proof")
	if err != nil {
		t.Fatal(err)
	}
	renewBody := credentialprotocol.HelperResponseBody{
		RequestType: credentialprotocol.PacketTypeRenew, Disposition: credentialprotocol.ResponseDispositionAccepted,
		Revision: 2, FailureCode: credentialprotocol.FailureCodeNone,
		Renew: &credentialprotocol.HelperRenewResponseResult{ExpiresAtUnixNano: renew.ExpiresAtUnixNano(), ReplacementActiveProofID: "replacement-proof"},
	}
	renewHeader := testHelperHeader(credentialprotocol.PacketTypeResponse, 2, renew.RequestID().Bytes(), digest.Bytes(), identity.identity.GuestBootNonce, 1)
	renewEncoded, err := credentialprotocol.EncodeHelperResponseBody(renewBody)
	if err != nil {
		t.Fatal(err)
	}
	renewHeader.BodyLength = uint32(len(renewEncoded))
	renewMapped, err := mapHelperRenewSuccessToV2(renew, renewHeader, renewBody)
	if err != nil || renewMapped.ReplacementActiveProofID() != "replacement-proof" {
		t.Fatalf("mapHelperRenewSuccessToV2() = %#v, %v", renewMapped, err)
	}
}

func encodeHelperResponseDatagram(t *testing.T, sequence uint64, requestID [16]byte, identity, nonce [32]byte, body credentialprotocol.HelperResponseBody) []byte {
	t.Helper()
	encoded, err := credentialprotocol.EncodeHelperResponseBody(body)
	if err != nil {
		t.Fatal(err)
	}
	header := testHelperHeader(credentialprotocol.PacketTypeResponse, sequence, requestID, identity, nonce, uint32(len(encoded)))
	encodedHeader, err := credentialprotocol.EncodeHelperPacketHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	datagram := make([]byte, len(encodedHeader)+len(encoded))
	copy(datagram, encodedHeader[:])
	copy(datagram[len(encodedHeader):], encoded)
	return datagram
}

func TestL8D7GuestHelperPrepareFileMismatchesFailClosed(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare, payload, fileDigest := testFileBearingDispatchPrepareRequest(t, identity)
	digest := identityDigestForSession(t, testCredentialPacketSessionIdentity(t, identity.sessionID))
	wrongDigest := sha256.Sum256([]byte("wrong-file-payload"))
	wrongPayload := []byte("secret!!")
	wrongPayloadDigest := sha256.Sum256(wrongPayload)

	cases := []struct {
		name   string
		packet ControllerPacket
	}{
		{
			name: "digest",
			packet: testControllerPrivateFilePacket(2, identity, prepare, digest, 1, payload, wrongDigest, &testHelperBody{
				length: uint32(len(payload)), digest: wrongDigest, payload: append([]byte(nil), payload...),
			}),
		},
		{
			name:   "index",
			packet: testControllerPrivateFilePacket(2, identity, prepare, digest, 0, payload, fileDigest, testControllerPrepareFileBody(payload, fileDigest)),
		},
		{
			name:   "mode",
			packet: testControllerPrivateFilePacket(2, identity, prepare, digest, 0, payload, fileDigest, testControllerPrepareFileBody(payload, fileDigest)),
		},
		{
			name:   "length",
			packet: testControllerPrivateFilePacket(2, identity, prepare, digest, 1, wrongPayload, wrongPayloadDigest, testControllerPrepareFileBody(wrongPayload, wrongPayloadDigest)),
		},
		{
			name: "exec-private",
			packet: ControllerPacket{
				sequence:  2,
				sessionID: identity.sessionID,
				arm: controllerPacketArm{kind: controllerPacketArmPrivate, private: controllerPrivateRecord{
					kind: credentialprotocol.PrivateRecordKindOpaqueExecBinding, requestID: prepare.RequestID(),
					identityDigest: digest, chunkIndex: 0, chunkCount: 1, payloadLength: uint32(len(payload)), payloadSHA256: fileDigest,
				}},
				body: testControllerPrepareFileBody(payload, fileDigest),
			},
		},
		{
			name: "exec-stream",
			packet: ControllerPacket{
				sequence:  2,
				sessionID: identity.sessionID,
				arm:       controllerPacketArm{kind: controllerPacketArmStream},
				body:      testControllerPrepareFileBody(payload, fileDigest),
			},
		},
		{
			name: "second-prepare",
			packet: ControllerPacket{
				sequence:  2,
				sessionID: identity.sessionID,
				arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			stream := newFakeHelperStream()
			owner := &fakeHelperOwner{stream: stream}
			var sends atomic.Uint32
			var receives atomic.Uint32
			transport := &dispatchRedTransport{identity: identity}
			transport.receiveController = func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
				count := receives.Add(1)
				if count == 1 {
					return ControllerPacket{
						sequence:  1,
						sessionID: identity.sessionID,
						arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
					}, nil
				}
				return test.packet, nil
			}
			transport.sendController = func(context.Context, ControllerSendPacket) error {
				sends.Add(1)
				return errors.New("mismatched prepare-file must not mint proofs or answer the controller")
			}
			err := newDispatchRedClientOpts(t, transport, owner).Serve(context.Background())
			if !errors.Is(err, ErrClientControlDependencyUnaccepted) {
				t.Fatalf("Serve() error = %v, want prepare-file mismatch unaccepted", err)
			}
			if sends.Load() != 0 {
				t.Fatalf("controller sends = %d, want 0", sends.Load())
			}
			if receives.Load() != 2 {
				t.Fatalf("controller receives = %d, want prepare plus one payload attempt", receives.Load())
			}
			assertHelperPacketTypes(t, stream, credentialprotocol.PacketTypePrepareBegin)
		})
	}
}

func TestL8D7GuestHelperPrepareFileAggregateBound(t *testing.T) {
	exact := make([]credentialprotocol.HelperBindingManifestRecord, 16)
	for index := range exact {
		exact[index] = credentialprotocol.HelperBindingManifestRecord{
			BindingID:         "file",
			Mode:              credentialprotocol.DeliveryModeFileTmpfs,
			TargetPath:        "credentials/config",
			DeclaredFileBytes: credentialprotocol.MaxHelperFileBytes,
			FileSHA256:        sha256.Sum256([]byte{byte(index)}),
		}
	}
	indexes, aggregate, err := helperOrderedFileTmpfsIndexes(exact)
	if err != nil || len(indexes) != 16 || aggregate != credentialprotocol.MaxHelperFileAggregateBytes {
		t.Fatalf("exact aggregate = %d indexes %d err %v", aggregate, len(indexes), err)
	}
	over := append(append([]credentialprotocol.HelperBindingManifestRecord{}, exact...), credentialprotocol.HelperBindingManifestRecord{
		BindingID: "file-over", Mode: credentialprotocol.DeliveryModeFileTmpfs, TargetPath: "over",
		DeclaredFileBytes: 1, FileSHA256: sha256.Sum256([]byte("over")),
	})
	if _, _, err := helperOrderedFileTmpfsIndexes(over); !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("aggregate overflow error = %v, want unaccepted", err)
	}
}

func matchingFileBearingPrepareHelperResponse(t *testing.T, prepare v2control.CredentialPrepareRequest) credentialprotocol.HelperResponseBody {
	t.Helper()
	return credentialprotocol.HelperResponseBody{
		RequestType: credentialprotocol.PacketTypePrepareCommit,
		Disposition: credentialprotocol.ResponseDispositionAccepted,
		Revision:    prepare.Revision(),
		FailureCode: credentialprotocol.FailureCodeNone,
		Prepare: &credentialprotocol.HelperPrepareResponseResult{
			ExpiresAtUnixNano: prepare.ExpiresAtUnixNano(),
			ActiveProofID:     "active-proof",
			ExecBindingID:     "exec-binding",
			BindingProofs: []credentialprotocol.HelperBindingProof{
				{BindingID: "binding-http", Mode: credentialprotocol.DeliveryModeHTTPProxy, ProofID: "proof-http"},
				{BindingID: "binding-file", Mode: credentialprotocol.DeliveryModeFileTmpfs, ProofID: "proof-file"},
			},
		},
	}
}

func testMatchingFilePayload() ([]byte, [32]byte) {
	payload := []byte("secret!")
	return payload, sha256.Sum256(payload)
}

func testFileBearingDispatchPrepareRequest(t *testing.T, identity transportIdentity) (v2control.CredentialPrepareRequest, []byte, [32]byte) {
	t.Helper()
	payload, digest := testMatchingFilePayload()
	sessionIdentity := testCredentialPacketSessionIdentity(t, identity.sessionID)
	httpBinding, err := v2control.NewHTTPBindingManifest("binding-http", "azure-openai-responses-v1")
	if err != nil {
		t.Fatal(err)
	}
	fileBinding, err := v2control.NewFileBindingManifest("binding-file", "credentials/config", uint32(len(payload)), hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	prepare, err := v2control.NewCredentialPrepareRequest(
		testPacketRequestID(t), sessionIdentity, 1, 1700000001123456789,
		[]v2control.BindingManifest{httpBinding, fileBinding}, 1, uint64(len(payload)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return prepare, payload, digest
}

func testControllerPrepareFileBody(payload []byte, digest [32]byte) *testHelperBody {
	return &testHelperBody{length: uint32(len(payload)), digest: digest, payload: append([]byte(nil), payload...)}
}

func testControllerPrivateFilePacket(
	sequence uint64,
	identity transportIdentity,
	prepare v2control.CredentialPrepareRequest,
	digest v2control.IdentityDigest,
	bindingIndex uint16,
	payload []byte,
	fileDigest [32]byte,
	body *testHelperBody,
) ControllerPacket {
	return ControllerPacket{
		sequence:  sequence,
		sessionID: identity.sessionID,
		arm: controllerPacketArm{kind: controllerPacketArmPrivate, private: controllerPrivateRecord{
			kind:           credentialprotocol.PrivateRecordKindFileBytes,
			requestID:      prepare.RequestID(),
			identityDigest: digest,
			bindingIndex:   bindingIndex,
			chunkIndex:     0,
			chunkCount:     1,
			payloadLength:  uint32(len(payload)),
			payloadSHA256:  fileDigest,
		}},
		body: body,
	}
}

func matchingHTTPPrepareHelperResponse(t *testing.T, prepare v2control.CredentialPrepareRequest) credentialprotocol.HelperResponseBody {
	t.Helper()
	return credentialprotocol.HelperResponseBody{
		RequestType: credentialprotocol.PacketTypePrepareCommit,
		Disposition: credentialprotocol.ResponseDispositionAccepted,
		Revision:    prepare.Revision(),
		FailureCode: credentialprotocol.FailureCodeNone,
		Prepare: &credentialprotocol.HelperPrepareResponseResult{
			ExpiresAtUnixNano: prepare.ExpiresAtUnixNano(),
			ActiveProofID:     "active-proof",
			ExecBindingID:     "exec-binding",
			BindingProofs: []credentialprotocol.HelperBindingProof{
				{BindingID: "binding-http", Mode: credentialprotocol.DeliveryModeHTTPProxy, ProofID: "proof-http"},
			},
		},
	}
}

func matchingSSHPrepareHelperResponse(t *testing.T, prepare v2control.CredentialPrepareRequest) credentialprotocol.HelperResponseBody {
	t.Helper()
	return credentialprotocol.HelperResponseBody{
		RequestType: credentialprotocol.PacketTypePrepareCommit,
		Disposition: credentialprotocol.ResponseDispositionAccepted,
		Revision:    prepare.Revision(),
		FailureCode: credentialprotocol.FailureCodeNone,
		Prepare: &credentialprotocol.HelperPrepareResponseResult{
			ExpiresAtUnixNano: prepare.ExpiresAtUnixNano(),
			ActiveProofID:     "active-proof",
			ExecBindingID:     "exec-binding",
			BindingProofs: []credentialprotocol.HelperBindingProof{
				{BindingID: "binding-ssh", Mode: credentialprotocol.DeliveryModeSSHAgent, ProofID: "proof-ssh"},
			},
		},
	}
}

func mutateHTTPPrepareHelperResponse(t *testing.T, prepare v2control.CredentialPrepareRequest, mutate func(*credentialprotocol.HelperPrepareResponseResult)) credentialprotocol.HelperResponseBody {
	t.Helper()
	body := matchingHTTPPrepareHelperResponse(t, prepare)
	cloned := *body.Prepare
	cloned.BindingProofs = append([]credentialprotocol.HelperBindingProof(nil), body.Prepare.BindingProofs...)
	mutate(&cloned)
	body.Prepare = &cloned
	return body
}

func testPacketRequestIDSeed(t *testing.T, seed byte) v2control.RequestID {
	t.Helper()
	var raw [16]byte
	for index := range raw {
		raw[index] = byte(index + 1)
	}
	raw[0] = seed
	requestID, err := v2control.NewRequestID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return requestID
}

func testSSHOnlyDispatchSessionIdentity(t *testing.T, identity transportIdentity) v2control.GuestCredentialSessionIdentity {
	t.Helper()
	root := testCredentialPacketRoot(identity.sessionID)
	root.BindingIDs = []string{"binding-ssh"}
	root.DeliveryModes = []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeSSHAgent}
	root.NetworkPlanID = ""
	root.PolicySnapshotID = ""
	root.ProxySessionID = ""
	root.ProxyGenerationID = ""
	root.TopologyGenerationID = ""
	root.RuleGenerationID = ""
	sessionIdentity, err := v2control.GuestCredentialSessionIdentityFromRoot(identity.sessionID, root)
	if err != nil {
		t.Fatal(err)
	}
	return sessionIdentity
}

func testSSHOnlyDispatchPrepareRequest(t *testing.T, identity transportIdentity) v2control.CredentialPrepareRequest {
	t.Helper()
	sessionIdentity := testSSHOnlyDispatchSessionIdentity(t, identity)
	binding, err := v2control.NewSSHBindingManifest("binding-ssh", "ssh-policy-1", 1)
	if err != nil {
		t.Fatal(err)
	}
	prepare, err := v2control.NewCredentialPrepareRequest(testPacketRequestID(t), sessionIdentity, 1, 1700000001123456789, []v2control.BindingManifest{binding}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return prepare
}

func testHTTPOnlyPrivateExecRequest(t *testing.T, requestID v2control.RequestID, identity v2control.GuestCredentialSessionIdentity) v2control.CredentialExecRequest {
	t.Helper()
	const proxyURL = "http://proxy-runtime/.well-known/hal/credential-http/v1/azure-openai-responses-v1/deployments/model-1"
	correlation, err := v2control.NewCredentialExecCorrelation(identity, 1, "exec-binding", true, proxyURL, 1, 321, strings.Repeat("a", 64), 1700000000000, 1700001800000, 1700001900000)
	if err != nil {
		t.Fatal(err)
	}
	env := []v2control.ExecEnvironment{mustPacketExecEnvironment(t, "MODE", v2control.ExecEnvironmentLiteral, "batch")}
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		env = append(env, mustPacketExecEnvironment(t, name, v2control.ExecEnvironmentGenerated, proxyURL))
	}
	timing, err := v2control.NewExecTiming(v2control.ExecTimingTimeoutMillis, 30000)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := v2control.NewExecPlan([]string{"/usr/bin/tool", "run"}, env, "/workspace", 1024, 2048, 4096, timing)
	if err != nil {
		t.Fatal(err)
	}
	request, err := v2control.NewCredentialExecRequest(requestID, correlation, plan)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func testSSHOnlyDispatchExecRequest(t *testing.T, requestID v2control.RequestID, identity v2control.GuestCredentialSessionIdentity) v2control.CredentialExecRequest {
	t.Helper()
	empty := sha256.Sum256(nil)
	correlation, err := v2control.NewCredentialExecCorrelation(
		identity, 1, "exec-binding", false, "", 0, 0, hex.EncodeToString(empty[:]),
		1700000000000, 1700001800000, 1700001900000,
	)
	if err != nil {
		t.Fatal(err)
	}
	env := []v2control.ExecEnvironment{mustPacketExecEnvironment(t, "MODE", v2control.ExecEnvironmentLiteral, "batch")}
	timing, err := v2control.NewExecTiming(v2control.ExecTimingTimeoutMillis, 30000)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := v2control.NewExecPlan([]string{"/usr/bin/tool", "run"}, env, "/workspace", 1024, 2048, 4096, timing)
	if err != nil {
		t.Fatal(err)
	}
	request, err := v2control.NewCredentialExecRequest(requestID, correlation, plan)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func blockingControllerAfter(t *testing.T, packets []ControllerPacket, closed <-chan struct{}) func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
	t.Helper()
	var count atomic.Uint32
	return func(ctx context.Context, receive ControllerReceiveRequest) (ControllerPacket, error) {
		index := int(count.Add(1))
		if index <= len(packets) {
			return packets[index-1], nil
		}
		select {
		case <-closed:
			return ControllerPacket{}, errors.New("closed")
		case <-ctx.Done():
			return ControllerPacket{}, ctx.Err()
		}
	}
}

func waitForControllerSends(t *testing.T, sends *atomic.Uint32, want uint32, serveDone <-chan error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sends.Load() >= want {
			return
		}
		select {
		case err := <-serveDone:
			t.Fatalf("Serve returned before %d controller sends: %v", want, err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatalf("controller sends = %d, want %d", sends.Load(), want)
}

func waitForHelperPacketCount(t *testing.T, stream *fakeHelperStream, want int, serveDone <-chan error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(decodeHelperDatagrams(t, stream.bytes())) >= want {
			return
		}
		select {
		case err := <-serveDone:
			t.Fatalf("Serve returned before %d helper packets: %v", want, err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatalf("helper packets = %d, want %d", len(decodeHelperDatagrams(t, stream.bytes())), want)
}

func assertHelperPacketTypes(t *testing.T, stream *fakeHelperStream, want ...credentialprotocol.PacketType) {
	t.Helper()
	packets := decodeHelperDatagrams(t, stream.bytes())
	if len(packets) != len(want) {
		t.Fatalf("helper packets = %d, want %d (%v)", len(packets), len(want), want)
	}
	for index, packet := range packets {
		if packet.header.Type != want[index] {
			t.Fatalf("helper packet %d type = %s, want %s", index, packet.header.Type, want[index])
		}
	}
}
