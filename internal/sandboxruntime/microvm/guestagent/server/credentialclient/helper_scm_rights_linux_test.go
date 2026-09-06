//go:build linux

package credentialclient

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/v2control"
)

func TestL8D7GuestHelperSCMRightsReceiveTransfersFD(t *testing.T) {
	clientConn, peerConn := testHelperSeqpacketPair(t)
	rightClient, rightPeer := testHelperStreamPair(t)
	identity := testDispatchTransportIdentity()
	prepare := testSSHOnlyDispatchPrepareRequest(t, identity)
	digest := identityDigestForSession(t, testSSHOnlyDispatchSessionIdentity(t, identity))
	capabilityDigest := sha256.Sum256([]byte("relay-capability"))
	requestID := [16]byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 9, 8, 7, 6, 5, 4, 3}
	datagram := encodeHelperSSHAcceptedDatagram(t, 1, requestID, digest.Bytes(), identity.identity.GuestBootNonce, 1, 0, 1, capabilityDigest)

	rawRight, err := rightClient.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	rightFD := -1
	if controlErr := rawRight.Control(func(fd uintptr) { rightFD = int(fd) }); controlErr != nil || rightFD < 0 {
		t.Fatalf("right fd control = %d, %v", rightFD, controlErr)
	}
	if err := sendHelperSSHAccepted(peerConn, datagram, rightFD); err != nil {
		t.Fatalf("Sendmsg SCM_RIGHTS = %v", err)
	}
	if err := rightClient.Close(); err != nil {
		t.Fatal(err)
	}

	request, err := newHelperControlReceiveRequest(1, credentialprotocol.HelperSSHAcceptedFDBodyEncodedLength(), 1, [16]byte{}, false, digest.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	packet, received, readErr := tryReadHelperSSHAcceptedPacket(context.Background(), clientConn, request)
	if readErr != nil || !received {
		t.Fatalf("tryReadHelperSSHAcceptedPacket() = %#v, %v, %v", packet, received, readErr)
	}
	accepted, ok := packet.sshAcceptedValue()
	if !ok || accepted.Revision() != 1 || accepted.BindingIndex() != 0 || accepted.Ordinal() != 1 || accepted.CapabilitySHA256() != capabilityDigest {
		t.Fatalf("accepted metadata = %#v", accepted)
	}
	if accepted.Connection().SHA256() != capabilityDigest {
		t.Fatal("received capability digest did not match the authenticated body")
	}

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
	session := &recordingSSHSession{handledCh: make(chan struct{})}
	client := newDispatchRedClientWithSSHSession(t, &dispatchRedTransport{identity: identity}, nil, session)
	if err := client.dispatchHelperSSHAccepted(context.Background(), packet, digest, ledger); err != nil {
		t.Fatalf("dispatchHelperSSHAccepted() error = %v", err)
	}
	transferred := session.acceptedPacket(t)
	if err := transferred.WaitTransferred(context.Background()); err != nil {
		t.Fatalf("WaitTransferred() error = %v", err)
	}
	payload := []byte("ssh-agent-ping")
	if _, err := rightPeer.Write(payload); err != nil {
		t.Fatal(err)
	}
	n, err := transferred.Connection().Read(context.Background(), sshTestSink{capacity: credentialprotocol.SSHAgentMaxFrameBytes})
	if err != nil || n.ByteCount() != uint64(len(payload)) || n.EOF() || n.Truncated() {
		t.Fatalf("transferred Read() = %#v, %v", n, err)
	}
}

func TestL8D7GuestHelperSCMRightsMissingRightFailsClosed(t *testing.T) {
	clientConn, peerConn := testHelperSeqpacketPair(t)
	identity := testDispatchTransportIdentity()
	digest := identityDigestForSession(t, testSSHOnlyDispatchSessionIdentity(t, identity))
	capabilityDigest := sha256.Sum256([]byte("relay-capability"))
	datagram := encodeHelperSSHAcceptedDatagram(t, 1, [16]byte{9}, digest.Bytes(), identity.identity.GuestBootNonce, 1, 0, 1, capabilityDigest)
	if _, err := peerConn.Write(datagram); err != nil {
		t.Fatal(err)
	}
	request, err := newHelperControlReceiveRequest(1, credentialprotocol.HelperSSHAcceptedFDBodyEncodedLength(), 1, [16]byte{}, false, digest.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	_, received, readErr := tryReadHelperSSHAcceptedPacket(context.Background(), clientConn, request)
	if received || readErr == nil {
		t.Fatalf("missing-right SSH receive = %v, %v, want fail-closed", received, readErr)
	}
}

func TestL8D7GuestHelperSCMRightsServeDispatchesBeforeNextHelperIO(t *testing.T) {
	clientConn, peerConn := testHelperSeqpacketPair(t)
	go drainHelperPeerReads(peerConn)

	rightClient, rightPeer := testHelperStreamPair(t)
	defer rightPeer.Close()
	identity := testDispatchTransportIdentity()
	prepare := testSSHOnlyDispatchPrepareRequest(t, identity)
	sessionIdentity := testSSHOnlyDispatchSessionIdentity(t, identity)
	digest := identityDigestForSession(t, sessionIdentity)
	revokeID := testPacketRequestIDSeed(t, 0x61)
	revoke, err := v2control.NewCredentialRevokeRequest(revokeID, sessionIdentity, 1, v2control.CredentialRevokeReasonRequested)
	if err != nil {
		t.Fatal(err)
	}
	nonce := identity.identity.GuestBootNonce
	if _, err := peerConn.Write(encodeHelperResponseDatagram(t, 1, prepare.RequestID().Bytes(), digest.Bytes(), nonce, matchingSSHPrepareHelperResponse(t, prepare))); err != nil {
		t.Fatal(err)
	}

	allowSecond := make(chan struct{})
	closed := make(chan struct{})
	var sends atomic.Uint32
	var receives atomic.Uint32
	session := &recordingSSHSession{handledCh: make(chan struct{})}
	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = func(ctx context.Context, _ ControllerReceiveRequest) (ControllerPacket, error) {
		switch receives.Add(1) {
		case 1:
			return ControllerPacket{sequence: 1, sessionID: identity.sessionID, arm: controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare}}, nil
		case 2:
			select {
			case <-allowSecond:
				return ControllerPacket{sequence: 2, sessionID: identity.sessionID, arm: controllerPacketArm{kind: controllerPacketArmRevoke, revoke: revoke}}, nil
			case <-closed:
				return ControllerPacket{}, errors.New("closed")
			case <-ctx.Done():
				return ControllerPacket{}, ctx.Err()
			}
		default:
			select {
			case <-closed:
				return ControllerPacket{}, errors.New("closed")
			case <-ctx.Done():
				return ControllerPacket{}, ctx.Err()
			}
		}
	}
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

	owner, err := newPreopenedHelperConnectionOwner(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	client := newDispatchRedClientWithSSHSession(t, transport, owner, session)
	serveDone := make(chan error, 1)
	go func() { serveDone <- client.Serve(context.Background()) }()
	waitForControllerSends(t, &sends, 1, serveDone)

	capabilityDigest := sha256.Sum256([]byte("relay-capability"))
	rawRight, err := rightClient.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	rightFD := -1
	if controlErr := rawRight.Control(func(fd uintptr) { rightFD = int(fd) }); controlErr != nil || rightFD < 0 {
		t.Fatalf("right fd control = %d, %v", rightFD, controlErr)
	}
	datagram := encodeHelperSSHAcceptedDatagram(t, 2, [16]byte{9}, digest.Bytes(), nonce, 1, 0, 1, capabilityDigest)
	if err := sendHelperSSHAccepted(peerConn, datagram, rightFD); err != nil {
		t.Fatalf("Sendmsg SCM_RIGHTS = %v", err)
	}
	if err := rightClient.Close(); err != nil {
		t.Fatal(err)
	}
	close(allowSecond)

	select {
	case <-session.handledCh:
	case err := <-serveDone:
		t.Fatalf("Serve returned before SSH dispatch: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("SSH accepted FD was not dispatched")
	}
	if err := session.acceptedPacket(t).WaitTransferred(context.Background()); err != nil {
		t.Fatalf("WaitTransferred() error = %v", err)
	}
	if _, err := peerConn.Write(encodeHelperResponseDatagram(t, 3, revoke.RequestID().Bytes(), digest.Bytes(), nonce, credentialprotocol.HelperResponseBody{
		RequestType: credentialprotocol.PacketTypeRevoke,
		Disposition: credentialprotocol.ResponseDispositionCleanupComplete,
		Revision:    1,
		FailureCode: credentialprotocol.FailureCodeNone,
		Revoke:      &credentialprotocol.HelperRevokeResponseResult{CleanupProofID: "cleanup-proof", AuthorityAbsent: true, ResourcesAbsent: true},
	})); err != nil {
		t.Fatal(err)
	}
	waitForControllerSends(t, &sends, 2, serveDone)
	if err := client.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve() after SCM_RIGHTS SSH = %v", err)
	}
}

func TestL8D7GuestHelperSCMRightsNoExtensionFailsClosed(t *testing.T) {
	clientConn, peerConn := testHelperSeqpacketPair(t)
	go drainHelperPeerReads(peerConn)
	rightClient, rightPeer := testHelperStreamPair(t)
	defer rightPeer.Close()
	identity := testDispatchTransportIdentity()
	prepare := testSSHOnlyDispatchPrepareRequest(t, identity)
	sessionIdentity := testSSHOnlyDispatchSessionIdentity(t, identity)
	digest := identityDigestForSession(t, sessionIdentity)
	nonce := identity.identity.GuestBootNonce
	if _, err := peerConn.Write(encodeHelperResponseDatagram(t, 1, prepare.RequestID().Bytes(), digest.Bytes(), nonce, matchingSSHPrepareHelperResponse(t, prepare))); err != nil {
		t.Fatal(err)
	}

	allowSecond := make(chan struct{})
	closed := make(chan struct{})
	var sends atomic.Uint32
	var receives atomic.Uint32
	revokeID := testPacketRequestIDSeed(t, 0x62)
	revoke, err := v2control.NewCredentialRevokeRequest(revokeID, sessionIdentity, 1, v2control.CredentialRevokeReasonRequested)
	if err != nil {
		t.Fatal(err)
	}
	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = func(ctx context.Context, _ ControllerReceiveRequest) (ControllerPacket, error) {
		switch receives.Add(1) {
		case 1:
			return ControllerPacket{sequence: 1, sessionID: identity.sessionID, arm: controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare}}, nil
		case 2:
			select {
			case <-allowSecond:
				return ControllerPacket{sequence: 2, sessionID: identity.sessionID, arm: controllerPacketArm{kind: controllerPacketArmRevoke, revoke: revoke}}, nil
			case <-closed:
				return ControllerPacket{}, errors.New("closed")
			case <-ctx.Done():
				return ControllerPacket{}, ctx.Err()
			}
		default:
			select {
			case <-closed:
				return ControllerPacket{}, errors.New("closed")
			case <-ctx.Done():
				return ControllerPacket{}, ctx.Err()
			}
		}
	}
	transport.sendController = func(_ context.Context, packet ControllerSendPacket) error {
		if _, ok := packet.revokeResponseValue(); ok {
			sends.Add(1)
			return errors.New("SSH without extension must not continue into revoke success")
		}
		if _, ok := packet.prepareResponseValue(); ok {
			sends.Add(1)
		}
		return nil
	}
	transport.close = func(context.Context) error {
		transport.closeOnce.Do(func() { close(closed) })
		return nil
	}
	owner, err := newPreopenedHelperConnectionOwner(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- newDispatchRedClientOpts(t, transport, owner).Serve(context.Background()) }()
	waitForControllerSends(t, &sends, 1, serveDone)

	capabilityDigest := sha256.Sum256([]byte("relay-capability"))
	rawRight, err := rightClient.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	rightFD := -1
	if controlErr := rawRight.Control(func(fd uintptr) { rightFD = int(fd) }); controlErr != nil || rightFD < 0 {
		t.Fatalf("right fd control = %d, %v", rightFD, controlErr)
	}
	datagram := encodeHelperSSHAcceptedDatagram(t, 2, [16]byte{9}, digest.Bytes(), nonce, 1, 0, 1, capabilityDigest)
	if err := sendHelperSSHAccepted(peerConn, datagram, rightFD); err != nil {
		t.Fatal(err)
	}
	_ = rightClient.Close()
	close(allowSecond)
	err = <-serveDone
	if !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("Serve() error = %v, want SSH without extension unaccepted", err)
	}
	if sends.Load() != 1 {
		t.Fatalf("controller sends = %d, want prepare success only", sends.Load())
	}
}

func encodeHelperSSHAcceptedDatagram(t *testing.T, sequence uint64, requestID [16]byte, identity, nonce [32]byte, revision uint64, bindingIndex uint16, ordinal uint8, digest [32]byte) []byte {
	t.Helper()
	body := make([]byte, credentialprotocol.HelperSSHAcceptedFDBodyEncodedLength())
	if err := credentialprotocol.EncodeHelperSSHAcceptedFDBodyTo(body, revision, bindingIndex, ordinal, digest); err != nil {
		t.Fatal(err)
	}
	header := testHelperHeader(credentialprotocol.PacketTypeSSHAcceptedFD, sequence, requestID, identity, nonce, uint32(len(body)))
	encodedHeader, err := credentialprotocol.EncodeHelperPacketHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	datagram := make([]byte, len(encodedHeader)+len(body))
	copy(datagram, encodedHeader[:])
	copy(datagram[len(encodedHeader):], body)
	return datagram
}

func sendHelperSSHAccepted(peer *net.UnixConn, datagram []byte, rightFD int) error {
	oob := unix.UnixRights(rightFD)
	n, oobn, err := peer.WriteMsgUnix(datagram, oob, nil)
	if err != nil || n != len(datagram) || oobn != len(oob) {
		return errInvalidHelperPacket
	}
	return nil
}

func drainHelperPeerReads(peer *net.UnixConn) {
	buf := make([]byte, credentialprotocol.MaxHelperPacketDatagramBytes)
	for {
		if _, err := peer.Read(buf); err != nil {
			return
		}
	}
}

func testHelperStreamPair(t *testing.T) (client, peer *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	client = unixConnFromHelperFD(t, fds[0])
	peer = unixConnFromHelperFD(t, fds[1])
	t.Cleanup(func() {
		_ = client.Close()
		_ = peer.Close()
	})
	return client, peer
}
