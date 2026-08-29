//go:build linux

package credentialclient

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestL8D7GuestHelperPreopenedOwnerRevalidatesSeqpacketSocketpair(t *testing.T) {
	clientConn, peerConn := testHelperSeqpacketPair(t)
	raw, err := clientConn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	sockType := 0
	if controlErr := raw.Control(func(fd uintptr) {
		sockType, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
	}); controlErr != nil || err != nil || sockType != unix.SOCK_SEQPACKET {
		t.Fatalf("test socketpair type = %d, %v, %v", sockType, err, controlErr)
	}
	owner, err := newPreopenedHelperConnectionOwner(clientConn)
	if err != nil {
		t.Fatalf("newPreopenedHelperConnectionOwner() error = %v", err)
	}
	identity := testDispatchTransportIdentity()
	digest := identityDigestForSession(t, testCredentialPacketSessionIdentity(t, identity.sessionID))
	expectation, err := newHelperAcceptExpectation(identity.sessionID, digest.Bytes(), identity.helperGeneration, identity.identity.GuestBootNonce)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := owner.AcceptVerified(context.Background(), expectation)
	if err != nil {
		t.Fatalf("AcceptVerified() error = %v", err)
	}
	if stream != clientConn {
		t.Fatal("AcceptVerified did not return the same-object revalidated stream")
	}
	if _, err := owner.AcceptVerified(context.Background(), expectation); !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("second AcceptVerified() error = %v, want consume-once unaccepted", err)
	}

	begin := credentialprotocol.HelperPrepareBeginBody{
		Revision:       1,
		ExpiryUnixNano: 1700000001123456789,
		Bindings: []credentialprotocol.HelperBindingManifestRecord{
			{BindingID: "binding-http", Mode: credentialprotocol.DeliveryModeHTTPProxy},
		},
	}
	packet, err := newHelperPrepareBeginSendPacket(testHelperHeader(0, 1, testHelperPacketRequestID(), digest.Bytes(), identity.identity.GuestBootNonce, 0), begin)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeHelperSendPacket(context.Background(), stream, packet); err != nil {
		t.Fatalf("writeHelperSendPacket() error = %v", err)
	}
	buf := make([]byte, credentialprotocol.MaxHelperPacketDatagramBytes)
	n, err := peerConn.Read(buf)
	if err != nil {
		t.Fatalf("peer Read() error = %v", err)
	}
	header, err := credentialprotocol.ValidateHelperPacketDatagram(buf[:n])
	if err != nil || header.Type != credentialprotocol.PacketTypePrepareBegin {
		t.Fatalf("seqpacket datagram header = %#v, %v", header, err)
	}
	if err := owner.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestL8D7GuestHelperPreopenedOwnerRejectsNonConnStream(t *testing.T) {
	owner, err := newPreopenedHelperConnectionOwner(newFakeHelperStream())
	if err != nil {
		t.Fatalf("newPreopenedHelperConnectionOwner() error = %v", err)
	}
	identity := testDispatchTransportIdentity()
	expectation, err := newHelperAcceptExpectation(identity.sessionID, [32]byte{1}, identity.helperGeneration, identity.identity.GuestBootNonce)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.AcceptVerified(context.Background(), expectation); !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("AcceptVerified(fake stream) error = %v, want unaccepted", err)
	}
}

func testHelperSeqpacketPair(t *testing.T) (client, peer *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
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

func unixConnFromHelperFD(t *testing.T, fd int) *net.UnixConn {
	t.Helper()
	file := os.NewFile(uintptr(fd), "helper-seqpacket")
	if file == nil {
		t.Fatal("os.NewFile returned nil")
	}
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		t.Fatalf("FileConn type %T, want *net.UnixConn", conn)
	}
	return unixConn
}
