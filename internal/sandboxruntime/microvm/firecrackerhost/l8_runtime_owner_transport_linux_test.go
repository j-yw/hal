//go:build linux

package firecrackerhost

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestL8RuntimeOwnerSeqpacketTransfersExactlyCorrelatedNamespaces(t *testing.T) {
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sockets[0])
	defer unix.Close(sockets[1])
	user, err := os.Open("/proc/self/ns/user")
	if err != nil {
		t.Fatal(err)
	}
	defer user.Close()
	network, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	correlation := l8RuntimeOwnerTestNamespaceCorrelation(t, user, network)
	body := encodeL8RuntimeOwnerNamespaceCorrelation(correlation)
	if len(body) != 32 {
		t.Fatalf("namespace correlation body = %d bytes", len(body))
	}
	packet := l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeBootstrapStart, Body: body}
	if err := sendL8RuntimeOwnerSeqpacket(sockets[0], packet, []*os.File{user, network}); err != nil {
		t.Fatal(err)
	}
	received, err := receiveL8RuntimeOwnerSeqpacket(sockets[1])
	if err != nil {
		t.Fatal(err)
	}
	defer closeL8RuntimeOwnerTestFiles(received.Files)
	if received.Packet.Opcode != packet.Opcode || len(received.Files) != 2 {
		t.Fatalf("received = %#v, files %d", received.Packet, len(received.Files))
	}
	decoded, err := decodeL8RuntimeOwnerNamespaceCorrelation(received.Packet.Body)
	if err != nil || decoded != correlation {
		t.Fatalf("correlation = %#v, %v", decoded, err)
	}
	if err := validateL8RuntimeOwnerNamespaceFiles(received.Files, decoded); err != nil {
		t.Fatal(err)
	}
	for _, file := range received.Files {
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("received namespace CLOEXEC = %#x, %v", flags, err)
		}
	}
	uid, err := l8RuntimeOwnerPeerUID(sockets[1])
	if err != nil || uid != uint32(os.Geteuid()) {
		t.Fatalf("peer UID = %d, %v", uid, err)
	}
}

func TestL8RuntimeOwnerNamespaceTransferRejectsCountOrderKindAndCorrelation(t *testing.T) {
	user, err := os.Open("/proc/self/ns/user")
	if err != nil {
		t.Fatal(err)
	}
	defer user.Close()
	network, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	regular, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	correlation := l8RuntimeOwnerTestNamespaceCorrelation(t, user, network)
	for name, files := range map[string][]*os.File{
		"missing":       {user},
		"extra":         {user, network, regular},
		"reordered":     {network, user},
		"non namespace": {user, regular},
		"duplicate":     {user, user},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateL8RuntimeOwnerNamespaceFiles(files, correlation); !errors.Is(err, errL8RuntimeOwnerInvalid) {
				t.Fatalf("validation = %v", err)
			}
		})
	}
	mutated := correlation
	mutated.NetworkInode++
	if err := validateL8RuntimeOwnerNamespaceFiles([]*os.File{user, network}, mutated); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("mismatched correlation = %v", err)
	}
	for _, body := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		if _, err := decodeL8RuntimeOwnerNamespaceCorrelation(body); !errors.Is(err, errL8RuntimeOwnerProtocol) {
			t.Fatalf("correlation length %d = %v", len(body), err)
		}
	}
}

func l8RuntimeOwnerTestNamespaceCorrelation(t *testing.T, user, network *os.File) l8RuntimeOwnerNamespaceCorrelationV1 {
	t.Helper()
	var userStat, networkStat unix.Stat_t
	if unix.Fstat(int(user.Fd()), &userStat) != nil || unix.Fstat(int(network.Fd()), &networkStat) != nil {
		t.Fatal("stat namespace descriptors")
	}
	return l8RuntimeOwnerNamespaceCorrelationV1{
		UserDevice: uint64(userStat.Dev), UserInode: userStat.Ino,
		NetworkDevice: uint64(networkStat.Dev), NetworkInode: networkStat.Ino,
	}
}

func closeL8RuntimeOwnerTestFiles(files []*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}
