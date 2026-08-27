//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"reflect"
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

func TestL8RuntimeOwnerSeqpacketRejectsMultipleRightsMessagesWithoutLeakingDescriptors(t *testing.T) {
	first, err := unix.Dup(0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := unix.Dup(0)
	if err != nil {
		_ = unix.Close(first)
		t.Fatal(err)
	}
	oob := append(unix.UnixRights(first), unix.UnixRights(second)...)
	if files, err := l8RuntimeOwnerFilesFromControl(oob); !errors.Is(err, errL8RuntimeOwnerProtocol) || len(files) != 0 {
		t.Fatalf("multiple rights = %v, %v", files, err)
	}
	for _, fd := range []int{first, second} {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			t.Fatalf("received fd %d remains open: %v", fd, err)
		}
	}
}

func TestL8RuntimeOwnerBootstrapPublishesOnlyAfterArmedChildRevisionOne(t *testing.T) {
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
	genesis := l8RuntimeOwnerTestGenesis(l8RuntimeOwnerTestRecord(t, l8RuntimeOwnerTestSeed(), "01234567-89ab-cdef-0123-456789abcdef"))
	store := &l8RuntimeOwnerTestStore{}
	var events []string
	owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{
		Store: store, GenesisRecord: genesis, ExpectedUID: uint32(os.Geteuid()), CommitKey: make([]byte, 32),
		StartChild: func() (l8RuntimeOwnerStartedChild, error) {
			events = append(events, "armed")
			return l8RuntimeOwnerStartedChild{
				Observation: l8RuntimeOwnerProcessObservation{PID: 5001, ParentPID: genesis.SupervisorPID, StartTime: 7001, state: 'S', pidfd: 10, pidfdOwned: true},
				Release: func() error {
					events = append(events, "release")
					if store.record.Revision != 1 || store.record.State != "starting" {
						t.Fatalf("released before revision one: %#v", store.record)
					}
					return nil
				},
				Abort: func() error { events = append(events, "abort"); return nil },
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := owner.HandleBootstrap(context.Background(), uint32(os.Geteuid()), l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeBootstrapStart, Body: encodeL8RuntimeOwnerNamespaceCorrelation(correlation)}, Files: []*os.File{user, network}})
	if err != nil || result.Packet.Opcode != l8RuntimeOwnerOpcodeBootstrapPublished || store.record.Revision != 2 || store.record.State != "running" || store.record.ControllerState != "unclaimed" || !reflect.DeepEqual(events, []string{"armed", "release"}) {
		t.Fatalf("bootstrap = %#v record %#v events %v err %v", result, store.record, events, err)
	}
}

func TestL8RuntimeOwnerBootstrapFailureAbortsAndNeverAcknowledgesPublication(t *testing.T) {
	for _, scenario := range []struct {
		name          string
		releaseErr    bool
		transitionErr bool
	}{
		{name: "release failure", releaseErr: true}, {name: "revision one durability", transitionErr: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			genesis := l8RuntimeOwnerTestGenesis(l8RuntimeOwnerTestRecord(t, l8RuntimeOwnerTestSeed(), "01234567-89ab-cdef-0123-456789abcdef"))
			store := &l8RuntimeOwnerFailingTransitionStore{l8RuntimeOwnerTestStore: l8RuntimeOwnerTestStore{}, failTransition: scenario.transitionErr}
			aborts := 0
			owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{Store: store, GenesisRecord: genesis, ExpectedUID: 1000, CommitKey: make([]byte, 32), StartChild: func() (l8RuntimeOwnerStartedChild, error) {
				return l8RuntimeOwnerStartedChild{Observation: l8RuntimeOwnerProcessObservation{PID: 5, ParentPID: genesis.SupervisorPID, StartTime: 7, state: 'S', pidfd: 9, pidfdOwned: true}, Release: func() error {
					if scenario.releaseErr {
						return errors.New("private release")
					}
					return nil
				}, Abort: func() error { aborts++; return nil }}, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			result, err := owner.HandleBootstrap(context.Background(), 1000, l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeBootstrapStart, Body: make([]byte, 32)}, Files: make([]*os.File, 2)})
			if !errors.Is(err, errL8RuntimeOwnerInvalid) || result.Packet.Opcode == l8RuntimeOwnerOpcodeBootstrapPublished || aborts != 1 {
				t.Fatalf("bootstrap failure = %#v, %v aborts %d", result, err, aborts)
			}
		})
	}
}

type l8RuntimeOwnerFailingTransitionStore struct {
	l8RuntimeOwnerTestStore
	failTransition bool
}

func (store *l8RuntimeOwnerFailingTransitionStore) Transition(ctx context.Context, expected uint64, next firecrackerRuntimeOwnerRecordV1) (firecrackerRuntimeOwnerRecordV1, error) {
	if store.failTransition {
		return firecrackerRuntimeOwnerRecordV1{}, errors.New("private durable path")
	}
	return store.l8RuntimeOwnerTestStore.Transition(ctx, expected, next)
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
