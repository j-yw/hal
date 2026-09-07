//go:build linux

package firecrackerhost

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// Actual eight-role byte admission and SCM_RIGHTS receipt, with the existing
// in-memory FSM store and fake child callbacks. No namespace is created or
// entered, and no process, root supervisor, live L7 or VM is started.
func TestMinimalControlNamespacesRejectBeforeBootstrapOwnership(t *testing.T) {
	for _, name := range []string{"user-device", "user-inode", "network-device", "network-inode", "user-is-mount", "network-is-mount", "missing-binding"} {
		t.Run(name, func(t *testing.T) {
			f := newMinimalControlAdmissionFixture(t)
			names := [2]string{"user", "net"}
			if name == "user-is-mount" {
				names[0] = "mnt"
			}
			if name == "network-is-mount" {
				names[1] = "mnt"
			}
			files, correlation := minimalNamespaceTestFiles(t, names)
			f.config.Control.Namespace = minimalControlNamespaces(correlation)
			switch name {
			case "user-device":
				f.config.Control.Namespace.UserDevice++
			case "user-inode":
				f.config.Control.Namespace.UserInode++
			case "network-device":
				f.config.Control.Namespace.NetworkDevice++
			case "network-inode":
				f.config.Control.Namespace.NetworkInode++
			}
			f.reseal(nil)
			requireMinimalControlFCFixtureValid(t, f)
			code := f.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
				owned := minimalNamespaceTestRuntime(t, admission)
				defer owned.closeNamespaces()
				if name != "missing-binding" && bindMinimalControlNamespaces(owned, admission) != nil {
					t.Fatal("independent admitted projection did not reach actual bootstrap receiver")
				}
				got := minimalNamespaceTestBootstrap(t, owned, files, correlation)
				if got.err == nil || got.starts != 0 || got.releases != 0 || got.events != 0 || owned.namespaces != ([2]*os.File{}) {
					t.Errorf("uncorrelated namespace reached bootstrap: error=%v starts=%d releases=%d store-events=%d transferred=%t", got.err, got.starts, got.releases, got.events, owned.namespaces != ([2]*os.File{}))
				}
				return nil
			})
			if code != 0 || f.admissions != 1 || f.legacy != 0 || len(f.closed) != 8 {
				t.Fatal("namespace regression did not execute inside real eight-role admission")
			}
		})
	}
}

func TestMinimalControlNamespacesMatchingAndSnapshotControls(t *testing.T) {
	for _, name := range []string{"matching", "decoded-config-mutation"} {
		t.Run(name, func(t *testing.T) {
			f := newMinimalControlAdmissionFixture(t)
			files, correlation := minimalNamespaceTestFiles(t, [2]string{"user", "net"})
			f.config.Control.Namespace = minimalControlNamespaces(correlation)
			f.reseal(nil)
			code := f.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
				owned := minimalNamespaceTestRuntime(t, admission)
				defer owned.closeNamespaces()
				if name == "decoded-config-mutation" {
					admission.config.Control.Namespace = minimalControlNamespaces{}
					admission.configDigest = [32]byte{}
				}
				if bindMinimalControlNamespaces(owned, admission) != nil {
					t.Fatal("admission-owned snapshot was replaced by mutable decoded config")
				}
				got := minimalNamespaceTestBootstrap(t, owned, files, correlation)
				if got.err != nil || got.starts != 1 || got.releases != 1 || got.events != 3 || got.revision != 2 || owned.namespaces[0] == nil || owned.namespaces[1] == nil {
					t.Fatalf("matching received namespaces did not reach unchanged FSM: %#v", got)
				}
				return nil
			})
			if code != 0 || f.admissions != 1 || f.legacy != 0 || len(f.closed) != 8 {
				t.Fatal("matching bootstrap changed outer admission ownership")
			}
		})
	}
}

func TestMinimalControlNamespacesLegacyReceiverRemainsUnchanged(t *testing.T) {
	for _, name := range []string{"six-role", "seven-role"} {
		t.Run(name, func(t *testing.T) {
			files, correlation := minimalNamespaceTestFiles(t, [2]string{"user", "net"})
			record, config := jailerRecoveryTestRecord(t)
			owned := &l8RuntimeOwnerLinuxRuntime{config: l8RuntimeOwnerSupervisorConfigV1{DaemonUID: uint32(os.Geteuid())}, genesis: record}
			if name == "seven-role" {
				owned.store = &l8RuntimeOwnerLinuxRecordStore{selected: &jailerRecoveryStore{config: config}}
			}
			defer owned.closeNamespaces()
			got := minimalNamespaceTestBootstrap(t, owned, files, correlation)
			if got.err != nil || got.starts != 1 || got.releases != 1 || got.events != 3 || got.revision != 2 {
				t.Fatalf("absent selected option changed legacy receiver: %#v", got)
			}
		})
	}
}

func minimalNamespaceTestRuntime(t *testing.T, admission *minimalControlSupervisorAdmission) *l8RuntimeOwnerLinuxRuntime {
	t.Helper()
	record, _ := jailerRecoveryTestRecord(t)
	j := admission.config.Job
	record.SeedCorrelationDigest = hex.EncodeToString(admission.configDigest[:])
	record.SandboxID, record.ExecutionID, record.WorkerID = j.SandboxID, j.ExecutionID, j.WorkerID
	record.HostID, record.RuntimeID, record.RuntimeGeneration = j.HostID, j.RuntimeID, j.RuntimeGeneration
	// Only actual same-UID ordinary socket receipt is exercised. The real
	// root-only constructor is not called or weakened by this test fixture.
	return &l8RuntimeOwnerLinuxRuntime{config: l8RuntimeOwnerSupervisorConfigV1{DaemonUID: uint32(os.Geteuid())}, genesis: record,
		store: &l8RuntimeOwnerLinuxRecordStore{selected: &jailerRecoveryStore{config: admission.config.jailerRecoverySupervisorConfig, minimal: &admission.recovery}}}
}

type minimalNamespaceBootstrapResult struct {
	err                      error
	starts, releases, events int
	revision                 uint64
}

func minimalNamespaceTestBootstrap(t *testing.T, owned *l8RuntimeOwnerLinuxRuntime, files []*os.File, correlation l8RuntimeOwnerNamespaceCorrelationV1) minimalNamespaceBootstrapResult {
	t.Helper()
	if validateL8RuntimeOwnerNamespaceFiles(files, correlation) != nil {
		t.Fatal("generic actual-FD namespace prerequisite failed")
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	store := &l8RuntimeOwnerTestStore{}
	var got minimalNamespaceBootstrapResult
	owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{
		Store: store, GenesisRecord: owned.genesis, ExpectedUID: uint32(os.Geteuid()), CommitKey: make([]byte, 32),
		StartChild: func() (l8RuntimeOwnerStartedChild, error) {
			got.starts++
			return l8RuntimeOwnerStartedChild{Observation: l8RuntimeOwnerProcessObservation{PID: 7001, StartTime: 7002},
				Release: func() error { got.releases++; return nil }}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(owner.opts.CommitKey)
	packet := l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeBootstrapStart, Body: encodeL8RuntimeOwnerNamespaceCorrelation(correlation)}
	if sendL8RuntimeOwnerSeqpacket(pair[0], packet, files) != nil {
		t.Fatal("actual namespace SCM_RIGHTS send failed")
	}
	got.err = owned.serveBootstrap(owner, pair[1])
	got.events = len(store.events)
	if got.err == nil {
		reply, err := receiveL8RuntimeOwnerSeqpacket(pair[0])
		defer closeL8RuntimeOwnerFiles(reply.Files)
		if err != nil || reply.Packet.Opcode != l8RuntimeOwnerOpcodeBootstrapPublished || len(reply.Packet.Body) != 8 || len(reply.Files) != 0 {
			t.Fatal("actual bootstrap reply changed")
		}
		got.revision = binary.BigEndian.Uint64(reply.Packet.Body)
	}
	for _, file := range files {
		if _, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0); err != nil {
			t.Fatal("receiver closed sender-owned namespace handle")
		}
	}
	return got
}

func minimalNamespaceTestFiles(t *testing.T, names [2]string) ([]*os.File, l8RuntimeOwnerNamespaceCorrelationV1) {
	t.Helper()
	files := make([]*os.File, 2)
	var identities [2]l8RuntimeOwnerNSIdentity
	for i, name := range names {
		file, err := os.Open("/proc/self/ns/" + name)
		if err != nil {
			t.Fatal(err)
		}
		files[i] = file
		t.Cleanup(func() { _ = file.Close() })
		kind, err := unix.IoctlRetInt(int(file.Fd()), unix.NS_GET_NSTYPE)
		if err != nil || kind != map[string]int{"user": unix.CLONE_NEWUSER, "net": unix.CLONE_NEWNET, "mnt": unix.CLONE_NEWNS}[name] {
			t.Fatal("actual fixture namespace kind is unavailable or wrong")
		}
		identities[i], err = l8RuntimeOwnerStatNamespace(file)
		if err != nil {
			t.Fatal(err)
		}
	}
	return files, l8RuntimeOwnerNamespaceCorrelationV1{UserDevice: identities[0].device, UserInode: identities[0].inode, NetworkDevice: identities[1].device, NetworkInode: identities[1].inode}
}
