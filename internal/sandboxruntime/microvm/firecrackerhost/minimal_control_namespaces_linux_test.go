//go:build linux

package firecrackerhost

import (
	"encoding/binary"
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMinimalControlNamespacesMissingOrChangedSelectedBinding(t *testing.T) {
	for _, name := range []string{"missing projection", "zero projection", "foreign correlation", "zero namespace", "duplicate tuple", "missing store", "missing selected store", "missing recovery", "foreign recovery", "foreign genesis", "foreign job", "wrong store version", "runtime selection without binding"} {
		t.Run(name, func(t *testing.T) {
			withMinimalNamespaceTestBinding(t, func(owned *l8RuntimeOwnerLinuxRuntime, admission *minimalControlSupervisorAdmission, files []*os.File, correlation l8RuntimeOwnerNamespaceCorrelationV1) {
				switch name {
				case "missing projection":
					owned.minimalNamespaces = nil
				case "zero projection":
					owned.minimalNamespaces = &minimalControlNamespaceProjection{}
				case "foreign correlation":
					owned.minimalNamespaces.configCorrelation = strings.Repeat("a", 64)
				case "zero namespace":
					owned.minimalNamespaces.namespaces.UserInode = 0
				case "duplicate tuple":
					ns := &owned.minimalNamespaces.namespaces
					ns.NetworkDevice, ns.NetworkInode = ns.UserDevice, ns.UserInode
				case "missing store":
					owned.store = nil
				case "missing selected store":
					owned.store.selected = nil
				case "missing recovery":
					owned.store.selected.minimal = nil
				case "foreign recovery":
					owned.store.selected.minimal.configCorrelation = strings.Repeat("b", 64)
				case "foreign genesis":
					owned.genesis.SeedCorrelationDigest = strings.Repeat("c", 64)
				case "foreign job":
					owned.store.selected.minimal.job.ExecutionID = "foreign-execution"
				case "wrong store version":
					owned.store.selected.config.Version = jailerRecoveryConfigVersion
				case "runtime selection without binding":
					owned.minimalNamespaces, owned.store = nil, nil
					owned.selected = &jailerRecoveryRuntime{config: admission.config.jailerRecoverySupervisorConfig}
				}
				before := minimalNamespaceTestHandleCount(t, files)
				got := minimalNamespaceTestBootstrap(t, owned, files, correlation)
				if got.err == nil || got.events != 0 || got.starts != 0 || got.releases != 0 || owned.namespaces != ([2]*os.File{}) {
					t.Fatalf("changed selected binding reached child/FSM: %#v", got)
				}
				if minimalNamespaceTestHandleCount(t, files) != before {
					t.Fatal("rejection retained received namespace copies")
				}
			})
		})
	}
}

func TestMinimalControlNamespacesBindingIsSingleUseAndCopiesAdmission(t *testing.T) {
	withMinimalNamespaceTestBinding(t, func(owned *l8RuntimeOwnerLinuxRuntime, admission *minimalControlSupervisorAdmission, files []*os.File, correlation l8RuntimeOwnerNamespaceCorrelationV1) {
		projection := *owned.minimalNamespaces
		if bindMinimalControlNamespaces(nil, admission) == nil || bindMinimalControlNamespaces(owned, nil) == nil || bindMinimalControlNamespaces(owned, admission) == nil {
			t.Fatal("nil or repeated constructor handoff accepted")
		}
		admission.namespace = minimalControlNamespaceProjection{}
		admission.config.Control.Namespace = minimalControlNamespaces{}
		if *owned.minimalNamespaces != projection || owned.minimalNamespaces == &admission.namespace {
			t.Fatal("runtime borrowed mutable admission namespace fields")
		}
		got := minimalNamespaceTestBootstrap(t, owned, files, correlation)
		if got.err != nil || got.starts != 1 || got.releases != 1 || got.revision != 2 {
			t.Fatalf("unchanged private snapshot rejected: %#v", got)
		}
		original := owned.namespaces
		before := minimalNamespaceTestHandleCount(t, files)
		for range 5 {
			got = minimalNamespaceTestBootstrap(t, owned, files, correlation)
			if got.err == nil || got.starts != 0 || got.events != 0 || owned.namespaces != original {
				t.Fatal("repeated bootstrap replaced retained original namespace ownership")
			}
			if minimalNamespaceTestHandleCount(t, files) != before {
				t.Fatal("repeated bootstrap leaked its received namespace copies")
			}
		}
		owned.minimalNamespaces = nil
		admission.namespace = projection
		if bindMinimalControlNamespaces(owned, admission) == nil {
			t.Fatal("late binding after namespace ownership accepted")
		}
		for _, file := range original {
			if _, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0); err != nil {
				t.Fatal("rejection closed original retained namespace descriptor")
			}
		}
	})
}

func TestMinimalControlNamespacesMalformedReceiptClosesCopies(t *testing.T) {
	for _, name := range []string{"no descriptors", "one descriptor", "three descriptors", "duplicate", "swapped", "non namespace", "truncated tuple", "wrong opcode"} {
		t.Run(name, func(t *testing.T) {
			withMinimalNamespaceTestBinding(t, func(owned *l8RuntimeOwnerLinuxRuntime, _ *minimalControlSupervisorAdmission, files []*os.File, correlation l8RuntimeOwnerNamespaceCorrelationV1) {
				candidate := append([]*os.File(nil), files...)
				packet := l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeBootstrapStart, Body: encodeL8RuntimeOwnerNamespaceCorrelation(correlation)}
				switch name {
				case "no descriptors":
					candidate = nil
				case "one descriptor":
					candidate = candidate[:1]
				case "three descriptors":
					candidate = append(candidate, files[0])
				case "duplicate":
					candidate[1] = files[0]
				case "swapped":
					candidate[0], candidate[1] = candidate[1], candidate[0]
				case "non namespace":
					file, err := os.Open(os.DevNull)
					if err != nil {
						t.Fatal(err)
					}
					defer file.Close()
					candidate[1] = file
				case "wrong opcode":
					packet.Opcode = l8RuntimeOwnerOpcodeChildRelease
					packet.Body = nil
				}
				wire, err := encodeL8RuntimeOwnerPacket(packet)
				if err != nil {
					t.Fatal("invalid source packet fixture")
				}
				if name == "truncated tuple" {
					wire = wire[:len(wire)-1]
					binary.BigEndian.PutUint16(wire[14:16], 31)
				}
				var rights []int
				for _, file := range candidate {
					rights = append(rights, int(file.Fd()))
				}
				var control []byte
				if len(rights) != 0 {
					control = unix.UnixRights(rights...)
				}
				store := &l8RuntimeOwnerTestStore{}
				owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{
					Store: store, GenesisRecord: owned.genesis, ExpectedUID: uint32(os.Geteuid()), CommitKey: make([]byte, 32),
					StartChild: func() (l8RuntimeOwnerStartedChild, error) {
						t.Error("malformed packet reached child callback")
						return l8RuntimeOwnerStartedChild{}, errL8RuntimeOwnerInvalid
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				defer clear(owner.opts.CommitKey)
				// Count only these exact kernel namespace identities, not the
				// process's unrelated runtime/test descriptors.
				before := minimalNamespaceTestHandleCount(t, files)
				for range 5 {
					pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
					if err != nil {
						t.Fatal(err)
					}
					if unix.Sendmsg(pair[0], wire, control, nil, 0) != nil {
						unix.Close(pair[0])
						unix.Close(pair[1])
						t.Fatal("fixture packet never reached actual receiver")
					}
					err = owned.serveBootstrap(owner, pair[1])
					unix.Close(pair[0])
					unix.Close(pair[1])
					if err == nil || len(store.events) != 0 || owned.namespaces != ([2]*os.File{}) || minimalNamespaceTestHandleCount(t, files) != before {
						t.Fatal("malformed receipt transferred or leaked namespace handles")
					}
				}
				for _, file := range candidate {
					if _, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0); err != nil {
						t.Fatal("rejection closed a sender-owned handle")
					}
				}
			})
		})
	}
}

func TestMinimalControlNamespacesClosedHandleFailsKindCheck(t *testing.T) {
	withMinimalNamespaceTestBinding(t, func(owned *l8RuntimeOwnerLinuxRuntime, _ *minimalControlSupervisorAdmission, files []*os.File, correlation l8RuntimeOwnerNamespaceCorrelationV1) {
		// Closed handles cannot travel via SCM_RIGHTS. Exercise the narrow
		// ioctl failure directly; malformed actual receipt is covered above.
		fd, err := unix.FcntlInt(files[0].Fd(), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			t.Fatal(err)
		}
		closed := os.NewFile(uintptr(fd), "closed-test-namespace")
		if closed.Close() != nil || owned.validateMinimalControlNamespaces([]*os.File{closed, files[1]}, correlation) == nil {
			t.Fatal("closed namespace handle accepted")
		}
	})
}

func withMinimalNamespaceTestBinding(t *testing.T, consume func(*l8RuntimeOwnerLinuxRuntime, *minimalControlSupervisorAdmission, []*os.File, l8RuntimeOwnerNamespaceCorrelationV1)) {
	t.Helper()
	f := newMinimalControlAdmissionFixture(t)
	files, correlation := minimalNamespaceTestFiles(t, [2]string{"user", "net"})
	f.config.Control.Namespace = minimalControlNamespaces(correlation)
	f.reseal(nil)
	if code := f.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		owned := minimalNamespaceTestRuntime(t, admission)
		defer owned.closeNamespaces()
		if bindMinimalControlNamespaces(owned, admission) != nil {
			t.Fatal("valid independent admission binding failed")
		}
		consume(owned, admission, files, correlation)
		return nil
	}); code != 0 || f.admissions != 1 || len(f.closed) != 8 {
		t.Fatal("fixture did not complete actual eight-role admission")
	}
}

func minimalNamespaceTestHandleCount(t *testing.T, files []*os.File) int {
	t.Helper()
	want := make(map[l8RuntimeOwnerNSIdentity]bool)
	for _, file := range files {
		identity, err := l8RuntimeOwnerStatNamespace(file)
		if err != nil {
			t.Fatal("sender namespace identity lost")
		}
		want[identity] = true
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		var stat unix.Stat_t
		if err == nil && unix.Fstat(fd, &stat) == nil && want[l8RuntimeOwnerNSIdentity{device: uint64(stat.Dev), inode: stat.Ino}] {
			count++
		}
	}
	return count
}
