//go:build linux

package firecrackerhost

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// The real selected startChild/contain/store consumers run here, but host
// allocation and process observations are explicitly fake. Ordinary files and
// Unix socketpairs do not prove trusted root ownership, namespaces or KVM.
func jailerRecoveryRuntimeFixture(t *testing.T) (*l8RuntimeOwnerLinuxRuntime, *coordinatorFakeRoot, *fakeJailerIdentityStore, *[]string) {
	t.Helper()
	ctx := context.Background()
	events := []string{}
	root := &coordinatorFakeRoot{events: &events}
	coordinator := coordinatorForStateTest(&events, root, &coordinatorFakeLifecycle{events: &events})
	identity, identityStore := newFakeJailerIdentityAuthority()
	coordinator.deps.identity = identity
	config := jailerRecoveryTestSupervisorConfig(t)
	config.EnablePCI = true
	request := validStrictJailerCoordinatorRequest(t)
	selected := &jailerRecoveryRuntime{config: config, coordinator: coordinator, starter: &jailerRecoveryStarter{started: true}}
	for index, input := range []jailerStagingResourceInput{request.kernel, request.rootfs, request.config} {
		file, measured, err := snapshotJailerRecoveryAsset(ctx, []string{"kernel", "rootfs", "config"}[index], input.Source, input.SizeBytes, input.SHA256, 4<<30)
		if err != nil {
			t.Fatal(err)
		}
		selected.files[index] = file
		t.Cleanup(func() { _ = file.Close() })
		switch index {
		case 0:
			selected.config.Kernel = measured
		case 1:
			selected.config.Rootfs = measured
		case 2:
			selected.config.Config = measured
		}
	}
	coordinator.deps.inspect = func(request strictJailerHostInspectionRequest) (strictJailerHostInspectionResult, error) {
		return strictJailerHostInspectionResult{canonicalJailerPath: request.jailerPath, canonicalFirecrackerPath: request.firecrackerPath, canonicalChrootBaseDir: request.chrootBaseDir, runtimeUID: request.runtimeUID, runtimeGID: request.runtimeGID}, nil
	}
	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = directory.Close() })
	record, _ := jailerRecoveryTestRecord(t)
	record.SeedCorrelationDigest = jailerRecoveryConfigDigest(selected.config)
	if err := validateJailerRecoverySupervisorConfig(selected.config); err != nil {
		t.Fatal("selected config fixture", err)
	}
	if _, err := encodeJailerRecoveryRecord(record, selected.config, nil, false); err != nil {
		t.Fatal("selected genesis fixture", err)
	}
	selectedRequest, err := selected.request()
	if err != nil {
		t.Fatal("selected request fixture", err)
	}
	if err := validateStrictJailerCoordinatorConfig(selectedRequest); err != nil {
		t.Fatal("selected coordinator fixture", err)
	}
	store := &l8RuntimeOwnerLinuxRecordStore{directoryFD: int(directory.Fd()), bootID: record.HostBootID, selected: &jailerRecoveryStore{config: selected.config}}
	coordinator.deps.recovery = store.recoveryAuthority()
	owned := &l8RuntimeOwnerLinuxRuntime{selected: selected, store: store, genesis: record, listenerFD: -1, config: l8RuntimeOwnerSupervisorConfigV1{DaemonUID: 0}}
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	selected.starter.gate = os.NewFile(uintptr(sockets[0]), "fake-armed-gate")
	// This owned disposable descriptor stands in for pidfd close ownership only;
	// no syscall interprets it as a process, and no signal or process is used.
	pidfd, err := unix.FcntlInt(directory.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		t.Fatal(err)
	}
	selected.starter.observation = l8RuntimeOwnerProcessObservation{PID: 303, StartTime: 404, ParentPID: record.SupervisorPID, pidfd: pidfd, pidfdOwned: true}
	t.Cleanup(func() {
		_ = unix.Close(sockets[1])
		_ = selected.starter.close()
		_ = coordinator.generationIdentityForTest().close()
		if store.selected.file != nil {
			_ = store.selected.file.Close()
		}
	})
	return owned, root, identityStore, &events
}

func TestJailerRecoveryActualSelectedOwnerRetainsCoordinatorAcrossReconnect(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "terminal", true: "retry_owned_cleanup"}[cleanupFails], func(t *testing.T) {
			owned, root, identityStore, events := jailerRecoveryRuntimeFixture(t)
			if cleanupFails {
				root.removeErrors = []error{errors.New("owned root incomplete"), nil}
			}
			nextToken := byte(10)
			owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{Store: owned.store, GenesisRecord: owned.genesis, ExpectedUID: 0, CommitKey: make([]byte, 32), commitID: jailerRecoveryCommitID, RandomToken: func() (string, error) { nextToken++; return l8RuntimeOwnerTestToken(nextToken), nil }, StartChild: owned.startChild, ContainChild: owned.containChild, ReinspectAbsence: owned.reinspectAbsence, CloseNamespaces: owned.closeNamespaces})
			if err != nil {
				t.Fatal(err)
			}
			_, err = owner.HandleBootstrap(context.Background(), 0, l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeBootstrapStart, Body: make([]byte, 32)}, Files: make([]*os.File, 2)})
			if err != nil {
				t.Fatalf("selected bootstrap: %v events %v attempted=%t poisoned=%t file=%t reservation=%t", err, *events, owned.selected.attempted, owned.store.selected.poisoned, owned.store.selected.file != nil, owned.store.selected.reservation != nil)
			}
			retained := owned.selected.coordinator.generation
			if retained == nil || owned.store.selected.reservation != retained.identity || !owned.selected.starter.released {
				t.Fatal("selected ownership not retained through publication")
			}
			admit := func() string {
				record, err := owned.store.Load(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				body, _ := encodeL8RuntimeOwnerHandshake(l8RuntimeOwnerHandshakeV1{SupervisorGeneration: record.SupervisorGeneration, RuntimeGeneration: record.RuntimeGeneration, RecordRevision: record.Revision, ReconnectSecret: record.ReconnectSecret})
				result, err := owner.AdmitController(context.Background(), 0, l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeHandshake, Body: body}})
				if err != nil {
					t.Fatal(err)
				}
				ack, err := decodeL8RuntimeOwnerHandshakeAck(result.Packet.Body)
				if err != nil {
					t.Fatal(err)
				}
				return ack.ControllerSessionGeneration
			}
			first := admit()
			before := slices.Clone(*events)
			if owner.ControllerLost(context.Background()) != nil {
				t.Fatal("controller loss")
			}
			second := admit()
			if owned.selected.coordinator.generation != retained || !slices.Equal(before, *events) {
				t.Fatal("daemon loss replaced or cleaned owner resources")
			}
			if _, err := jailerRecoveryFakeStop(owner, first); err == nil {
				t.Fatal("stale controller stopped runtime")
			}
			_, err = jailerRecoveryFakeStop(owner, second)
			if cleanupFails {
				if err == nil || owned.store.selected.terminal || owned.selected.coordinator.generation == nil {
					t.Fatal("failed cleanup promoted to terminal")
				}
				if owner.ControllerLost(context.Background()) != nil {
					t.Fatal("retry disconnect")
				}
				second = admit()
				_, err = jailerRecoveryFakeStop(owner, second)
			}
			if err != nil {
				t.Fatalf("selected stop: %v events %v", err, *events)
			}
			idle, err := readJailerIdentityRecord(identityStore.snapshot(), owned.selected.coordinator.deps.identity.slot)
			if err != nil || idle.State != "idle" || !owned.store.selected.terminal || owned.selected.coordinator.generation != nil {
				t.Fatalf("selected cleanup did not durably finish: %v %s", err, idle.State)
			}
			before = slices.Clone(*events)
			if _, err := jailerRecoveryFakeStop(owner, second); err != nil || !slices.Equal(before, *events) {
				t.Fatal("stop replay repeated cleanup")
			}
			payload, err := json.Marshal(owned.store.selected.busy)
			if err != nil || len(payload) == 0 {
				t.Fatal("missing original reservation correlation")
			}
			if count := func() int {
				n := 0
				for _, event := range *events {
					if event == "start" {
						n++
					}
				}
				return n
			}(); count != 1 {
				t.Fatalf("launch count %d", count)
			}
		})
	}
}

func TestJailerRecoverySelectedDecoderChecksRealSealedInput(t *testing.T) {
	config := jailerRecoveryTestSupervisorConfig(t)
	payload, _ := json.Marshal(config)
	file, err := sealJailerRecoveryBytes(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	got, selected, err := readJailerRecoverySelectedConfigFD(int(file.Fd()))
	if err != nil || !selected || got.Version != jailerRecoveryConfigVersion {
		t.Fatalf("selected sealed decoder: %v", err)
	}
	legacy, _ := encodeL8RuntimeOwnerSupervisorConfig(l8RuntimeOwnerTestSupervisorConfig())
	old, err := sealJailerRecoveryBytes(context.Background(), legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if _, selected, err := readJailerRecoverySelectedConfigFD(int(old.Fd())); err != nil || selected {
		t.Fatal("legacy config did not retain legacy route")
	}
	mutable, err := os.CreateTemp(t.TempDir(), "mutable")
	if err != nil {
		t.Fatal(err)
	}
	defer mutable.Close()
	if _, err := mutable.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readJailerRecoverySelectedConfigFD(int(mutable.Fd())); err == nil {
		t.Fatal("mutable config accepted")
	}
}
