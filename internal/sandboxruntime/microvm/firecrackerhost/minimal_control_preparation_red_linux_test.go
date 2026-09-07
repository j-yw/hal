//go:build linux

package firecrackerhost

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"os"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Actual sealed eight-role admission, namespace SCM_RIGHTS/kind checks, selected
// file store and starter gate send; identity/cgroup/process allocation is the
// existing fake coordinator fixture. This does not pass the root constructor,
// enter namespaces or prove a live process/Jailer/L7/KVM boundary.
type minimalPreparationFixture struct {
	owned     *l8RuntimeOwnerLinuxRuntime
	owner     *l8RuntimeOwnerSupervisor
	admission *minimalControlSupervisorAdmission
	peer      int
	gatePeer  int
	files     []*os.File
	packet    l8RuntimeOwnerPacketV1
	order     []string
}

func withMinimalPreparationFixture(t *testing.T, deadline time.Time, use func(*minimalPreparationFixture)) {
	t.Helper()
	f := newMinimalControlAdmissionFixture(t)
	files, correlation := minimalNamespaceTestFiles(t, [2]string{"user", "net"})
	f.config.EnablePCI = true
	f.config.Control.Namespace = minimalControlNamespaces(correlation)
	f.config.Control.PreparationDeadlineUnixNano = deadline.UnixNano()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[1])
	if f.files[0].Close() != nil {
		t.Fatal("replace only fixture-owned unused endpoint")
	}
	f.files[0] = os.NewFile(uintptr(pair[0]), "minimal-preparation-original-test")
	f.reseal(nil)
	requireMinimalControlFCFixtureValid(t, f)
	code := f.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		owned, _, _, _ := jailerRecoveryRuntimeFixture(t)
		selected := owned.selected
		selected.config = admission.config.jailerRecoverySupervisorConfig
		requestProjection, recoveryProjection := admission.request, admission.recovery
		selected.minimalControl = &requestProjection
		for index, position := range []int{3, 4, 6} {
			fd, err := unix.FcntlInt(uintptr(admission.borrowed[position]), unix.F_DUPFD_CLOEXEC, 10)
			if err != nil {
				t.Fatal(err)
			}
			file := os.NewFile(uintptr(fd), "minimal-preparation-measured-test")
			selected.files[index] = file
			defer file.Close()
		}
		// The ordinary socket fixture authenticates its actual caller UID;
		// it does not pretend to pass the production root constructor.
		owned.config.DaemonUID = uint32(os.Geteuid())
		owned.store.selected.config = selected.config
		owned.store.selected.minimal = &recoveryProjection
		owned.genesis.SeedCorrelationDigest = hex.EncodeToString(admission.configDigest[:])
		if bindMinimalControlNamespaces(owned, admission) != nil {
			t.Fatal("actual eight-role namespace/store binding prerequisite")
		}
		request, err := selected.request()
		if err != nil || validateStrictJailerCoordinatorConfig(request) != nil {
			t.Fatal("actual admitted measured request prerequisite", err)
		}
		gate, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(gate[1])
		if selected.starter.gate.Close() != nil {
			t.Fatal("dispose unused fixture gate")
		}
		selected.starter.gate = os.NewFile(uintptr(gate[0]), "minimal-preparation-gate-test")
		fixture := &minimalPreparationFixture{owned: owned, admission: admission, peer: pair[1], gatePeer: gate[1], files: files,
			packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeBootstrapStart, Body: encodeL8RuntimeOwnerNamespaceCorrelation(correlation)}}
		fixture.owner, err = newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{
			Store: owned.store, GenesisRecord: owned.genesis, ExpectedUID: owned.config.DaemonUID, CommitKey: make([]byte, 32),
			StartChild: func() (l8RuntimeOwnerStartedChild, error) {
				record, err := owned.store.Load(context.Background())
				if err != nil || record.Revision != 0 || record.State != "starting" {
					return l8RuntimeOwnerStartedChild{}, errL8RuntimeOwnerInvalid
				}
				fixture.order = append(fixture.order, "genesis")
				child, err := selected.startMinimalControlChild()
				if err != nil {
					return child, err
				}
				fixture.order = append(fixture.order, "armed")
				release := child.Release
				child.Release = func() error {
					record, err := owned.store.Load(context.Background())
					if err != nil || record.Revision != 1 || record.FirecrackerPID != child.Observation.PID || record.FirecrackerStartTime != child.Observation.StartTime {
						return errL8RuntimeOwnerInvalid
					}
					fixture.order = append(fixture.order, "revision1")
					if err := release(); err != nil {
						return err
					}
					fixture.order = append(fixture.order, "release")
					return nil
				}
				return child, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer clear(fixture.owner.opts.CommitKey)
		defer func() {
			// This fixture cleans only through its fake retained coordinator;
			// received namespace copies are closed by the real existing helper.
			if selected.attempted {
				_, _ = selected.contain()
			}
			_ = owned.closeNamespaces()
		}()
		use(fixture)
		return nil
	})
	if code != 0 || f.admissions != 1 || f.legacy != 0 || len(f.closed) != 8 {
		t.Fatalf("actual admission/borrowed-FD cleanup prerequisite: code=%d admissions=%d legacy=%d closes=%d", code, f.admissions, f.legacy, len(f.closed))
	}
}

func (f *minimalPreparationFixture) start(t *testing.T) <-chan error {
	t.Helper()
	if err := sendL8RuntimeOwnerSeqpacket(f.peer, f.packet, f.files); err != nil {
		t.Fatal("actual bootstrap send prerequisite", err)
	}
	done := make(chan error, 1)
	go func() { done <- f.owned.serveMinimalControlPreparation(f.owner, f.admission.borrowed[0], f.admission) }()
	return done
}

func minimalPreparationJoin(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("fixture failed to quiesce; intended behavior assertion is not reached")
		return nil
	}
}

func TestMinimalPreparationActualBootstrapOrderControl(t *testing.T) {
	withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
		done := f.start(t)
		if err := minimalPreparationJoin(t, done); err != nil {
			t.Fatal("positive bootstrap failed before behavior boundary", err)
		}
		for _, fd := range []int{f.gatePeer, f.peer} {
			if setL8RuntimeOwnerSocketTimeout(fd, time.Second) != nil {
				t.Fatal("fixture receive bound")
			}
		}
		gate, gateErr := receiveL8RuntimeOwnerSeqpacket(f.gatePeer)
		defer closeL8RuntimeOwnerFiles(gate.Files)
		reply, replyErr := receiveL8RuntimeOwnerSeqpacket(f.peer)
		defer closeL8RuntimeOwnerFiles(reply.Files)
		record, err := f.owned.store.Load(context.Background())
		if gateErr != nil || gate.Packet.Opcode != l8RuntimeOwnerOpcodeChildRelease || len(gate.Files) != 0 ||
			replyErr != nil || reply.Packet.Opcode != l8RuntimeOwnerOpcodeBootstrapPublished || len(reply.Packet.Body) != 8 ||
			binary.BigEndian.Uint64(reply.Packet.Body) != 2 || err != nil || record.Revision != 2 || record.State != "running" ||
			record.SeedCorrelationDigest != hex.EncodeToString(f.admission.configDigest[:]) || f.owned.namespaces[0] == nil || f.owned.namespaces[1] == nil {
			t.Fatalf("actual gate/reply/durable-order prerequisite: gate=%v reply=%v record=%v", gateErr, replyErr, err)
		}
		f.order = append(f.order, "revision2-reply")
		if !slices.Equal(f.order, []string{"genesis", "armed", "revision1", "release", "revision2-reply"}) {
			t.Fatalf("bootstrap ordering: %v", f.order)
		}
		if _, err := unix.FcntlInt(f.files[0].Fd(), unix.F_GETFD, 0); err != nil {
			t.Fatal("SCM receiver closed borrowed sender namespace")
		}
	})
}

func TestMinimalPreparationBootstrapLossCancelsStart(t *testing.T) {
	withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
		entered := make(chan context.Context, 1)
		release := make(chan struct{})
		allocate := f.owned.selected.coordinator.deps.prepareCgroup
		f.owned.selected.coordinator.deps.prepareCgroup = func(ctx context.Context, request strictJailerCgroupRequest) (*strictJailerCgroupLease, error) {
			entered <- ctx
			<-release
			return allocate(ctx, request)
		}
		done := f.start(t)
		var ctx context.Context
		select {
		case ctx = <-entered:
		case <-time.After(3 * time.Second):
			close(release)
			_ = minimalPreparationJoin(t, done)
			t.Fatal("fixture did not reach actual selected allocation callback")
		}
		// Shutdown delivers genuine peer EOF while preserving its test-owned FD
		// for joined cleanup; no raw close races or namespace/process operation.
		if unix.Shutdown(f.peer, unix.SHUT_RDWR) != nil {
			close(release)
			_ = minimalPreparationJoin(t, done)
			t.Fatal("fixture peer loss prerequisite")
		}
		observed := false
		select {
		case <-ctx.Done():
			observed = true
		case <-time.After(time.Second):
		}
		close(release)
		_ = minimalPreparationJoin(t, done)
		if !observed {
			t.Error("original-channel EOF did not cancel selected preparation before fixture unblocked")
		}
	})
}

func TestMinimalPreparationKeepsAdmittedAbsoluteDeadline(t *testing.T) {
	deadline := time.Now().Add(10 * time.Second)
	withMinimalPreparationFixture(t, deadline, func(f *minimalPreparationFixture) {
		var observed time.Time
		var bounded bool
		allocate := f.owned.selected.coordinator.deps.prepareCgroup
		f.owned.selected.coordinator.deps.prepareCgroup = func(ctx context.Context, request strictJailerCgroupRequest) (*strictJailerCgroupLease, error) {
			observed, bounded = ctx.Deadline()
			return allocate(ctx, request)
		}
		if err := minimalPreparationJoin(t, f.start(t)); err != nil {
			t.Fatal("fixture did not finish actual bootstrap", err)
		}
		want := time.Unix(0, f.admission.config.Control.PreparationDeadlineUnixNano)
		if !bounded || !observed.Equal(want) {
			t.Errorf("selected allocator received rebased deadline %v; independently admitted absolute P is %v", observed, want)
		}
	})
}

func TestMinimalPreparationStageCapControl(t *testing.T) {
	withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
		var observed, latest time.Time
		var bounded bool
		allocate := f.owned.selected.coordinator.deps.prepareCgroup
		f.owned.selected.coordinator.deps.prepareCgroup = func(ctx context.Context, request strictJailerCgroupRequest) (*strictJailerCgroupLease, error) {
			observed, bounded = ctx.Deadline()
			latest = time.Now().Add(l8RuntimeOwnerContainmentBudget)
			return allocate(ctx, request)
		}
		earliest := time.Now().Add(l8RuntimeOwnerContainmentBudget)
		if err := minimalPreparationJoin(t, f.start(t)); err != nil {
			t.Fatal("stage-cap fixture bootstrap", err)
		}
		if !bounded || observed.Before(earliest) || observed.After(latest) {
			t.Fatalf("stage deadline %v outside actual start interval [%v,%v]", observed, earliest, latest)
		}
	})
}

func TestMinimalPreparationExpiredBeforeBootstrapDoesNotAllocate(t *testing.T) {
	withMinimalPreparationFixture(t, time.Now().Add(-time.Second), func(f *minimalPreparationFixture) {
		allocations := 0
		allocate := f.owned.selected.coordinator.deps.prepareCgroup
		f.owned.selected.coordinator.deps.prepareCgroup = func(ctx context.Context, request strictJailerCgroupRequest) (*strictJailerCgroupLease, error) {
			allocations++
			return allocate(ctx, request)
		}
		err := minimalPreparationJoin(t, f.start(t))
		if err == nil || allocations != 0 || f.owned.selected.starter.released {
			t.Errorf("expired admitted P reached bootstrap/host allocation: err=%v allocations=%d released=%t", err, allocations, f.owned.selected.starter.released)
		}
	})
}

func TestMinimalPreparationMalformedBootstrapControls(t *testing.T) {
	for _, name := range []string{"wrong_opcode", "no_namespaces", "wrong_namespace_tuple"} {
		t.Run(name, func(t *testing.T) {
			withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
				switch name {
				case "wrong_opcode":
					f.packet = l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeChildRelease}
				case "no_namespaces":
					f.files = nil
				case "wrong_namespace_tuple":
					f.packet.Body = slices.Clone(f.packet.Body)
					f.packet.Body[31] ^= 1
				}
				if err := minimalPreparationJoin(t, f.start(t)); err == nil || len(f.order) != 0 || f.owned.selected.attempted || f.owned.namespaces != ([2]*os.File{}) {
					t.Fatal("malformed original packet reached store/child or retained namespaces", err)
				}
			})
		})
	}
}
