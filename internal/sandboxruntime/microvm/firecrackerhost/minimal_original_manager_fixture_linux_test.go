//go:build linux

package firecrackerhost

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
	"golang.org/x/sys/unix"
)

// One original strict lifecycle launches through the existing injected process,
// identity and cgroup boundaries. Only its ordinary directory/socket ownership,
// sealed admission, store, gate I/O and protocol are real. Self pidfd observation
// does not prove a supervisor child, dedicated UID, root admission or a VM.
type minimalOriginalManagerFixture struct {
	*minimalPreparationFixture
	lifecycle *strictJailerLifecycle
	manager   *ProcessLifecycleManager
	paths     firecracker.PathPlan
	parent    privateStateDirIdentity
	stages    int
}

func withMinimalOriginalManagerFixture(t *testing.T, use func(*minimalOriginalManagerFixture)) {
	t.Helper()
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		t.Skip("ordinary nonzero-UID/GID directory and socket fixture required")
	}
	// Keep the derived jail/run/socket path below the Unix address bound.
	root, err := os.MkdirTemp("", "omf-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	a := newMinimalControlAdmissionFixture(t)
	namespaces, correlation := minimalNamespaceTestFiles(t, [2]string{"user", "net"})
	a.config.EnablePCI = true
	a.config.Control.Namespace = minimalControlNamespaces(correlation)
	a.config.Control.PreparationDeadlineUnixNano = time.Now().Add(time.Minute).UnixNano()
	p := &a.config.Policy
	p.UID, p.GID = uint32(os.Geteuid()), uint32(os.Getegid())
	p.TrustedAnchor, p.ChrootBase = root, filepath.Join(root, "j")
	p.JailerPath, p.FirecrackerPath = filepath.Join(root, "jailer"), filepath.Join(root, "firecracker")
	p.IdentityDirectory = filepath.Join(root, "identity")
	// The older coordinator fixture uses /run/fc-run-1 for runtime run-1.
	// Derive this composition's canonical paths before sealing or launching;
	// the unchanged transport must never repair a recorded process's paths.
	a.config.Job.RuntimeID = "fc-run-1"
	a.config.Control.Prelaunch["runtimeId"] = a.config.Job.RuntimeID
	paths, err := firecracker.PlanPaths(firecracker.PathPlanRequest{RuntimeID: a.config.Job.RuntimeID, BaseStateDir: "/run"})
	if err != nil {
		t.Fatal(err)
	}
	original, err := readMinimalControlFirecrackerConfig(int(a.files[6].Fd()), a.config.Config)
	if err != nil {
		t.Fatal("original measured config", err)
	}
	fc := make([]byte, a.config.Config.Size)
	if n, err := unix.Pread(int(a.files[6].Fd()), fc, 0); err != nil || n != len(fc) || bytes.Count(fc, []byte(a.config.Paths.VsockSocketPath)) != 1 {
		t.Fatal("original measured fixture config", err)
	}
	fc = bytes.Replace(fc, []byte(a.config.Paths.VsockSocketPath), []byte(paths.VsockSocketPath), 1)
	_, line := minimalOriginalManagerBoot(t, a.config)
	oldLine, _ := json.Marshal(original.BootSource.BootArgs)
	newLine, _ := json.Marshal(line)
	if bytes.Count(fc, oldLine) != 1 {
		t.Fatal("original fixture boot command line")
	}
	fc = bytes.Replace(fc, oldLine, newLine, 1)
	if a.files[6].Close() != nil {
		t.Fatal("dispose unused noncanonical fixture config")
	}
	a.files[6] = minimalControlTestMemfd(t, fc, l8RuntimeOwnerRequiredSeals, 0o400, true)
	a.config.Config = minimalControlTestMeasuredAsset(t, a.files[6], "config", fc)
	a.config.Paths = paths
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[1])
	if a.files[0].Close() != nil {
		t.Fatal("dispose unused admission endpoint")
	}
	a.files[0] = os.NewFile(uintptr(pair[0]), "original-manager-bootstrap")
	a.reseal(nil)
	requireMinimalControlFCFixtureValid(t, a)
	code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		_, prep, err := beginMinimalControlPreparation(admission)
		if err != nil {
			t.Fatal("pre-assembly lifetime prerequisite", err)
		}
		defer prep.close()
		owned, _, identityStore, _ := jailerRecoveryRuntimeFixture(t)
		selected := owned.selected
		if selected.attempted || selected.lifecycle != nil || selected.coordinator.generation != nil {
			t.Fatal("fixture assembly already launched or retained another lifecycle")
		}
		selected.config = admission.config.jailerRecoverySupervisorConfig
		requestProjection, recoveryProjection := admission.request, admission.recovery
		selected.minimalControl = &requestProjection
		for index, position := range []int{3, 4, 6} {
			fd, err := unix.FcntlInt(uintptr(admission.borrowed[position]), unix.F_DUPFD_CLOEXEC, 10)
			if err != nil {
				t.Fatal(err)
			}
			file := os.NewFile(uintptr(fd), "original-manager-measured-input")
			selected.files[index] = file
			defer file.Close()
		}
		// These are fixture-side peer/genesis observations, not a root override
		// in the unchanged production constructor or admitted sealed config.
		owned.config.DaemonUID = uint32(os.Geteuid())
		owned.store.selected.config, owned.store.selected.minimal = selected.config, &recoveryProjection
		owned.genesis.SeedCorrelationDigest = hex.EncodeToString(admission.configDigest[:])
		owned.genesis.RuntimeID = admission.config.Job.RuntimeID
		if bindMinimalControlNamespaces(owned, admission) != nil {
			t.Fatal("selected namespace/store binding")
		}
		selected.starter.started = false // The inherited fixture has not launched.
		if bindMinimalControlPreparation(owned, prep) != nil {
			t.Fatal("pre-assembly lifetime binding")
		}
		gate, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(gate[1])
		if selected.starter.gate.Close() != nil {
			t.Fatal("dispose unused fixture gate")
		}
		selected.starter.gate = os.NewFile(uintptr(gate[0]), "original-manager-gate")
		observation, err := inspectL8RuntimeOwnerProcess(uint32(os.Getpid()))
		if err != nil {
			t.Fatal("read-only self pidfd prerequisite", err)
		}
		if selected.starter.observation.Close() != nil {
			_ = observation.Close()
			t.Fatal("dispose close-only placeholder")
		}
		selected.starter.observation = observation
		owned.genesis.SupervisorPID = observation.ParentPID

		// Configure the fresh fake slot before any reservation; its filesystem
		// implementation is the existing injected boundary, not a real UID lease.
		identity := selected.coordinator.deps.identity
		identity.slot = strictJailerIdentitySlot{directory: p.IdentityDirectory, uid: p.UID, gid: p.GID}
		identityStore.payload = idleJailerIdentityRecord(identity.slot).payload()
		starter := &minimalReleaseFakeStarter{process: &minimalReleaseSelfProcess{atomicJailerTestProcess: newAtomicJailerTestProcess()}}
		runner, err := newStrictJailerNamespaceRunner(strictJailerNamespaceRunnerOptions{namespace: owned, starter: starter})
		if err != nil {
			t.Fatal(err)
		}
		lifecycle, err := newJailerRecoveryLifecycle(runner)
		if err != nil {
			t.Fatal(err)
		}
		selected.lifecycle, selected.coordinator.deps.lifecycle = lifecycle, lifecycle
		selected.coordinator.deps.plan = planStrictJailerLaunch
		starter.selected, starter.lifecycle, starter.manager, starter.ownerStarter = selected, lifecycle, lifecycle.manager, selected.starter
		f := &minimalOriginalManagerFixture{minimalPreparationFixture: &minimalPreparationFixture{owned: owned, admission: admission,
			peer: pair[1], gatePeer: gate[1], files: namespaces, tracked: starter,
			packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeBootstrapStart, Body: encodeL8RuntimeOwnerNamespaceCorrelation(correlation)}},
			lifecycle: lifecycle, manager: lifecycle.manager}
		stage := selected.coordinator.deps.stage
		selected.coordinator.deps.stage = func(fs jailerStagingFilesystem, request jailerStagingRequest) (jailerStagingResult, error) {
			if starter.calls != 0 || selected.starter.started || !f.manager.productionVsock {
				return jailerStagingResult{}, errL8RuntimeOwnerInvalid
			}
			paths, err := strictJailerHostPaths(request.Authority.JailRootHostPath, admission.config.Paths)
			if err != nil || os.MkdirAll(paths.StateDir, 0o700) != nil {
				return jailerStagingResult{}, errL8RuntimeOwnerInvalid
			}
			parent, err := statStrictJailerPrivateStateDir(paths.StateDir, request.Authority.UID)
			if err != nil {
				return jailerStagingResult{}, err
			}
			f.paths, f.parent = paths, parent
			f.stages++
			return stage(fs, request)
		}
		f.owner, err = newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{
			Store: owned.store, GenesisRecord: owned.genesis, ExpectedUID: owned.config.DaemonUID, CommitKey: make([]byte, 32),
			StartChild: func() (l8RuntimeOwnerStartedChild, error) {
				record, err := owned.store.Load(prep.preparationCtx)
				if err != nil || record.Revision != 0 || record.State != "starting" {
					return l8RuntimeOwnerStartedChild{}, errL8RuntimeOwnerInvalid
				}
				f.order = append(f.order, "genesis")
				child, err := selected.startMinimalControlChild()
				if err != nil {
					return child, err
				}
				f.order = append(f.order, "armed")
				release := child.Release
				child.Release = func() error {
					record, err := owned.store.Load(prep.preparationCtx)
					if err != nil || record.Revision != 1 || record.FirecrackerPID != child.Observation.PID || record.FirecrackerStartTime != child.Observation.StartTime {
						return errL8RuntimeOwnerInvalid
					}
					f.order = append(f.order, "revision1")
					if err := release(); err != nil {
						return err
					}
					f.order = append(f.order, "release")
					return nil
				}
				return child, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer clear(f.owner.opts.CommitKey)
		defer func() {
			if owned.shutdownMinimalControlPreparation() != nil {
				t.Error("preparation shutdown/join")
			}
			if selected.attempted {
				if _, err := selected.contain(); err != nil {
					t.Error("injected same-owner containment", err)
				}
			}
			if owned.closeNamespaces() != nil {
				t.Error("received namespace close")
			}
			for _, fd := range admission.borrowed {
				if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
					t.Error("fixture cleanup closed borrowed admission role")
				}
			}
			for _, file := range namespaces {
				if _, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0); err != nil {
					t.Error("fixture cleanup closed borrowed namespace sender")
				}
			}
		}()
		use(f)
		return nil
	})
	if code != 0 || a.admissions != 1 || a.legacy != 0 || len(a.closed) != 8 {
		t.Fatalf("sealed admission/import ownership: code=%d admissions=%d legacy=%d closes=%d", code, a.admissions, a.legacy, len(a.closed))
	}
}

func minimalOriginalManagerBoot(t *testing.T, config minimalControlSupervisorConfig) (session.Identity, string) {
	t.Helper()
	c, j := config.Control, config.Job
	public, publicOK := minimalControlConfigBase64(c.ControllerPublicKey)
	nonce, nonceOK := minimalControlConfigBase64(c.BootNonce)
	image, err := hex.DecodeString(config.Rootfs.SHA256)
	if !publicOK || !nonceOK || err != nil || len(image) != 32 {
		t.Fatal("immutable fixture guest pins")
	}
	identity := session.Identity{Channel: session.ChannelControl, GuestCID: session.GuestCID, GuestPort: session.ControlPort,
		RuntimeID: j.RuntimeID, RuntimeGeneration: j.RuntimeGeneration, BootGeneration: c.Prelaunch["bootGeneration"],
		ImageGeneration: c.Prelaunch["imageGeneration"], ControllerKeyGeneration: c.ControllerKeyGeneration, GuestBootNonce: nonce}
	copy(identity.ImageSHA256[:], image)
	line, err := minimalcontrol.RenderBootCommandLine("console=ttyS0 "+minimalL7BootFragment(c.StaticNetwork), identity, public[:], c.Prelaunch)
	if err != nil {
		t.Fatal(err)
	}
	return identity, line
}
