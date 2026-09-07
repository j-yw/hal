//go:build linux

package firecrackerhost

import (
	"context"
	"os"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"golang.org/x/sys/unix"
)

// Only fixture setup changes: the old preparation RED remains byte-identical.
// This uses the real strict manager, pure launch planner and original namespace
// duplicate, but a fake HostProcess and fake cgroup filesystem. Self pidfd/proc
// reads prove only that read-only observation works, not a supervisor-created
// child, namespace entry, dedicated UID, private parent, cgroup or Jailer launch.
func minimalReleaseUseTrackedFixture(t *testing.T, f *minimalPreparationFixture) *minimalReleaseFakeStarter {
	t.Helper()
	selected := f.owned.selected
	if selected.attempted || selected.coordinator.generation != nil {
		t.Fatal("tracked fixture correction must precede all launch attempts")
	}
	observation, err := inspectL8RuntimeOwnerProcess(uint32(os.Getpid()))
	if err != nil {
		t.Fatal("read-only self pidfd/proc prerequisite unavailable", err)
	}
	if selected.starter.observation.Close() != nil {
		_ = observation.Close()
		t.Fatal("could not dispose unused close-only descriptor placeholder")
	}
	selected.starter.observation = observation
	// The existing ordinary owner genesis is fake. Its parent correlation is
	// explicitly set for this self observation, never claimed as live ownership.
	f.owned.genesis.SupervisorPID = observation.ParentPID
	f.owner.opts.GenesisRecord = f.owned.genesis
	starter := &minimalReleaseFakeStarter{process: &minimalReleaseSelfProcess{atomicJailerTestProcess: newAtomicJailerTestProcess()}}
	runner, err := newStrictJailerNamespaceRunner(strictJailerNamespaceRunnerOptions{namespace: f.owned, starter: starter})
	if err != nil {
		t.Fatal(err)
	}
	// Fake staging has no actual runtime-UID directory. This lower lifecycle
	// fixture therefore does not claim the production vsock-parent option.
	lifecycle, err := newStrictJailerLifecycle(runner)
	if err != nil {
		t.Fatal(err)
	}
	selected.lifecycle = lifecycle
	selected.coordinator.deps.lifecycle = lifecycle
	selected.coordinator.deps.plan = planStrictJailerLaunch
	return starter
}

type minimalReleaseSelfProcess struct{ *atomicJailerTestProcess }

// Signal and Kill remain the embedded fake's channel-only methods. They never
// signal this PID; no OS process is started, terminated or reaped by the fixture.
func (*minimalReleaseSelfProcess) HostPID() int { return os.Getpid() }

type minimalReleaseFakeStarter struct {
	process *minimalReleaseSelfProcess
	cgroup  *strictJailerCgroupLease
	launch  *os.File
	calls   int
}

func (starter *minimalReleaseFakeStarter) startStrictJailerNamespaceProcess(ctx context.Context, request strictJailerNamespaceProcessStartRequest) (HostProcess, error) {
	if validateStrictJailerNamespaceProcessStartRequest(request) != nil {
		return nil, errStrictJailerNamespaceRequestInvalid
	}
	command, err := parseStrictJailerCommand(firecracker.ProcessRunnerStartRequest{Executable: request.executable, Args: request.args})
	if err != nil {
		return nil, err
	}
	starter.cgroup = request.cgroup
	err = request.cgroup.withLaunchFD(ctx, command.runtimeID, func(file *os.File) error {
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			return errJailerCgroup
		}
		starter.launch = file // Observe closure after the real callback returns.
		starter.calls++
		return nil // No clone, exec, namespace entry, cgroup control or signal.
	})
	if err != nil {
		return nil, err
	}
	return starter.process, nil
}

func minimalReleaseRequireRevisionOne(t *testing.T, f *minimalPreparationFixture, starter *minimalReleaseFakeStarter) {
	t.Helper()
	selected := f.owned.selected
	record, err := f.owned.store.Load(context.Background())
	if err != nil || record.Revision != 1 || record.State != "starting" || record.ControllerState != "none" ||
		record.FirecrackerPID != uint32(os.Getpid()) || record.FirecrackerStartTime != selected.starter.observation.StartTime {
		t.Fatal("fixture did not reach actual canonical revision 1", err)
	}
	generation := selected.coordinator.generation
	if generation == nil || !generation.hasProcess || generation.state != strictJailerCoordinatorActive ||
		selected.lifecycle == nil || selected.coordinator.deps.lifecycle != selected.lifecycle || !selected.lifecycle.validProcess(generation.process) {
		t.Fatal("fixture did not reach the original strict lifecycle/manager")
	}
	identity, err := selected.lifecycle.manager.resolveLiveProcessIdentity(generation.process.handle)
	if err != nil || identity.pid != os.Getpid() || identity.done != starter.process.Done() ||
		!cleanupPathPlansEqual(identity.paths, generation.process.hostPaths) || starter.calls != 1 ||
		starter.cgroup != generation.cgroup || !starter.cgroup.launched || starter.launch == nil ||
		starter.launch.Fd() != ^uintptr(0) || !l8RuntimeOwnerProcessAlive(selected.starter.observation.pidfd) {
		t.Fatal("actual tracked process, self pidfd or scoped fake-cgroup launch prerequisite", err)
	}
}
