//go:build linux && minimal_runtime_constructor_integration

package firecrackerhost

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This sole subprocess changes only its user namespace. It never bootstraps,
// allocates a cgroup/identity slot/jail, enters a network namespace or starts a
// VM. Namespace-root construction is not initial-host-root launch acceptance.
func TestMinimalRuntimeAssemblyNamespaceConstructor(t *testing.T) {
	const marker = "minimal-runtime-assembly-namespace-child"
	if slices.Contains(os.Args, marker) {
		if os.Geteuid() != 0 || os.Getegid() != 0 {
			t.Fatal("prerequisite: child did not obtain actual namespace-root credentials")
		}
		minimalRuntimeAssemblyNamespaceChild(t)
		return
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-test.run=^TestMinimalRuntimeAssemblyNamespaceConstructor$", "-test.v", "-test.timeout=10s", "--", marker)
	command.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	command.Env = []string{"TMPDIR=" + t.TempDir(), "GOMAXPROCS=2"}
	command.WaitDelay = 2 * time.Second
	output, err := command.CombinedOutput() // Run joins this one bounded test child.
	t.Logf("namespace constructor child:\n%s", output)
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EINVAL) {
		t.Fatalf("prerequisite unavailable: isolated user namespace was refused; constructor RED not reached: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("namespace constructor child exceeded bounded deadline")
	}
	if err != nil {
		t.Fatalf("namespace constructor child failed: %v", err)
	}
}

func minimalRuntimeAssemblyNamespaceChild(t *testing.T) {
	f := newMinimalControlAdmissionFixture(t)
	f.config.EnablePCI = true
	f.reseal(nil)
	var first [6]int
	for i := range first {
		first[i] = int(f.files[i].Fd())
	}
	imports := map[int]*os.File{}
	openFD := func(number uintptr, role string) (int, error) {
		if (number != 9 && number != 10) || role != minimalControlTestRoles[number-3] {
			return -1, errL8RuntimeOwnerInvalid
		}
		file := f.files[number-3]
		imports[int(file.Fd())] = file
		return int(file.Fd()), nil
	}
	closeFD := func(fd int) error {
		file := imports[fd]
		if file == nil {
			return errL8RuntimeOwnerInvalid
		}
		delete(imports, fd)
		return file.Close()
	}
	admitted := false
	// Fixed UID 0, exactly as production: no injected UID/stat/key observer.
	selected, err := withMinimalControlSupervisorAdmission(first, openFD, closeFD, 0, func(admission *minimalControlSupervisorAdmission) error {
		admitted = true
		if !t.Run("real_prerequisites", func(t *testing.T) { minimalRuntimeAssemblyPrerequisites(t, admission) }) {
			return errL8RuntimeOwnerInvalid
		}
		t.Run("actual_eight_constructor", func(t *testing.T) {
			owned, err := newMinimalControlLinuxRuntime(admission)
			if err != nil || owned == nil {
				t.Fatalf("real namespace-root eight-role admission reached unavailable constructor: %v", err)
			}
			defer func() {
				if owned.listenerFD >= 0 {
					owned.close()
				}
			}()
			minimalRuntimeAssemblyAssertOwned(t, owned, admission)
		})
		return nil
	})
	if err != nil || !selected || !admitted || len(imports) != 0 {
		t.Fatalf("actual fixed-root admission/cleanup prerequisite: selected=%t admitted=%t imports=%d err=%v", selected, admitted, len(imports), err)
	}
}

func minimalRuntimeAssemblyPrerequisites(t *testing.T, admission *minimalControlSupervisorAdmission) {
	t.Helper()
	if os.Geteuid() != 0 || admission.config.DaemonUID != 0 || len(admission.borrowed) != 7 {
		t.Fatal("real root/eight-role admission prerequisite absent")
	}
	fd, err := unix.FcntlInt(uintptr(admission.borrowed[5]), unix.F_DUPFD_CLOEXEC, 10)
	if err != nil {
		t.Fatal("cleanup key duplicate prerequisite", err)
	}
	key, err := loadL8RuntimeOwnerStableKeyFD(fd, 0, realL8RuntimeOwnerKeyFDOps())
	if err != nil {
		t.Fatal("actual root-owned cleanup key prerequisite", err)
	}
	clear(key)
	if _, err := readL8RuntimeOwnerHostBootID(); err != nil {
		t.Fatal("actual boot identity prerequisite", err)
	}
	process, err := inspectL8RuntimeOwnerProcess(uint32(os.Getpid()))
	if err != nil {
		t.Fatal("actual self-process inspection prerequisite", err)
	}
	defer process.Close()
	listener, name, err := openL8RuntimeOwnerReconnectListener(admission.borrowed[1], l8RuntimeOwnerTestToken(52))
	if err != nil {
		t.Fatal("actual private reconnect listener prerequisite", err)
	}
	if unix.Close(listener) != nil || unix.Unlinkat(admission.borrowed[1], name, 0) != nil {
		t.Fatal("private prerequisite listener cleanup")
	}
	projection := admission.request
	requestOwner := &jailerRecoveryRuntime{config: admission.config.jailerRecoverySupervisorConfig, minimalControl: &projection}
	for i, position := range []int{3, 4, 6} {
		duplicate, err := unix.FcntlInt(uintptr(admission.borrowed[position]), unix.F_DUPFD_CLOEXEC, 10)
		if err != nil {
			t.Fatal("actual sealed asset duplicate prerequisite", err)
		}
		requestOwner.files[i] = os.NewFile(uintptr(duplicate), "minimal-assembly-prerequisite")
		defer requestOwner.files[i].Close()
	}
	request, err := requestOwner.request()
	if err != nil || validateStrictJailerCoordinatorConfig(request) != nil {
		t.Fatal("actual eight-role NIC request prerequisite", err)
	}
	if _, err := strictJailerCoordinatorCgroupRequest(request); err != nil {
		t.Fatal("pure finite resource request prerequisite", err)
	}
}

// These post-construction assertions are deliberately unreachable at the initial
// unavailable RED. They describe coupled assembly, not already-proved behavior.
func minimalRuntimeAssemblyAssertOwned(t *testing.T, owned *l8RuntimeOwnerLinuxRuntime, admission *minimalControlSupervisorAdmission) {
	t.Helper()
	selected := owned.selected
	if selected == nil || selected.config.Version != minimalControlSupervisorConfigVersion || selected.minimalControl == nil || *selected.minimalControl != admission.request ||
		owned.store == nil || selected.store != owned.store || owned.store.selected == nil || owned.store.selected.minimal == nil {
		t.Fatal("eight-role runtime/request/store assembly missing or relabeled seven-role")
	}
	binding, err := owned.store.selected.recordBinding()
	if err != nil || binding != jailerRecoveryRecordBinding(admission.recovery) || owned.genesis.SeedCorrelationDigest != hex.EncodeToString(admission.configDigest[:]) ||
		owned.genesis.SeedCorrelationDigest == jailerRecoveryConfigDigest(selected.config) || owned.minimalNamespaces == nil || *owned.minimalNamespaces != admission.namespace {
		t.Fatal("constructor did not bind independently admitted full-eight correlation and namespaces")
	}
	if selected.lifecycle == nil || selected.lifecycle.manager == nil || selected.coordinator == nil || selected.coordinator.deps.lifecycle != selected.lifecycle ||
		selected.lifecycle.manager.runner != selected.lifecycle.runner || selected.lifecycle.runner.namespace != owned || selected.lifecycle.runner.starter != selected.starter ||
		selected.attempted || selected.coordinator.generation != nil || owned.namespaces != ([2]*os.File{}) {
		t.Fatal("constructor did not retain one unstarted owner/runner/manager/coordinator")
	}
	for i, position := range []int{3, 4, 6} {
		file := selected.files[i]
		if file == nil || int(file.Fd()) == admission.borrowed[position] {
			t.Fatal("asset was not independently duplicated")
		}
		var actual, borrowed unix.Stat_t
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 || unix.Fstat(int(file.Fd()), &actual) != nil || unix.Fstat(admission.borrowed[position], &borrowed) != nil ||
			actual.Dev != borrowed.Dev || actual.Ino != borrowed.Ino || actual.Size != borrowed.Size {
			t.Fatal("retained sealed asset identity/CLOEXEC mismatch")
		}
	}
	keyAlias := owned.commitKey
	if !bytes.Equal(keyAlias, bytes.Repeat([]byte{17}, 32)) || bytes.Equal(keyAlias, admission.controllerKey) {
		t.Fatal("recovery key not retained separately from controller key")
	}
	owned.close()
	if !bytes.Equal(keyAlias, make([]byte, 32)) {
		t.Fatal("constructor cleanup did not clear recovery key")
	}
	for _, file := range selected.files {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("constructor cleanup did not close owned asset duplicate")
		}
	}
	for i, fd := range admission.borrowed {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
			t.Fatal("constructor cleanup closed borrowed role", strconv.Itoa(i), err)
		}
	}
}
