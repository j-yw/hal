//go:build linux && minimal_runtime_constructor_integration

package firecrackerhost

import (
	"context"
	"errors"
	"maps"
	"os"
	"os/exec"
	"slices"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Same bounded harmless child as the constructor tests: CLONE_NEWUSER only,
// current UID/GID mapped to zero. No bootstrap, other namespace entry, cgroup,
// host identity reservation, Jailer or VM is executed here.
func TestMinimalPreparationNamespaceConstructor(t *testing.T) {
	const marker = "minimal-preparation-constructor-child"
	if slices.Contains(os.Args, marker) {
		if os.Geteuid() != 0 || os.Getegid() != 0 {
			t.Fatal("actual namespace-root prerequisite absent")
		}
		minimalRuntimeAssemblyNamespaceChild(t) // Original positive root/assembly control.
		minimalPreparationNamespaceCases(t)
		minimalRuntimeAssemblyLegacyNamespaceControl(t)
		return
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-test.run=^TestMinimalPreparationNamespaceConstructor$", "-test.v", "-test.timeout=10s", "--", marker)
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false}
	command.Env = []string{"TMPDIR=" + t.TempDir(), "GOMAXPROCS=2"}
	command.WaitDelay = 2 * time.Second
	output, err := command.CombinedOutput()
	t.Logf("namespace preparation child:\n%s", output)
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EINVAL) {
		t.Fatalf("userns prerequisite unavailable, not constructor coverage: %v", err)
	}
	if ctx.Err() != nil || err != nil {
		t.Fatalf("joined constructor child failed: %v (deadline=%v)", err, ctx.Err())
	}
}

func minimalPreparationNamespaceCases(t *testing.T) {
	for _, mode := range []string{"owned", "expired", "listener_failure", "missing_preparation", "foreign_preparation", "legacy_with_preparation"} {
		t.Run(mode, func(t *testing.T) {
			f := newMinimalControlAdmissionFixture(t)
			f.config.EnablePCI = true
			if mode == "expired" {
				f.config.Control.PreparationDeadlineUnixNano = time.Now().Add(-time.Second).UnixNano()
			}
			f.reseal(nil)
			if code := f.run("supervise", func(a *minimalControlSupervisorAdmission) error {
				if mode == "listener_failure" {
					if err := os.Remove(f.files[1].Name()); err != nil {
						t.Fatal("remove only empty task-owned listener directory", err)
					}
				}
				before := minimalRuntimeAssemblyDescriptorSnapshot(t)
				var owned *l8RuntimeOwnerLinuxRuntime
				var err error
				if mode == "missing_preparation" || mode == "foreign_preparation" || mode == "legacy_with_preparation" {
					var prep *minimalControlPreparation
					config := a.config.jailerRecoverySupervisorConfig
					if mode != "missing_preparation" {
						_, prep, err = beginMinimalControlPreparation(a)
						if err != nil {
							t.Fatal("actual preparation init prerequisite", err)
						}
						if mode == "foreign_preparation" {
							config.Job.ExecutionID = "foreign-job"
						} else {
							config.Version = jailerRecoveryConfigVersion
							config.Roles = jailerRecoverySupervisorRoles()
						}
					}
					var fds [6]int
					copy(fds[:], a.borrowed[:6])
					minimal := a
					if mode == "legacy_with_preparation" {
						minimal = nil
					}
					owned, err = assembleJailerRecoveryLinuxRuntime(fds, config, a.borrowed[6], minimal, prep)
					if prep != nil && prep.close() != nil {
						t.Error("untransferred preparation close")
					}
				} else {
					owned, err = newMinimalControlLinuxRuntime(a)
				}
				if mode == "owned" {
					if err != nil || owned == nil || owned.minimalPreparation == nil || owned.selected.minimalPreparation != owned.minimalPreparation {
						t.Fatal("actual root constructor omitted same-owner preparation", err)
					}
					prep := owned.minimalPreparation
					if !prep.matchesAdmission(a, owned.selected.config) || prep.owner != owned || prep.used || prep.ioDone != nil || prep.monitorDone != nil {
						t.Fatal("constructor did not retain exact unstarted preparation")
					}
					if deadline, ok := prep.preparationCtx.Deadline(); !ok || deadline.UnixNano() != a.config.Control.PreparationDeadlineUnixNano {
						t.Fatal("constructor rebased immutable P")
					}
					owned.close() // Production hook must join before closing other handles.
					waitMinimalPreparationSignal(t, prep.observerDone, "constructor P observer")
					waitMinimalPreparationSignal(t, prep.closeDone, "production preparation close")
					if prep.ctx.Err() == nil {
						t.Fatal("production close left preparation alive")
					}
				} else if err == nil || owned != nil {
					if owned != nil {
						owned.close()
					}
					t.Fatal("unsafe preparation construction/assembly accepted")
				}
				if after := minimalRuntimeAssemblyDescriptorSnapshot(t); !maps.Equal(before, after) {
					t.Fatal("constructor/preparation leaked or closed borrowed descriptors")
				}
				for _, fd := range a.borrowed {
					if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
						t.Fatal("production cleanup closed borrowed role", err)
					}
				}
				return nil
			}); code != 0 || f.admissions != 1 || len(f.closed) != 8 {
				t.Fatal("actual namespace-root admission/cleanup prerequisite")
			}
		})
	}
}
