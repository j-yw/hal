//go:build linux && minimal_runtime_constructor_integration

package firecrackerhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// As in the frozen RED, only this tagged test child enters a user namespace.
// All production ownership observations remain actual; no launch occurs.
func TestMinimalRuntimeAssemblyNamespaceFailures(t *testing.T) {
	const marker = "minimal-runtime-assembly-failure-child"
	if slices.Contains(os.Args, marker) {
		if os.Geteuid() != 0 || os.Getegid() != 0 {
			t.Fatal("actual namespace-root prerequisite missing")
		}
		// Execute the original successful prerequisite/constructor assertions
		// before treating any rejection below as a reachable negative.
		minimalRuntimeAssemblyNamespaceChild(t)
		minimalRuntimeAssemblyNamespaceFailures(t)
		minimalRuntimeAssemblyLegacyNamespaceControl(t)
		return
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-test.run=^TestMinimalRuntimeAssemblyNamespaceFailures$", "-test.v", "-test.timeout=10s", "--", marker)
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false}
	command.Env = []string{"TMPDIR=" + t.TempDir(), "GOMAXPROCS=2"}
	command.WaitDelay = 2 * time.Second
	output, err := command.CombinedOutput()
	t.Logf("namespace failure child:\n%s", output)
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EINVAL) {
		t.Fatalf("userns prerequisite unavailable, not constructor coverage: %v", err)
	}
	if ctx.Err() != nil || err != nil {
		t.Fatalf("joined namespace child failed: %v (deadline=%v)", err, ctx.Err())
	}
}

func minimalRuntimeAssemblyNamespaceFailures(t *testing.T) {
	for _, scenario := range []string{"callback_map", "full_correlation", "request_correlation", "recovery_job", "recovery_uid", "recovery_gid", "recovery_fc", "namespace_tuple",
		"closed_kernel", "closed_rootfs", "closed_fc", "replaced_kernel", "replaced_rootfs", "replaced_fc", "cleanup_key_size", "cleanup_key_mode", "listener_directory_removed", "owned_snapshot"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMinimalControlAdmissionFixture(t)
			f.config.EnablePCI = true
			f.reseal(nil)
			if os.Geteuid() != 0 || f.seedUID != 0 {
				t.Fatal("fixture must use actual namespace UID zero")
			}
			code := f.run("supervise", func(a *minimalControlSupervisorAdmission) error {
				if _, err := validateMinimalControlRuntimeAdmission(a); err != nil {
					t.Fatal("real admission prerequisite", err)
				}
				switch scenario {
				case "callback_map":
					a.config.Control.Prelaunch["workerJobId"] = "changed"
				case "full_correlation":
					a.configDigest[0] ^= 1
				case "request_correlation":
					a.request.configCorrelation[0] ^= 1
				case "recovery_job":
					a.recovery.job.ExecutionID = "changed"
				case "recovery_uid":
					a.recovery.uid++
				case "recovery_gid":
					a.recovery.gid++
				case "recovery_fc":
					a.recovery.firecrackerConfigSHA256 = f.config.Kernel.SHA256
				case "namespace_tuple":
					a.namespace.namespaces.UserInode++
				case "closed_kernel", "closed_rootfs", "closed_fc", "replaced_kernel", "replaced_rootfs", "replaced_fc":
					position := map[string]int{"closed_kernel": 3, "closed_rootfs": 4, "closed_fc": 6, "replaced_kernel": 3, "replaced_rootfs": 4, "replaced_fc": 6}[scenario]
					file := minimalControlTestMemfd(t, []byte("different authenticated asset"), l8RuntimeOwnerRequiredSeals, 0400, true)
					t.Cleanup(func() { _ = file.Close() })
					a.borrowed[position] = int(file.Fd())
					if scenario[:6] == "closed" {
						if err := file.Close(); err != nil {
							t.Fatal(err)
						}
					}
				case "cleanup_key_size":
					if err := f.files[5].Truncate(31); err != nil {
						t.Fatal(err)
					}
				case "cleanup_key_mode":
					if err := f.files[5].Chmod(0644); err != nil {
						t.Fatal(err)
					}
				case "listener_directory_removed":
					// No host/global changes: remove this one empty task directory.
					// Its retained FD still passes the actual directory predicate,
					// so bind fails only after real asset/key assembly has begun.
					if err := os.Remove(f.files[1].Name()); err != nil {
						t.Fatal(err)
					}
					if validateL8RuntimeOwnerDirectoryFD(a.borrowed[1]) != nil {
						t.Fatal("late listener prerequisite not reached")
					}
				}
				before := minimalRuntimeAssemblyDescriptorSnapshot(t)
				keyBefore := bytes.Clone(a.controllerKey)
				owned, err := newMinimalControlLinuxRuntime(a)
				if scenario == "owned_snapshot" {
					if err != nil || owned == nil {
						t.Fatal("actual namespace constructor", err)
					}
					defer func() {
						if owned.listenerFD >= 0 {
							owned.close()
						}
					}()
					projection, recovery, namespace := a.request, a.recovery, a.namespace
					selected := owned.selected
					if selected.minimalControl == &a.request || owned.store.selected.minimal == &a.recovery || owned.minimalNamespaces == &a.namespace {
						t.Fatal("admission projection aliases escaped")
					}
					a.config.Job.ExecutionID = "changed"
					a.config.Policy.UID++
					a.config.Roles[0] = "changed"
					a.config.Control.Prelaunch["workerJobId"] = "changed"
					a.request.nic.HostDeviceName = "changed"
					a.recovery.job.ExecutionID = "changed"
					a.namespace.namespaces.UserInode++
					binding, err := owned.store.selected.recordBinding()
					if err != nil || binding != jailerRecoveryRecordBinding(recovery) || *selected.minimalControl != projection || *owned.minimalNamespaces != namespace || selected.config.Job != recovery.job || selected.config.Policy.UID != recovery.uid || selected.config.Roles[0] != "control-socket" {
						t.Fatal("callback mutation changed retained independent owner")
					}
					if selected.attempted || selected.terminal || selected.coordinator.generation != nil || owned.store.selected.file != nil {
						t.Fatal("construction created launch/terminal/store authority")
					}
					owned.close()
				} else if err == nil || owned != nil {
					if owned != nil {
						owned.close()
					}
					t.Fatal("unsafe actual constructor input accepted")
				}
				if after := minimalRuntimeAssemblyDescriptorSnapshot(t); !maps.Equal(before, after) {
					t.Fatal("constructor failed to release only its owned descriptors")
				}
				if !bytes.Equal(keyBefore, a.controllerKey) {
					t.Fatal("constructor consumed original admission key")
				}
				if scenario != "listener_directory_removed" {
					entries, err := os.ReadDir(f.files[1].Name())
					if err != nil || len(entries) != 0 {
						t.Fatal("constructor left reconnect/state entries", err)
					}
				}
				return nil
			})
			if code != 0 || f.admissions != 1 || f.legacy != 0 || len(f.closed) != 8 {
				t.Fatal("actual fixed-root admission/borrowed-FD cleanup failed")
			}
		})
	}
}

// Observe only descriptor identities of this test child, never paths, contents,
// environment or another process. Ignore ReadDir's already-closed own FD.
func minimalRuntimeAssemblyDescriptorSnapshot(t *testing.T) map[int][3]uint64 {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[int][3]uint64)
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatal("non-numeric descriptor entry")
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); errors.Is(err, unix.EBADF) {
			continue
		} else if err != nil {
			t.Fatal(err)
		}
		out[fd] = [3]uint64{uint64(stat.Dev), stat.Ino, uint64(stat.Mode)}
	}
	return out
}

func minimalRuntimeAssemblyLegacyNamespaceControl(t *testing.T) {
	t.Run("actual_seven_constructor", func(t *testing.T) {
		f := newMinimalControlAdmissionFixture(t)
		if err := f.files[6].Close(); err != nil {
			t.Fatal(err)
		}
		fc := []byte(validCoordinatorConfig()) // Ordinary legacy no-NIC bytes.
		f.files[6] = minimalControlTestMemfd(t, fc, l8RuntimeOwnerRequiredSeals, 0400, true)
		config := f.config.jailerRecoverySupervisorConfig
		config.EnablePCI = true
		config.Version, config.Roles = jailerRecoveryConfigVersion, jailerRecoverySupervisorRoles()
		config.Config = minimalControlTestMeasuredAsset(t, f.files[6], "config", fc)
		payload, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		f.reseal(payload)
		var fds [6]int
		for i := range fds {
			fds[i] = int(f.files[i].Fd())
		}
		before := minimalRuntimeAssemblyDescriptorSnapshot(t)
		owned, err := newJailerRecoveryLinuxRuntime(fds, config, int(f.files[6].Fd()))
		if err != nil || owned == nil {
			t.Fatal("actual seven-role root constructor changed", err)
		}
		defer func() {
			if owned.listenerFD >= 0 {
				owned.close()
			}
		}()
		if owned.selected.config.Version != jailerRecoveryConfigVersion || owned.selected.minimalControl != nil || owned.store.selected.minimal != nil || owned.minimalNamespaces != nil || owned.genesis.SeedCorrelationDigest != jailerRecoveryConfigDigest(config) {
			t.Fatal("seven-role assembly acquired selected-eight behavior")
		}
		owned.close()
		if !maps.Equal(before, minimalRuntimeAssemblyDescriptorSnapshot(t)) {
			t.Fatal("seven-role construction leaked descriptors")
		}
		config.Version = minimalControlSupervisorConfigVersion
		if owned, err := newJailerRecoveryLinuxRuntime(fds, config, int(f.files[6].Fd())); err == nil || owned != nil {
			t.Fatal("legacy constructor admitted eight-role version")
		}
	})
}
