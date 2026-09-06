package firecrackerhost

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestStrictJailerMinimalStagesVerifiedBytesThroughExistingCoordinator(t *testing.T) {
	verified, _, kernel, rootfs := minimalJailerFixture(t)
	events := []string{}
	lifecycle := &coordinatorFakeLifecycle{events: &events}
	coordinator, filesystem := minimalJailerTestCoordinator(&events, lifecycle)
	session, err := coordinator.startMinimal(context.Background(), minimalJailerTestRequest(t), verified)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(events, "start") {
		t.Fatal("existing lifecycle was not called")
	}
	for name, want := range map[string][]byte{"boot/vmlinux": kernel, "images/rootfs.ext4": rootfs} {
		file := filesystem.root.files[filepath.FromSlash(name)]
		if file == nil || !bytes.Equal(file.data, want) || file.syncCalls != 2 || file.verifyCalls != 1 || !file.closed {
			t.Fatalf("staged bytes/inspection differ for %s: %#v", name, file)
		}
	}
	if lifecycle.lastStart.hostPaths.ConfigPath != "/srv/jailer/firecracker/run-1/root/run/fc-run-1/firecracker-config.json" {
		t.Fatal("existing generation/path correlation changed")
	}
	if err := coordinator.stop(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	if filesystem.root.removeCalls != 1 || filesystem.root.closeCalls != 1 {
		t.Fatal("owned staged root not released exactly once")
	}
}

func TestStrictJailerMinimalRejectsSameInodeMutationDuringCopyEvenWhenRestored(t *testing.T) {
	verified, root, _, original := minimalJailerFixture(t)
	events := []string{}
	lifecycle := &coordinatorFakeLifecycle{events: &events}
	coordinator, filesystem := minimalJailerTestCoordinator(&events, lifecycle)
	stage := coordinator.deps.stage
	coordinator.deps.stage = func(fs jailerStagingFilesystem, request jailerStagingRequest) (jailerStagingResult, error) {
		// After the lease's currentness check, change the same inode. Restore it
		// before the borrow's final check: only actual copy/readback hashes catch it.
		path := filepath.Join(root, "rootfs.ext4")
		if err := os.WriteFile(path, bytes.Repeat([]byte("x"), len(original)), 0600); err != nil {
			t.Fatal(err)
		}
		result, err := stage(fs, request)
		if restoreErr := os.WriteFile(path, original, 0600); restoreErr != nil {
			t.Fatal(restoreErr)
		}
		return result, err
	}
	_, err := coordinator.startMinimal(context.Background(), minimalJailerTestRequest(t), verified)
	if err == nil || slices.Contains(events, "start") {
		t.Fatalf("mutated launch accepted: %v %v", err, events)
	}
	if filesystem.root == nil || filesystem.root.removeCalls != 1 {
		t.Fatal("tampered staged root not cleaned")
	}
}

func TestStrictJailerMinimalRejectsReplacementAndLateCancellation(t *testing.T) {
	for _, phase := range []string{"replace_before_launch", "cancel_after_stage", "cancel_after_plan", "failed_stage", "failed_start"} {
		t.Run(phase, func(t *testing.T) {
			verified, root, _, original := minimalJailerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			events := []string{}
			lifecycle := &coordinatorFakeLifecycle{events: &events}
			coordinator, filesystem := minimalJailerTestCoordinator(&events, lifecycle)
			stage := coordinator.deps.stage
			coordinator.deps.stage = func(fs jailerStagingFilesystem, request jailerStagingRequest) (jailerStagingResult, error) {
				result, err := stage(fs, request)
				if phase == "cancel_after_stage" {
					cancel()
				}
				return result, err
			}
			plan := coordinator.deps.plan
			coordinator.deps.plan = func(request strictJailerLaunchRequest) (strictJailerLaunchPlan, error) {
				if phase == "cancel_after_plan" {
					cancel()
				}
				if phase == "replace_before_launch" {
					path := filepath.Join(root, "rootfs.ext4")
					if err := os.Rename(path, filepath.Join(t.TempDir(), "old")); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, original, 0600); err != nil {
						t.Fatal(err)
					}
				}
				return plan(request)
			}
			if phase == "failed_stage" {
				filesystem.failCreatePath = filepath.FromSlash("images/rootfs.ext4")
				filesystem.failure = errors.New("injected failure")
			}
			if phase == "failed_start" {
				lifecycle.startErr = errors.New("injected contained start failure")
			}
			_, err := coordinator.startMinimal(ctx, minimalJailerTestRequest(t), verified)
			if err == nil || (phase != "failed_start" && slices.Contains(events, "start")) {
				t.Fatalf("invalid launch accepted: %v %v", err, events)
			}
			if filesystem.root == nil || filesystem.root.removeCalls != 1 {
				t.Fatalf("owned cleanup calls: %#v", filesystem.root)
			}
		})
	}
}

func minimalJailerTestRequest(t *testing.T) strictJailerCoordinatorRequest {
	request := validStrictJailerCoordinatorRequest(t)
	request.kernel = jailerStagingResourceInput{JailPath: request.kernel.JailPath}
	request.rootfs = jailerStagingResourceInput{JailPath: request.rootfs.JailPath}
	return request
}

func minimalJailerTestCoordinator(events *[]string, lifecycle *coordinatorFakeLifecycle) (*strictJailerCoordinator, *fakeJailerStagingFilesystem) {
	filesystem := newFakeJailerStagingFilesystem()
	coordinator := coordinatorForStateTest(events, &coordinatorFakeRoot{events: events}, lifecycle)
	coordinator.deps.newFilesystem = func(jailerStagingAuthority) (jailerStagingFilesystem, error) { return filesystem, nil }
	coordinator.deps.stage = stageStrictJailerResources
	return coordinator, filesystem
}
