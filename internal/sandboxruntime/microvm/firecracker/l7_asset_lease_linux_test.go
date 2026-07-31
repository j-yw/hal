//go:build linux

package firecracker

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const l7AssetOwnershipHarnessMarker = "--hal-l7-asset-ownership-harness"

func TestVerifiedL7AssetLeaseClosesAllPinnedDescriptors(t *testing.T) {
	verified := verifiedL7DistributionForTest(t)
	baseline := l7OpenDescriptorCount(t)
	for iteration := 0; iteration < 32; iteration++ {
		lease, err := verified.AcquireL7AssetLease()
		if err != nil {
			t.Fatalf("AcquireL7AssetLease(%d) error = %v", iteration, err)
		}
		if err := lease.Close(); err != nil {
			t.Fatalf("Close(%d) error = %v", iteration, err)
		}
	}
	if got := l7OpenDescriptorCount(t); got != baseline {
		t.Fatalf("open descriptor count = %d, want baseline %d after lease cleanup", got, baseline)
	}
}

func TestL7StartOwnsSealedAssetsAcrossConcurrentLeaseCleanup(t *testing.T) {
	if hasL7AssetOwnershipHarnessMarker() {
		t.Skip("parent-only ownership test")
	}
	baseline := l7OpenDescriptorCount(t)
	tests := []struct {
		name    string
		cleanup func(*testing.T, BackendConfig)
	}{
		{
			name: "lease close",
			cleanup: func(t *testing.T, config BackendConfig) {
				t.Helper()
				if err := config.VerifiedL7Assets.Close(); err != nil {
					t.Fatalf("Close() error = %v", err)
				}
			},
		},
		{
			name: "duplicate render",
			cleanup: func(t *testing.T, config BackendConfig) {
				t.Helper()
				if _, err := renderLiveBootFilesForStart(config); err == nil {
					t.Fatal("duplicate render error = nil")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := validL7NetworkBackendConfig(t)
			config.RuntimeID = "runtime-l7-owned-assets"
			stateDir := filepath.Join(t.TempDir(), "state")
			config.Paths = PathPlan{
				StateDir:        stateDir,
				APISocketPath:   filepath.Join(stateDir, "api.sock"),
				ConfigPath:      filepath.Join(stateDir, "config.json"),
				LogPath:         filepath.Join(stateDir, "firecracker.log"),
				MetricsPath:     filepath.Join(stateDir, "firecracker.metrics"),
				VsockSocketPath: filepath.Join(stateDir, "guest.vsock"),
			}
			files, err := renderLiveBootFilesForStart(config)
			if err != nil {
				t.Fatalf("renderLiveBootFilesForStart() error = %v", err)
			}
			plan := validFirecrackerStartOperationPlan(t)
			descriptor, err := ProcessCommandDescriptorFromStartPlan(plan)
			if err != nil {
				t.Fatal(err)
			}
			atStartBoundary := make(chan struct{})
			continueStart := make(chan struct{})
			started := make(chan *exec.Cmd, 1)
			starter := &fakeProcessStarter{start: func(_ context.Context, req ProcessRunnerStartRequest) (ProcessHandleMetadata, error) {
				close(atStartBoundary)
				<-continueStart
				executable, executableErr := os.Executable()
				if executableErr != nil {
					return ProcessHandleMetadata{}, executableErr
				}
				command := exec.Command(
					executable,
					"-test.run=^TestL7AssetOwnershipChildHarness$",
					"--",
					l7AssetOwnershipHarnessMarker,
				)
				command.Env = []string{}
				command.ExtraFiles = append([]*os.File(nil), req.InheritedFiles...)
				if startErr := command.Start(); startErr != nil {
					return ProcessHandleMetadata{}, startErr
				}
				started <- command
				return ProcessHandleMetadata{ID: "fc-owned-assets", Source: "starter"}, nil
			}}
			controller := firecrackerController{
				processAdapter:       ProcessLaunchAdapter{Starter: starter},
				bootAcceptanceWaiter: l7AcceptedBootWaiter{},
			}
			startResult := make(chan error, 1)
			go func() {
				_, startErr := controller.startLiveProcessWithInheritedFiles(context.Background(), descriptor, config, files)
				startResult <- startErr
			}()
			<-atStartBoundary
			tt.cleanup(t, config)
			close(continueStart)
			if startErr := <-startResult; startErr != nil {
				t.Fatalf("startLiveProcessWithInheritedFiles() error = %v", startErr)
			}
			command := <-started
			if waitErr := command.Wait(); waitErr != nil {
				t.Fatalf("asset ownership child failed: %v", waitErr)
			}
		})
	}
	if got := l7OpenDescriptorCount(t); got != baseline {
		t.Fatalf("open descriptor count = %d, want baseline %d after actual starts", got, baseline)
	}
}

func TestL7AssetOwnershipChildHarness(t *testing.T) {
	if !hasL7AssetOwnershipHarnessMarker() {
		t.Skip("L7 asset ownership subprocess harness")
	}
	for index, want := range [][]byte{[]byte("verified-l7-kernel"), []byte("verified-l7-rootfs")} {
		got, err := os.ReadFile(filepath.Join("/proc/self/fd", string(rune('3'+index))))
		if err != nil {
			t.Fatalf("read inherited asset %d: %v", index, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("inherited asset %d bytes = %q, want verified bytes", index, got)
		}
	}
}

func hasL7AssetOwnershipHarnessMarker() bool {
	for _, arg := range os.Args {
		if strings.TrimSpace(arg) == l7AssetOwnershipHarnessMarker {
			return true
		}
	}
	return false
}

func l7OpenDescriptorCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("ReadDir(/proc/self/fd) error = %v", err)
	}
	return len(entries)
}
