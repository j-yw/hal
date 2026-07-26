package firecracker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestL5ProductionConfigContainsVsockBeforeStartAndReadOnlyRoot(t *testing.T) {
	stateDir, err := os.MkdirTemp("/tmp", "hal-l5-cfg-")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })
	paths, err := PlanPaths(PathPlanRequest{
		RuntimeID:    "fc-l5-config",
		BaseStateDir: stateDir,
	})
	if err != nil {
		t.Fatalf("PlanPaths() error = %v", err)
	}
	if got, want := paths.VsockSocketPath, filepath.Join(paths.StateDir, "guest.vsock"); got != want {
		t.Fatalf("VsockSocketPath = %q, want %q", got, want)
	}

	config := BackendConfig{
		CPUCount:        1,
		MemoryMiB:       128,
		KernelImagePath: filepath.Join(stateDir, "vmlinux"),
		RootfsPath:      filepath.Join(stateDir, "rootfs.ext4"),
		Paths:           paths,
		ProductionVsock: true,
	}
	rendered, err := liveBootConfig(config)
	if err != nil {
		t.Fatalf("liveBootConfig() error = %v", err)
	}
	encoded, err := json.Marshal(rendered)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	boot := raw["boot-source"].(map[string]any)
	if got := boot["boot_args"]; got != l5ProductionBootArgs {
		t.Fatalf("boot_args = %#v, want %q", got, l5ProductionBootArgs)
	}
	drive := raw["drives"].([]any)[0].(map[string]any)
	if got := drive["is_read_only"]; got != true {
		t.Fatalf("is_read_only = %#v, want true", got)
	}
	vsock := raw["vsock"].(map[string]any)
	if got := vsock["guest_cid"]; got != float64(l5GuestCID) {
		t.Fatalf("guest_cid = %#v, want %d", got, l5GuestCID)
	}
	if got := vsock["uds_path"]; got != paths.VsockSocketPath {
		t.Fatalf("uds_path = %#v, want private target path", got)
	}
	entropy, ok := raw["entropy"].(map[string]any)
	if !ok || len(entropy) != 0 {
		t.Fatalf("entropy = %#v, want exact empty device object", raw["entropy"])
	}
}

func TestL5CompatibilityConfigOmitsVsock(t *testing.T) {
	rendered, err := liveBootConfig(BackendConfig{
		CPUCount:        1,
		MemoryMiB:       128,
		KernelImagePath: "/kernel",
		RootfsPath:      "/rootfs",
	})
	if err != nil {
		t.Fatalf("liveBootConfig() error = %v", err)
	}
	encoded, err := json.Marshal(rendered)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if _, ok := raw["vsock"]; ok {
		t.Fatalf("compatibility config unexpectedly contains vsock: %s", encoded)
	}
	if _, ok := raw["entropy"]; ok {
		t.Fatalf("compatibility config unexpectedly contains entropy: %s", encoded)
	}
}

func TestL5ProductionRenderRejectsSupportFileSymlinkWithoutFollowingIt(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "hal-l5-render-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	paths, err := PlanPaths(PathPlanRequest{RuntimeID: "fc-secure-render", BaseStateDir: base})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(base, "external")
	if err := os.WriteFile(external, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, paths.ConfigPath); err != nil {
		t.Fatal(err)
	}
	err = renderLiveBootFiles(BackendConfig{
		CPUCount: 1, MemoryMiB: 128,
		KernelImagePath: filepath.Join(base, "vmlinux"),
		RootfsPath:      filepath.Join(base, "rootfs.ext4"),
		Paths:           paths, ProductionVsock: true,
	})
	if err == nil {
		t.Fatal("renderLiveBootFiles() error = nil, want symlink rejection")
	}
	if data, readErr := os.ReadFile(external); readErr != nil || string(data) != "preserve" {
		t.Fatalf("external file was modified: data=%q error=%v", data, readErr)
	}
}

func TestL5ProductionRenderRequiresPrivateStateDirectoryMode(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "hal-l5-render-mode-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	paths, err := PlanPaths(PathPlanRequest{RuntimeID: "fc-secure-mode", BaseStateDir: base})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(paths.StateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	err = renderLiveBootFiles(BackendConfig{
		CPUCount: 1, MemoryMiB: 128,
		KernelImagePath: filepath.Join(base, "vmlinux"),
		RootfsPath:      filepath.Join(base, "rootfs.ext4"),
		Paths:           paths, ProductionVsock: true,
	})
	if err == nil {
		t.Fatal("renderLiveBootFiles() error = nil, want private state directory rejection")
	}
}
