package firecracker

import (
	"encoding/json"
	"errors"
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

func TestL5ProductionRenderRejectsSwappedSupportFileBeforeTruncation(t *testing.T) {
	stateDir, err := os.MkdirTemp("/tmp", "hal-l5-render-swap-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, DefaultConfigPath)
	replacementPath := filepath.Join(stateDir, "replacement")
	if err := os.WriteFile(configPath, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacementPath, []byte("replacement-must-survive"), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := openSecureLiveBootStateDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer state.close()
	state.beforeOpen = func(name string) error {
		if err := os.Remove(filepath.Join(stateDir, name)); err != nil {
			return err
		}
		return os.Rename(replacementPath, filepath.Join(stateDir, name))
	}

	err = state.writeFile(configPath, []byte("new config"))
	if !errors.Is(err, errUnsafeLiveBootStateEntry) {
		t.Fatalf("writeFile() error = %v, want unsafe entry rejection", err)
	}
	data, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if got, want := string(data), "replacement-must-survive"; got != want {
		t.Fatalf("swapped replacement contents = %q, want %q", got, want)
	}
}
