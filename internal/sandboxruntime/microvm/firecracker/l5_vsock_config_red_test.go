package firecracker

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestL5ProductionConfigContainsVsockBeforeStartAndReadOnlyRoot(t *testing.T) {
	stateDir := t.TempDir()
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
	if got := boot["boot_args"]; got != L5ProductionBootArgs {
		t.Fatalf("boot_args = %#v, want %q", got, L5ProductionBootArgs)
	}
	drive := raw["drives"].([]any)[0].(map[string]any)
	if got := drive["is_read_only"]; got != true {
		t.Fatalf("is_read_only = %#v, want true", got)
	}
	vsock := raw["vsock"].(map[string]any)
	if got := vsock["guest_cid"]; got != float64(L5GuestCID) {
		t.Fatalf("guest_cid = %#v, want %d", got, L5GuestCID)
	}
	if got := vsock["uds_path"]; got != paths.VsockSocketPath {
		t.Fatalf("uds_path = %#v, want private target path", got)
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
}
