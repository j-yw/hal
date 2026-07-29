//go:build l5_firecracker_vsock_integration

package localresolver

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
)

func TestL5PreparedLinuxImagePrerequisites(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Fatalf("L5 prepared image prerequisite requires Linux")
	}
	if runtime.GOARCH != "amd64" {
		t.Fatalf("L5 prepared image prerequisite requires x86_64")
	}
	root := strings.TrimSpace(os.Getenv("HAL_L5_DISTRIBUTION_DIR"))
	if root == "" {
		t.Fatal("HAL_L5_DISTRIBUTION_DIR is required")
	}

	request := DistributionRequest{RootDir: root}
	descriptor, err := ResolveDistribution(request)
	if err != nil {
		t.Fatalf("L5 installed launch assets failed verification")
	}
	verified, err := VerifyDistributionBundle(request)
	if err != nil {
		t.Fatalf("L5 distribution bundle failed verification")
	}
	if err := assetbuild.ValidateProvenanceAgainstManifest(verified.Provenance, verified.Manifest); err != nil {
		t.Fatalf("L5 provenance does not match distribution manifest")
	}
	if !reflect.DeepEqual(l5RequiredDistributionOutputs, []string{
		"SHA256SUMS",
		"distribution-manifest.json",
		"provenance.json",
		"rootfs.ext4",
		"vmlinux",
	}) {
		t.Fatal("L5 required distribution output set changed")
	}

	rootfs := l5PreparedRootfsPath(descriptor)
	if rootfs == "" {
		t.Fatal("L5 rootfs launch asset is unavailable")
	}
	debugfs, err := exec.LookPath("debugfs")
	if err != nil {
		t.Fatal("debugfs is required to inspect the L5 rootfs")
	}
	for _, path := range []string{"/sbin/init", "/sbin/hal-init", "/usr/bin/hal-guest-agent"} {
		requireL5RootfsEntry(t, debugfs, rootfs, path, "regular", "0755", 0, 0)
	}
	requireL5RootfsEntry(t, debugfs, rootfs, "/bin/busybox", "regular", "0755", 0, 0)
	for _, path := range []string{"/bin/sh", "/usr/bin/env"} {
		output := l5DebugfsCommand(t, debugfs, rootfs, "stat "+path)
		switch {
		case strings.Contains(output, "Type: regular"):
			requireL5RootfsEntry(t, debugfs, rootfs, path, "regular", "0755", 0, 0)
		case strings.Contains(output, "Type: symlink") &&
			strings.Contains(output, `Fast link dest: "/bin/busybox"`):
			// The only allowed applet link is the contained, inspected BusyBox binary.
		default:
			t.Fatal("L5 rootfs applet is neither a regular executable nor the intended BusyBox link")
		}
	}
	requireL5RootfsEntry(t, debugfs, rootfs, "/usr/bin/setpriv", "regular", "0755", 0, 0)
	requireL5SetprivPrivilegeDropOptions(t, debugfs, rootfs)
	requireL5RootfsEntry(t, debugfs, rootfs, "/workspace", "directory", "0700", 1000, 1000)

	passwd := l5DebugfsCommand(t, debugfs, rootfs, "cat /etc/passwd")
	if !strings.Contains(passwd, "agent:x:1000:1000:Agent:/workspace:/bin/sh") {
		t.Fatal("L5 rootfs does not pin the agent passwd identity to 1000/1000")
	}
	group := l5DebugfsCommand(t, debugfs, rootfs, "cat /etc/group")
	if !strings.Contains(group, "agent:x:1000:") {
		t.Fatal("L5 rootfs does not pin the agent group identity to 1000")
	}
}

func l5PreparedRootfsPath(descriptor assets.LaunchDescriptor) string {
	for _, asset := range descriptor.Assets {
		if asset.Role == assets.AssetRoleRootfs &&
			asset.Source.HostPath != nil {
			return asset.Source.HostPath.Path
		}
	}
	return ""
}

func requireL5RootfsEntry(
	t *testing.T,
	debugfs string,
	rootfs string,
	path string,
	entryType string,
	mode string,
	uid int,
	gid int,
) {
	t.Helper()
	output := l5DebugfsCommand(t, debugfs, rootfs, "stat "+path)
	if !strings.Contains(output, "Type: "+entryType) ||
		!regexp.MustCompile(`Mode:\s+`+regexp.QuoteMeta(mode)+`\b`).MatchString(output) ||
		!regexp.MustCompile(`User:\s+`+strconv.Itoa(uid)+`\s+Group:\s+`+strconv.Itoa(gid)+`\b`).MatchString(output) {
		t.Fatal("L5 rootfs entry type, mode, or ownership is invalid")
	}
}

func requireL5SetprivPrivilegeDropOptions(t *testing.T, debugfs string, rootfs string) {
	t.Helper()
	setprivPath := filepath.Join(t.TempDir(), "setpriv")
	_ = l5DebugfsCommand(t, debugfs, rootfs, "dump /usr/bin/setpriv "+setprivPath)
	if err := os.Chmod(setprivPath, 0o700); err != nil {
		t.Fatal("L5 rootfs setpriv extraction is not executable")
	}
	output, err := exec.Command(setprivPath, "--help").CombinedOutput()
	if err != nil {
		t.Fatal("L5 rootfs setpriv help failed")
	}
	for _, option := range []string{"--reuid", "--regid", "--clear-groups", "--no-new-privs"} {
		if !strings.Contains(string(output), option) {
			t.Fatalf("L5 rootfs setpriv does not support required privilege-drop option %q", option)
		}
	}
}

func l5DebugfsCommand(t *testing.T, debugfs string, rootfs string, commandText string) string {
	t.Helper()
	command := exec.Command(debugfs, "-R", commandText, rootfs)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatal("debugfs failed to inspect an L5 rootfs prerequisite")
	}
	return string(output)
}
