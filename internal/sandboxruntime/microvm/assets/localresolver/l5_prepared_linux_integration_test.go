//go:build l5_firecracker_vsock_integration

package localresolver

import (
	"os"
	"os/exec"
	"reflect"
	"runtime"
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
	command := exec.Command(debugfs, "-R", "stat /usr/bin/hal-guest-agent", rootfs)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatal("L5 rootfs does not contain the guest agent")
	}
	if !strings.Contains(string(output), "Type: regular") {
		t.Fatal("L5 rootfs guest agent is not a regular file")
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
