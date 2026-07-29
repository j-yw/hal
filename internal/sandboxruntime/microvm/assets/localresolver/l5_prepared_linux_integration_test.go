//go:build l5_firecracker_vsock_integration

package localresolver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
)

const (
	l5RootfsInspectionMaxBytes int64 = 128 << 20
	l5DebugfsOutputLimit       int64 = 8 << 20
	l5DebugfsTimeout                 = 5 * time.Second
)

type l5DebugfsOperation string

const (
	l5DebugfsOperationStat l5DebugfsOperation = "stat"
	l5DebugfsOperationCat  l5DebugfsOperation = "cat"
)

var l5DebugfsAllowedPaths = map[l5DebugfsOperation]map[string]struct{}{
	l5DebugfsOperationStat: {
		"/sbin/init":               {},
		"/sbin/hal-init":           {},
		"/usr/bin/hal-guest-agent": {},
		"/bin/busybox":             {},
		"/bin/sh":                  {},
		"/usr/bin/env":             {},
		"/usr/bin/setpriv":         {},
		"/workspace":               {},
	},
	l5DebugfsOperationCat: {
		"/usr/bin/setpriv": {},
		"/etc/passwd":      {},
		"/etc/group":       {},
	},
}

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
	if _, err := ResolveDistribution(request); err != nil {
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

	rootfs := l5CopyVerifiedRootfsForInspection(t, request, verified.Descriptor)
	debugfs, err := exec.LookPath("debugfs")
	if err != nil {
		t.Fatal("debugfs is required to inspect the L5 rootfs")
	}
	for _, path := range []string{"/sbin/init", "/sbin/hal-init", "/usr/bin/hal-guest-agent"} {
		requireL5RootfsEntry(t, debugfs, rootfs, path, "regular", "0755", 0, 0)
	}
	requireL5RootfsEntry(t, debugfs, rootfs, "/bin/busybox", "regular", "0755", 0, 0)
	for _, path := range []string{"/bin/sh", "/usr/bin/env"} {
		output := l5DebugfsCommand(t, debugfs, rootfs, l5DebugfsOperationStat, path)
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

	passwd := l5DebugfsCommand(t, debugfs, rootfs, l5DebugfsOperationCat, "/etc/passwd")
	if !strings.Contains(passwd, "agent:x:1000:1000:Agent:/workspace:/bin/sh") {
		t.Fatal("L5 rootfs does not pin the agent passwd identity to 1000/1000")
	}
	group := l5DebugfsCommand(t, debugfs, rootfs, l5DebugfsOperationCat, "/etc/group")
	if !strings.Contains(group, "agent:x:1000:") {
		t.Fatal("L5 rootfs does not pin the agent group identity to 1000")
	}
}

func l5PreparedRootfsAsset(descriptor assets.LaunchDescriptor) (assets.LaunchAsset, bool) {
	for _, asset := range descriptor.Assets {
		if asset.Role == assets.AssetRoleRootfs {
			return asset, true
		}
	}
	return assets.LaunchAsset{}, false
}

func TestL5CopyVerifiedRootfsForInspectionCopiesDigestLockedBytes(t *testing.T) {
	root := t.TempDir()
	data := []byte("l5-rootfs-inspection-fixture")
	if err := os.WriteFile(filepath.Join(root, "rootfs.ext4"), data, 0o600); err != nil {
		t.Fatal("write L5 rootfs inspection fixture failed")
	}
	digest := sha256.Sum256(data)
	descriptor := assets.LaunchDescriptor{Assets: []assets.LaunchAsset{{
		Role: assets.AssetRoleRootfs,
		Lock: assets.LockMetadata{
			Digest: assets.DigestMetadata{
				Algorithm: assets.DigestAlgorithmSHA256,
				Value:     hex.EncodeToString(digest[:]),
			},
			SizeBytes: int64(len(data)),
		},
	}}}

	copyPath := l5CopyVerifiedRootfsForInspection(t, DistributionRequest{RootDir: root}, descriptor)
	info, err := os.Stat(copyPath)
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatal("L5 rootfs inspection copy is not private and read-only")
	}
	copied, err := os.ReadFile(copyPath)
	if err != nil || string(copied) != string(data) {
		t.Fatal("L5 rootfs inspection copy does not preserve digest-locked bytes")
	}
}

func l5CopyVerifiedRootfsForInspection(
	t *testing.T,
	request DistributionRequest,
	descriptor assets.LaunchDescriptor,
) string {
	t.Helper()
	rootfsAsset, ok := l5PreparedRootfsAsset(descriptor)
	if !ok ||
		rootfsAsset.Lock.Digest.Algorithm != assets.DigestAlgorithmSHA256 ||
		rootfsAsset.Lock.Digest.Value == "" ||
		rootfsAsset.Lock.SizeBytes <= 0 ||
		rootfsAsset.Lock.SizeBytes > l5RootfsInspectionMaxBytes {
		t.Fatal("L5 rootfs inspection lock is unavailable or exceeds its bounded size")
	}

	root, _, err := openRequestedDistributionRoot(request.RootDir)
	if err != nil {
		t.Fatal("L5 rootfs inspection could not open the distribution root")
	}
	defer root.Close()

	source, err := openDistributionFileNoFollow(root, "rootfs.ext4")
	if err != nil {
		t.Fatal("L5 rootfs inspection could not open the verified rootfs")
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || info.Size() != rootfsAsset.Lock.SizeBytes {
		t.Fatal("L5 rootfs inspection source does not match its verified size")
	}

	path := filepath.Join(t.TempDir(), "rootfs.ext4")
	destination, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("L5 rootfs inspection could not create its private copy")
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(
		io.MultiWriter(destination, hasher),
		io.LimitReader(source, rootfsAsset.Lock.SizeBytes+1),
	)
	syncErr := destination.Sync()
	closeErr := destination.Close()
	if copyErr != nil ||
		syncErr != nil ||
		closeErr != nil ||
		written != rootfsAsset.Lock.SizeBytes ||
		hex.EncodeToString(hasher.Sum(nil)) != rootfsAsset.Lock.Digest.Value {
		t.Fatal("L5 rootfs inspection private copy does not match the verified asset")
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal("L5 rootfs inspection private copy is not read-only")
	}
	return path
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
	output := l5DebugfsCommand(t, debugfs, rootfs, l5DebugfsOperationStat, path)
	if !strings.Contains(output, "Type: "+entryType) ||
		!regexp.MustCompile(`Mode:\s+`+regexp.QuoteMeta(mode)+`\b`).MatchString(output) ||
		!regexp.MustCompile(`User:\s+`+strconv.Itoa(uid)+`\s+Group:\s+`+strconv.Itoa(gid)+`\b`).MatchString(output) {
		t.Fatal("L5 rootfs entry type, mode, or ownership is invalid")
	}
}

func requireL5SetprivPrivilegeDropOptions(t *testing.T, debugfs string, rootfs string) {
	t.Helper()
	output := l5DebugfsCommand(t, debugfs, rootfs, l5DebugfsOperationCat, "/usr/bin/setpriv")
	for _, option := range []string{"--reuid", "--regid", "--clear-groups", "--no-new-privs"} {
		if !strings.Contains(output, option) {
			t.Fatalf("L5 rootfs setpriv does not contain required privilege-drop option %q", option)
		}
	}
}

func l5DebugfsCommand(
	t *testing.T,
	debugfs string,
	rootfs string,
	operation l5DebugfsOperation,
	path string,
) string {
	t.Helper()
	allowedPaths, ok := l5DebugfsAllowedPaths[operation]
	if !ok {
		t.Fatal("L5 rootfs inspection operation is not read-only")
	}
	if _, ok := allowedPaths[path]; !ok {
		t.Fatal("L5 rootfs inspection path is not allowlisted")
	}
	commandText := string(operation) + " " + path
	ctx, cancel := context.WithTimeout(context.Background(), l5DebugfsTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, debugfs, "-R", commandText, rootfs)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal("debugfs could not initialize an L5 rootfs inspection")
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		t.Fatal("debugfs could not start an L5 rootfs inspection")
	}
	output, readErr := io.ReadAll(io.LimitReader(stdout, l5DebugfsOutputLimit+1))
	if int64(len(output)) > l5DebugfsOutputLimit {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("debugfs output exceeded the L5 inspection limit")
	}
	if readErr != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("debugfs could not read an L5 rootfs inspection")
	}
	if err := command.Wait(); err != nil {
		if ctx.Err() != nil {
			t.Fatal("debugfs inspection exceeded the L5 timeout")
		}
		t.Fatal("debugfs failed to inspect an L5 rootfs prerequisite")
	}
	return string(output)
}
