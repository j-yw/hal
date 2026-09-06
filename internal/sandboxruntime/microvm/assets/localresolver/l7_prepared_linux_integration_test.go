//go:build firecracker_live && network_enforcement_live && l7_linux_network_integration

package localresolver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
)

const (
	l7DistributionDirEnv               = "HAL_L7_DISTRIBUTION_DIR"
	l7PreparedRootfsInspectionMaxBytes = int64(128 << 20)
	l7PreparedRootfsInspectionTimeout  = 60 * time.Second
)

var l7PreparedRootfsInspectionTools = []string{
	"bash",
	"debugfs",
	"grep",
	"awk",
	"sed",
	"realpath",
	"mktemp",
	"chmod",
	"rm",
}

func TestL7PreparedLinuxNetworkImagePrerequisites(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Fatal("L7 prepared network image prerequisite requires Linux")
	}
	if runtime.GOARCH != "amd64" {
		t.Fatal("L7 prepared network image prerequisite requires x86_64")
	}
	distributionRoot := strings.TrimSpace(os.Getenv(l7DistributionDirEnv))
	if distributionRoot == "" {
		t.Fatalf("%s is required", l7DistributionDirEnv)
	}
	for _, tool := range l7PreparedRootfsInspectionTools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("L7 prepared network image requires the %s inspection tool", tool)
		}
	}

	request := DistributionRequest{RootDir: distributionRoot}
	verified, err := VerifyDistributionBundle(request)
	if err != nil {
		t.Fatal("L7 installed distribution failed production verification")
	}
	if verified.Manifest.ImageProfile != assetbuild.ImageProfileL7Network {
		t.Fatal("installed distribution is not the locked L7 network profile")
	}
	profile, ok := verified.L7Profile()
	if !ok || !VerifiedL7ProfileMatches(&profile, &verified.Descriptor) {
		t.Fatal("installed L7 network profile proof is unavailable")
	}

	rootfs := copyL7PreparedRootfsForInspection(t, request, verified.Descriptor)
	verifyL7PreparedRootfs(t, rootfs)
}

func copyL7PreparedRootfsForInspection(
	t *testing.T,
	request DistributionRequest,
	descriptor assets.LaunchDescriptor,
) string {
	t.Helper()
	rootfsAsset, ok := l7PreparedRootfsAsset(descriptor)
	if !ok ||
		rootfsAsset.Lock.Digest.Algorithm != assets.DigestAlgorithmSHA256 ||
		rootfsAsset.Lock.Digest.Value == "" ||
		rootfsAsset.Lock.SizeBytes <= 0 ||
		rootfsAsset.Lock.SizeBytes > l7PreparedRootfsInspectionMaxBytes {
		t.Fatal("L7 rootfs inspection lock is unavailable or exceeds its bounded size")
	}

	root, _, err := openRequestedDistributionRoot(request.RootDir)
	if err != nil {
		t.Fatal("L7 rootfs inspection could not open the distribution root")
	}
	defer root.Close()

	source, err := openDistributionFileNoFollow(root, "rootfs.ext4")
	if err != nil {
		t.Fatal("L7 rootfs inspection could not open the verified rootfs")
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || info.Size() != rootfsAsset.Lock.SizeBytes {
		t.Fatal("L7 rootfs inspection source does not match its verified size")
	}

	path := filepath.Join(t.TempDir(), "rootfs.ext4")
	destination, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("L7 rootfs inspection could not create its private copy")
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
		t.Fatal("L7 rootfs inspection private copy does not match the verified asset")
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal("L7 rootfs inspection private copy is not read-only")
	}
	return path
}

func l7PreparedRootfsAsset(descriptor assets.LaunchDescriptor) (assets.LaunchAsset, bool) {
	for _, asset := range descriptor.Assets {
		if asset.Role == assets.AssetRoleRootfs {
			return asset, true
		}
	}
	return assets.LaunchAsset{}, false
}

func verifyL7PreparedRootfs(t *testing.T, rootfs string) {
	t.Helper()
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("L7 final-image verifier is unavailable")
	}
	packageDir := filepath.Dir(sourcePath)
	if !filepath.IsAbs(sourcePath) {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal("L7 final-image verifier is unavailable")
		}
		packageDir = cwd
	}
	repositoryRoot := filepath.Clean(filepath.Join(packageDir, "..", "..", "..", "..", ".."))
	verifier := filepath.Join(repositoryRoot, "tools", "microvm", "l7", "verify-final-image.sh")
	info, err := os.Lstat(verifier)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		t.Fatal("L7 final-image verifier is unavailable")
	}

	ctx, cancel := context.WithTimeout(context.Background(), l7PreparedRootfsInspectionTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, "bash", verifier, rootfs)
	command.Env = []string{"PATH=" + os.Getenv("PATH")}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			t.Fatal("L7 final-image verification exceeded its bounded deadline")
		}
		t.Fatal("L7 final-image verification failed")
	}
}
