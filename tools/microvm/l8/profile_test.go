package l8profile

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestL8ImageProfileLocksInheritedL7NetworkAndAddsCgroupPidfd(t *testing.T) {
	linux := readProfileFile(t, "linux.config")
	for _, required := range []string{
		"CONFIG_NET=y", "CONFIG_PACKET=y", "CONFIG_INET=y", "CONFIG_IPV6=y",
		"CONFIG_NETDEVICES=y", "CONFIG_VIRTIO_NET=y", "CONFIG_VSOCKETS=y", "CONFIG_VIRTIO_VSOCKETS=y",
		"CONFIG_TMPFS=y", "CONFIG_NAMESPACES=y", "CONFIG_PID_NS=y", "CONFIG_CGROUPS=y",
		"CONFIG_MEMCG=y", "CONFIG_CGROUP_PIDS=y", "CONFIG_CHECKPOINT_RESTORE=y",
	} {
		if !linePresent(linux, required) {
			t.Errorf("linux.config missing %q", required)
		}
	}
	buildroot := readProfileFile(t, "buildroot.config")
	for _, required := range []string{
		`BR2_SYSTEM_DHCP=""`,
		`BR2_ROOTFS_OVERLAY="/src/tools/microvm/l8/rootfs-overlay"`,
		`BR2_LINUX_KERNEL_CUSTOM_CONFIG_FILE="/src/tools/microvm/l8/linux.config"`,
		`BR2_PACKAGE_BUSYBOX_CONFIG_FRAGMENT_FILES="/src/tools/microvm/l8/busybox.fragment"`,
		`BR2_PACKAGE_NODEJS=y`,
		`BR2_TARGET_ROOTFS_EXT2_SIZE="512M"`,
	} {
		if !linePresent(buildroot, required) {
			t.Errorf("buildroot.config missing %q", required)
		}
	}
}

func TestL8ProfileDoesNotRewriteL5OrL7Contracts(t *testing.T) {
	l5 := readProfileFile(t, "../l5/linux.config")
	for _, required := range []string{"CONFIG_NET=y", "CONFIG_INET=n", "CONFIG_NETDEVICES=n"} {
		if !linePresent(l5, required) {
			t.Fatalf("L5 linux.config no-network contract missing %q", required)
		}
	}
	l7 := readProfileFile(t, "../l7/linux.config")
	if linePresent(l7, "CONFIG_CGROUPS=y") {
		t.Fatal("L7 linux.config must stay distinct from the L8 cgroup-v2 additions")
	}
	l8 := readProfileFile(t, "buildroot.config")
	if strings.Contains(l8, "/src/tools/microvm/l7/") {
		t.Fatal("L8 buildroot.config must not reuse L7 overlay or post-build paths")
	}
}

func TestL8BuildScriptsLockOfflinePinnedDockerAndSevenFileBundle(t *testing.T) {
	build := readProfileFile(t, "build.sh")
	container := readProfileFile(t, "build-in-container.sh")
	reproducible := readProfileFile(t, "verify-reproducible.sh")
	finalImage := readProfileFile(t, "verify-final-image.sh")
	cache := readProfileFile(t, "verify-cache.sh")
	for _, required := range []string{
		"--pull=never",
		"--network=none",
		"l8-production-credentials-image",
		"HL8E is unissued; L8 builds fail closed",
		"native bootstrap path is missing; L8 builds fail closed",
		"HAL_L8_PARENT_L7",
		"l7-firecracker-network-v1",
		"L5 images are not L8 production images",
		"tools/microvm/l8/role-bootstrap/hal-guest-role-bootstrap.S",
		"tools/microvm/l8/role-bootstrap/build.sh",
	} {
		if !strings.Contains(build, required) {
			t.Errorf("build.sh missing %q", required)
		}
	}
	for _, required := range []string{
		"guest-agent-v2",
		"credential_delivery_v2",
		"ssh_agent_relay_v1",
		"l8-production-credentials-v1",
		"final-inspection.json",
		"sources.lock.json",
		"VerifyL8DistributionBundle",
		"node-v22.22.0.tar.xz",
		"pi-coding-agent-0.82.1.tgz",
		"pi-shrinkwrap-0.82.1.json",
		"cmd/hal-guest-init",
		"cmd/hal-guest-agent",
		"HL8E is unissued; L8 builds fail closed",
		"role-bootstrap/hal-guest-role-bootstrap.S",
		"role-bootstrap/build.sh",
	} {
		if !strings.Contains(container, required) {
			t.Errorf("build-in-container.sh missing %q", required)
		}
	}
	if strings.Contains(container, "VerifyL8DistributionBundle(") {
		t.Fatal("build-in-container.sh must not call VerifyL8DistributionBundle")
	}
	if !strings.Contains(container, "-tags=l8_production_pid1") {
		t.Fatal("build-in-container.sh must compile L8 hal-init with l8_production_pid1")
	}
	halInitBuild := l8HalInitBuildCommand(container)
	if !strings.Contains(halInitBuild, "-tags=l8_production_pid1") || !strings.Contains(halInitBuild, "./cmd/hal-guest-init") {
		t.Fatalf("L8 hal-init build is missing the ForkExec-omitting tag: %s", halInitBuild)
	}
	for _, pkg := range []string{
		"./cmd/hal-guest-agent",
		"./cmd/hal-guest-credential-helper",
		"./cmd/hal-guest-mount-monitor",
		"./cmd/hal-guest-workload-shim",
	} {
		if strings.Contains(l8GuestBuildCommand(container, pkg), "-tags=l8_production_pid1") {
			t.Fatalf("L8 %s build must not use the PID1 ForkExec-omitting tag", pkg)
		}
	}
	for _, forbidden := range []string{
		"./cmd/hal-guest-role-bootstrap",
		"${CC:-gcc}",
		"tools/microvm/l8/native/",
		"profile_root/native/",
	} {
		if strings.Contains(container, forbidden) {
			t.Fatalf("build-in-container.sh must not use %q as the native bootstrap identity", forbidden)
		}
	}
	if _, err := os.Stat("role-bootstrap/hal-guest-role-bootstrap.S"); err != nil {
		t.Fatalf("native bootstrap source is missing: %v", err)
	}
	if _, err := os.Stat("role-bootstrap/build.sh"); err != nil {
		t.Fatalf("native bootstrap assembler is missing: %v", err)
	}
	for _, artifact := range sevenFileBundle() {
		if !strings.Contains(reproducible, artifact) {
			t.Errorf("verify-reproducible.sh missing %q", artifact)
		}
	}
	for _, required := range []string{
		"HL8E is unissued; L8 final-image verification fails closed",
		"HAL_L8_PARENT_L7",
		"/usr/bin/node",
		"/usr/bin/pi",
		"/sbin/hal-guest-role-bootstrap",
		"agent:x:998:998",
		"workload:x:1000:1000",
	} {
		if !strings.Contains(finalImage, required) {
			t.Errorf("verify-final-image.sh missing %q", required)
		}
	}
	for _, required := range []string{
		"cache.manifest",
		"L8 cache manifest is unissued",
		"node-v22.22.0.tar.xz",
		"pi-coding-agent-0.82.1.tgz",
		"pi-shrinkwrap-0.82.1.json",
	} {
		if !strings.Contains(cache, required) {
			t.Errorf("verify-cache.sh missing %q", required)
		}
	}
	if strings.Contains(cache, "l8_extra_count") || strings.Contains(cache, "manifest_count + l8_extra_count") {
		t.Fatal("verify-cache.sh must not accept unpinned L8 files outside an exact manifest")
	}
}

func TestL8BuildScriptsRejectUnsafeArgumentsWithoutBuildroot(t *testing.T) {
	t.Parallel()
	scripts := []string{"build.sh", "verify-reproducible.sh"}
	for _, script := range scripts {
		script := script
		t.Run(script+"/usage", func(t *testing.T) {
			t.Parallel()
			command := exec.Command("bash", script)
			err := command.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
				t.Fatalf("%s missing-args exit = %v, want 2", script, err)
			}
		})
		t.Run(script+"/relative", func(t *testing.T) {
			t.Parallel()
			command := exec.Command("bash", script, "--cache", "relative-cache", "--output", "/tmp/l8-output")
			err := command.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
				t.Fatalf("%s relative-cache exit = %v, want 2", script, err)
			}
		})
	}
}

func TestL8BuildFailsClosedWhenHL8EUnissued(t *testing.T) {
	if _, err := os.Stat("policy/verified-pinned-callsites.hl8e"); err == nil {
		t.Fatal("HL8E must remain unissued; do not generate verified-pinned-callsites.hl8e from a fixture")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}

	cache := filepath.Join("/tmp", "hal-l8-profile-cache")
	output := filepath.Join("/tmp", "hal-l8-profile-output")
	command := exec.Command("bash", "build.sh", "--cache", cache, "--output", output)
	payload, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 || exitErr.ExitCode() == 2 {
		t.Fatalf("build.sh HL8E gate exit = %v output = %s, want fail-closed", err, payload)
	}
	if !strings.Contains(string(payload), "HL8E is unissued") {
		t.Fatalf("build.sh output = %s, want HL8E fail-closed message", payload)
	}
}

func TestL8FinalImageVerifierFailsClosedWhenHL8EUnissued(t *testing.T) {
	root := t.TempDir()
	image := filepath.Join(root, "rootfs.ext4")
	if err := os.WriteFile(image, []byte("not-an-ext-image"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", "verify-final-image.sh", image)
	payload, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 || exitErr.ExitCode() == 2 {
		t.Fatalf("verify-final-image.sh HL8E gate exit = %v output = %s, want fail-closed", err, payload)
	}
	if !strings.Contains(string(payload), "HL8E is unissued") {
		t.Fatalf("verify-final-image.sh output = %s, want HL8E fail-closed message", payload)
	}
}

func TestL8CacheManifestLocksMeasuredNodePiAndTransitiveArchives(t *testing.T) {
	data, err := os.ReadFile("cache.manifest")
	if err != nil {
		t.Fatalf("L8 cache.manifest must exist: %v", err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatal("L8 cache.manifest must be a nonempty newline-terminated exact lock")
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != l8CacheManifestEntries {
		t.Fatalf("L8 cache.manifest entries = %d, want %d measured Node/Pi/transitive locks", len(lines), l8CacheManifestEntries)
	}
	sorted := append([]string(nil), lines...)
	sort.Strings(sorted)
	if strings.Join(lines, "\n") != strings.Join(sorted, "\n") {
		t.Fatal("L8 cache.manifest must be LC_ALL=C sorted")
	}

	l5Names := l8ManifestFilenames(t, readProfileFile(t, "../l5/cache.manifest"))
	seen := make(map[string]struct{}, len(lines))
	foundRequired := make(map[string]bool, len(l8RequiredCacheLocks))
	npmArchives := 0
	for i, line := range lines {
		digest, size, filename, ok := l8SplitManifestRecord(line)
		if !ok {
			t.Fatalf("L8 cache.manifest line %d is not digest<TAB>size<TAB>filename", i+1)
		}
		if len(digest) != 64 || digest != strings.ToLower(digest) || strings.Trim(digest, "0123456789abcdef") != "" {
			t.Fatalf("L8 cache.manifest line %d has an invalid digest", i+1)
		}
		if size == "" || size == "0" || strings.Trim(size, "0123456789") != "" || size[0] == '0' {
			t.Fatalf("L8 cache.manifest line %d has an invalid size", i+1)
		}
		if filename == "" || filename == "." || filename == ".." || strings.ContainsAny(filename, "/\\\t") {
			t.Fatalf("L8 cache.manifest line %d has an unsafe filename", i+1)
		}
		if _, exists := seen[filename]; exists {
			t.Fatalf("L8 cache.manifest duplicates filename %q", filename)
		}
		if _, exists := l5Names[filename]; exists {
			t.Fatalf("L8 cache.manifest collides with L5 filename %q", filename)
		}
		if strings.HasPrefix(filename, "firecracker-") {
			t.Fatalf("L8 cache.manifest must not reuse firecracker- L5 names, got %q", filename)
		}
		seen[filename] = struct{}{}
		if want, required := l8RequiredCacheLocks[filename]; required {
			if digest != want.digest || size != want.size {
				t.Fatalf("required L8 lock %s = %s %s, want measured %s %s", filename, digest, size, want.digest, want.size)
			}
			foundRequired[filename] = true
			continue
		}
		if !strings.HasSuffix(filename, ".tgz") {
			t.Fatalf("L8 transitive archive %q must be a unique .tgz", filename)
		}
		npmArchives++
	}
	for filename := range l8RequiredCacheLocks {
		if !foundRequired[filename] {
			t.Fatalf("L8 cache.manifest missing required name %q", filename)
		}
	}
	if npmArchives != l8TransitiveNpmArchiveCount {
		t.Fatalf("L8 transitive npm archives = %d, want %d shrinkwrap packs", npmArchives, l8TransitiveNpmArchiveCount)
	}
}

func TestL8CacheVerifierFailsClosedOnMissingUnsortedAndDuplicateLocks(t *testing.T) {
	t.Parallel()

	t.Run("issued manifest missing cache files", func(t *testing.T) {
		t.Parallel()
		cache := t.TempDir()
		if err := os.Chmod(cache, 0o700); err != nil {
			t.Fatal(err)
		}
		command := exec.Command("sh", "verify-cache.sh", "--cache", cache)
		payload, err := command.CombinedOutput()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 || exitErr.ExitCode() == 2 {
			t.Fatalf("verify-cache.sh missing-files exit = %v output = %s, want fail-closed", err, payload)
		}
		if !strings.Contains(string(payload), "cache entry is missing or is not a regular file") {
			t.Fatalf("verify-cache.sh output = %s, want missing cache-file fail-closed message", payload)
		}
	})

	tests := []struct {
		name    string
		mutate  func(t *testing.T, h l8CacheHarness)
		wantErr string
		wantOK  bool
	}{
		{name: "valid synthetic exact set", wantOK: true},
		{name: "missing file", mutate: func(t *testing.T, h l8CacheHarness) {
			t.Helper()
			if err := os.Remove(filepath.Join(h.cache, "chalk-5.6.2.tgz")); err != nil {
				t.Fatal(err)
			}
		}, wantErr: "cache entry is missing or is not a regular file"},
		{name: "unsorted", mutate: func(t *testing.T, h l8CacheHarness) {
			t.Helper()
			lines := strings.Split(strings.TrimSuffix(string(l8ReadFile(t, h.l8Manifest)), "\n"), "\n")
			sort.Sort(sort.Reverse(sort.StringSlice(lines)))
			l8WriteFile(t, h.l8Manifest, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
		}, wantErr: "L8 cache manifest must be sorted"},
		{name: "duplicate filename", mutate: func(t *testing.T, h l8CacheHarness) {
			t.Helper()
			l5Line := strings.TrimSpace(string(l8ReadFile(t, h.l5Manifest)))
			lines := strings.Split(strings.TrimSuffix(string(l8ReadFile(t, h.l8Manifest)), "\n"), "\n")
			lines = append(lines, l5Line)
			sort.Strings(lines)
			l8WriteFile(t, h.l8Manifest, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
		}, wantErr: "L5 and L8 cache manifests contain a duplicate filename"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newL8CacheHarness(t)
			if tt.mutate != nil {
				tt.mutate(t, h)
			}
			command := exec.Command("sh", h.script, "--cache", h.cache)
			payload, err := command.CombinedOutput()
			if tt.wantOK {
				if err != nil {
					t.Fatalf("verify-cache.sh error = %v, output = %s", err, payload)
				}
				return
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 || exitErr.ExitCode() == 2 {
				t.Fatalf("verify-cache.sh %s exit = %v output = %s, want fail-closed", tt.name, err, payload)
			}
			if !strings.Contains(string(payload), tt.wantErr) {
				t.Fatalf("verify-cache.sh %s output = %s, want %q", tt.name, payload, tt.wantErr)
			}
		})
	}
}

func TestL8FinalImageVerifierRejectsSymlinkInput(t *testing.T) {
	root := t.TempDir()
	payload := filepath.Join(root, "rootfs.ext2")
	if err := os.WriteFile(payload, []byte("not-an-ext-image"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "rootfs.ext4")
	if err := os.Symlink("rootfs.ext2", alias); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", "verify-final-image.sh", alias)
	err := command.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("verify-final-image.sh symlink exit = %v, want 2", err)
	}
}

func TestL8PostBuildKeepsL7ToolsAndInstallsL8BinariesWithoutSecrets(t *testing.T) {
	postBuild := readProfileFile(t, "post-build.sh")
	for _, required := range []string{
		`install -D -m 0755 /build/guest-bin/hal-guest-agent "$target/usr/bin/hal-guest-agent"`,
		`install -D -m 0755 /build/guest-bin/hal-init "$target/sbin/hal-init"`,
		`install -D -m 0755 /build/guest-bin/hal-guest-credential-helper "$target/usr/bin/hal-guest-credential-helper"`,
		`install -D -m 0755 /build/guest-bin/hal-guest-role-bootstrap "$target/sbin/hal-guest-role-bootstrap"`,
		`test -x "$target/usr/bin/setpriv"`,
		`test -x "$target/usr/bin/node"`,
		`test -x "$target/usr/bin/pi"`,
		`rm -rf -- "$target/root/.npm"`,
	} {
		if !strings.Contains(postBuild, required) {
			t.Errorf("post-build.sh missing %q", required)
		}
	}
}

const (
	l8CacheManifestEntries      = 142
	l8TransitiveNpmArchiveCount = 139
)

type l8RequiredLock struct {
	digest string
	size   string
}

var l8RequiredCacheLocks = map[string]l8RequiredLock{
	"node-v22.22.0.tar.xz": {
		digest: "4c138012bb5352f49822a8f3e6d1db71e00639d0c36d5b6756f91e4c6f30b683",
		size:   "50902788",
	},
	"pi-coding-agent-0.82.1.tgz": {
		digest: "8343ab95cbab5766f2f5d48844df8db13e772ead2e2976166cbb820a29dacb7d",
		size:   "4978133",
	},
	"pi-shrinkwrap-0.82.1.json": {
		digest: "ac68e6c713a3fa13b56d2e41855dcfce44fe2ca1645ccc90977bea3afbeaf50a",
		size:   "61545",
	},
}

type l8CacheHarness struct {
	script     string
	l5Manifest string
	l8Manifest string
	cache      string
}

func newL8CacheHarness(t *testing.T) l8CacheHarness {
	t.Helper()
	root := t.TempDir()
	l5Dir := filepath.Join(root, "l5")
	l8Dir := filepath.Join(root, "l8")
	cache := filepath.Join(root, "cache")
	h := l8CacheHarness{
		script:     filepath.Join(l8Dir, "verify-cache.sh"),
		l5Manifest: filepath.Join(l5Dir, "cache.manifest"),
		l8Manifest: filepath.Join(l8Dir, "cache.manifest"),
		cache:      cache,
	}
	if err := os.MkdirAll(l5Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(l8Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	l8WriteFile(t, h.script, l8ReadFile(t, "verify-cache.sh"), 0o755)

	l5Payload := []byte("cache-a")
	l8Files := []struct {
		name    string
		payload []byte
	}{
		{name: "node-v22.22.0.tar.xz", payload: []byte("synthetic-node")},
		{name: "pi-coding-agent-0.82.1.tgz", payload: []byte("synthetic-pi")},
		{name: "pi-shrinkwrap-0.82.1.json", payload: []byte("synthetic-shrinkwrap")},
		{name: "chalk-5.6.2.tgz", payload: []byte("synthetic-chalk")},
	}
	l8WriteCacheFile(t, cache, "dep-a.tar", l5Payload)
	l8WriteFile(t, h.l5Manifest, l8ManifestLine(l5Payload, "dep-a.tar"), 0o644)

	var l8Lines []string
	for _, file := range l8Files {
		l8WriteCacheFile(t, cache, file.name, file.payload)
		l8Lines = append(l8Lines, strings.TrimSuffix(string(l8ManifestLine(file.payload, file.name)), "\n"))
	}
	sort.Strings(l8Lines)
	l8WriteFile(t, h.l8Manifest, []byte(strings.Join(l8Lines, "\n")+"\n"), 0o644)
	return h
}

func l8WriteCacheFile(t *testing.T, cache, name string, payload []byte) {
	t.Helper()
	l8WriteFile(t, filepath.Join(cache, name), payload, 0o600)
}

func l8WriteFile(t *testing.T, path string, payload []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, payload, mode); err != nil {
		t.Fatal(err)
	}
}

func l8ReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func l8ManifestLine(payload []byte, filename string) []byte {
	sum := sha256.Sum256(payload)
	return []byte(fmt.Sprintf("%s\t%d\t%s\n", hex.EncodeToString(sum[:]), len(payload), filename))
}

func l8SplitManifestRecord(line string) (digest, size, filename string, ok bool) {
	parts := strings.Split(line, "\t")
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func l8ManifestFilenames(t *testing.T, manifest string) map[string]struct{} {
	t.Helper()
	names := make(map[string]struct{})
	for i, line := range strings.Split(strings.TrimSuffix(manifest, "\n"), "\n") {
		_, _, filename, ok := l8SplitManifestRecord(line)
		if !ok {
			t.Fatalf("manifest line %d is not digest<TAB>size<TAB>filename", i+1)
		}
		names[filename] = struct{}{}
	}
	return names
}

func sevenFileBundle() []string {
	return []string{
		"SHA256SUMS",
		"distribution-manifest.json",
		"final-inspection.json",
		"provenance.json",
		"rootfs.ext4",
		"sources.lock.json",
		"vmlinux",
	}
}

func readProfileFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	return string(data)
}

func linePresent(text, want string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

func l8HalInitBuildCommand(container string) string {
	return l8GuestBuildCommand(container, "./cmd/hal-guest-init")
}

func l8GuestBuildCommand(container, pkg string) string {
	marker := "-o /build/guest-bin/"
	index := 0
	for {
		start := strings.Index(container[index:], marker)
		if start < 0 {
			return ""
		}
		start += index
		end := strings.Index(container[start:], "\n")
		if end < 0 {
			end = len(container) - start
		}
		line := container[start : start+end]
		if strings.Contains(line, pkg) {
			blockStart := strings.LastIndex(container[:start], "go -C ")
			if blockStart < 0 {
				return line
			}
			return strings.TrimSpace(container[blockStart : start+end])
		}
		index = start + len(marker)
	}
}
