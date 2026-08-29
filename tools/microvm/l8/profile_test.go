package l8profile

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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
	} {
		if !strings.Contains(container, required) {
			t.Errorf("build-in-container.sh missing %q", required)
		}
	}
	if strings.Contains(container, "VerifyL8DistributionBundle(") {
		t.Fatal("build-in-container.sh must not call VerifyL8DistributionBundle")
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
		"node-v22.22.0.tar.xz",
		"pi-coding-agent-0.82.1.tgz",
		"pi-shrinkwrap-0.82.1.json",
		"required L8 cache file",
	} {
		if !strings.Contains(cache, required) {
			t.Errorf("verify-cache.sh missing %q", required)
		}
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
