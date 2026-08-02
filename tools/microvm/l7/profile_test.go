package l7profile

import (
	"os"
	"strings"
	"testing"
)

func TestL7ImageProfileLocksMinimalNetworkSupport(t *testing.T) {
	linux := readProfileFile(t, "linux.config")
	for _, required := range []string{
		"CONFIG_NET=y", "CONFIG_PACKET=y", "CONFIG_INET=y", "CONFIG_IPV6=y",
		"CONFIG_NETDEVICES=y", "CONFIG_VIRTIO_NET=y", "CONFIG_VSOCKETS=y", "CONFIG_VIRTIO_VSOCKETS=y",
	} {
		if !linePresent(linux, required) {
			t.Errorf("linux.config missing %q", required)
		}
	}
	buildroot := readProfileFile(t, "buildroot.config")
	for _, required := range []string{
		`BR2_SYSTEM_DHCP=""`, `BR2_ROOTFS_OVERLAY="/src/tools/microvm/l7/rootfs-overlay"`,
		`BR2_LINUX_KERNEL_CUSTOM_CONFIG_FILE="/src/tools/microvm/l7/linux.config"`,
		`BR2_PACKAGE_BUSYBOX_CONFIG_FRAGMENT_FILES="/src/tools/microvm/l7/busybox.fragment"`,
	} {
		if !linePresent(buildroot, required) {
			t.Errorf("buildroot.config missing %q", required)
		}
	}
	fragment := readProfileFile(t, "busybox.fragment")
	for _, required := range []string{"CONFIG_IP=y", "CONFIG_NC=y", "CONFIG_WGET=y"} {
		if !linePresent(fragment, required) {
			t.Errorf("busybox.fragment missing %q", required)
		}
	}
}

func TestL7ImageProfileDisablesAutomaticSITInterface(t *testing.T) {
	linux := readProfileFile(t, "linux.config")
	if !linePresent(linux, "CONFIG_IPV6_SIT=n") {
		t.Fatal("linux.config must disable the automatic SIT tunnel interface")
	}

	container := readProfileFile(t, "build-in-container.sh")
	for _, marker := range []string{
		`grep -Fxq 'CONFIG_IPV6_SIT=n' "$profile_root/linux.config"`,
		`grep -Fxq '# CONFIG_IPV6_SIT is not set' "$kernel_config"`,
	} {
		if !strings.Contains(container, marker) {
			t.Fatalf("build-in-container.sh missing SIT interface guard %q", marker)
		}
	}
}

func TestL7ProfileDoesNotAlterL5NoNetworkContract(t *testing.T) {
	l5 := readProfileFile(t, "../l5/linux.config")
	for _, required := range []string{"CONFIG_NET=y", "CONFIG_INET=n", "CONFIG_NETDEVICES=n"} {
		if !linePresent(l5, required) {
			t.Fatalf("L5 linux.config no-network contract missing %q", required)
		}
	}
}

func TestL7ImageProfileLocksRegularEmptyResolverConfiguration(t *testing.T) {
	postBuild := readProfileFile(t, "post-build.sh")
	for _, required := range []string{
		`rm -f -- "$target/etc/resolv.conf"`,
		`install -D -m 0644 /dev/null "$target/etc/resolv.conf"`,
	} {
		if !strings.Contains(postBuild, required) {
			t.Fatalf("post-build.sh missing resolver lock %q", required)
		}
	}
	verify := readProfileFile(t, "verify-final-image.sh")
	for _, required := range []string{
		"require_entry /etc/resolv.conf regular 0644 0 0",
		"grep -Eq 'Size:[[:space:]]+0([[:space:]]|$)'",
	} {
		if !strings.Contains(verify, required) {
			t.Fatalf("verify-final-image.sh missing resolver proof %q", required)
		}
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
