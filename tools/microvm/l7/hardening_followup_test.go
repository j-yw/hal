package l7profile

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestL7BuildScriptsValidateBoundedPositiveJobs(t *testing.T) {
	for _, path := range []string{"build.sh", "build-in-container.sh"} {
		text := readProfileFile(t, path)
		for _, marker := range []string{"HAL_L7_JOBS", "^[1-9][0-9]*$", "L7_MAX_JOBS", "64"} {
			if !strings.Contains(text, marker) {
				t.Errorf("%s missing bounded jobs validation marker %q", path, marker)
			}
		}
	}
}

func TestL7BuildPreservesL5BootCriticalAndFilesystemGates(t *testing.T) {
	container := readProfileFile(t, "build-in-container.sh")
	for _, marker := range []string{
		"BR2_KERNEL_HEADERS_AS_KERNEL=y",
		"BR2_PACKAGE_HOST_LINUX_HEADERS_CUSTOM_6_1=y",
		"BR2_LINUX_KERNEL_NEEDS_HOST_LIBELF=y",
		"BR2_PACKAGE_UTIL_LINUX=y",
		"BR2_PACKAGE_UTIL_LINUX_SETPRIV=y",
		"CONFIG_HYPERVISOR_GUEST=y",
		"CONFIG_PARAVIRT=y",
		"CONFIG_KVM_GUEST=y",
		"CONFIG_SMP=y",
		"CONFIG_ACPI=y",
		"CONFIG_BLK_MQ_PCI=y",
		"CONFIG_PCI=y",
		"CONFIG_PCI_MMCONFIG=y",
		"CONFIG_PCI_MSI=y",
		"CONFIG_PCIEPORTBUS=y",
		"CONFIG_VIRTIO_PCI=y",
		"CONFIG_X86_MPPARSE",
		"CONFIG_VIRTIO_MMIO",
		"CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES",
		"CONFIG_DEVTMPFS_MOUNT",
		"verify-final-image.sh",
	} {
		if !strings.Contains(container, marker) {
			t.Errorf("build-in-container.sh missing inherited L5 verification marker %q", marker)
		}
	}

	verification := readProfileFile(t, "verify-final-image.sh")
	for _, marker := range []string{
		"/bin/busybox", "0755", "setuid", "setgid", "security.capability",
	} {
		if !strings.Contains(verification, marker) {
			t.Errorf("verify-final-image.sh missing final-image marker %q", marker)
		}
	}
}

func TestL7BuildNormalizesBuildrootExt4AliasBeforeInspection(t *testing.T) {
	container := readProfileFile(t, "build-in-container.sh")
	ordered := []string{
		`rootfs_alias="$buildroot_output/images/rootfs.ext4"`,
		`rootfs_payload="$buildroot_output/images/rootfs.ext2"`,
		`[[ -L "$rootfs_alias" ]]`,
		`[[ "$(readlink -- "$rootfs_alias")" == rootfs.ext2 ]]`,
		`[[ -f "$rootfs_payload" && ! -L "$rootfs_payload" ]]`,
		`install -d -m 0700 -- "$rootfs_stage_dir"`,
		`install -m 0644 -- "$rootfs_payload" "$rootfs_stage"`,
		`[[ -f "$rootfs_stage" && ! -L "$rootfs_stage" ]]`,
		`e2fsck -fn "$rootfs_stage"`,
		`"$profile_root/verify-final-image.sh" "$rootfs_stage"`,
		`install -m 0644 -- "$rootfs_stage" /export/rootfs.ext4`,
		`[[ -f /export/rootfs.ext4 && ! -L /export/rootfs.ext4 ]]`,
	}
	previous := -1
	for _, marker := range ordered {
		index := strings.Index(container, marker)
		if index < 0 {
			t.Fatalf("build-in-container.sh missing rootfs normalization marker %q", marker)
		}
		if index <= previous {
			t.Fatalf("build-in-container.sh marker %q is out of fail-closed order", marker)
		}
		previous = index
	}
	if strings.Contains(container, `"$profile_root/verify-final-image.sh" "$buildroot_output/images/rootfs.ext4"`) {
		t.Fatal("build-in-container.sh passes Buildroot's symlink alias directly to the final-image verifier")
	}
}

func TestL7FinalImageVerifierRejectsSymlinkInput(t *testing.T) {
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

func TestL7GuestPrivilegeDropClearsEveryCapabilityPath(t *testing.T) {
	init := readProfileFile(t, "rootfs-overlay/sbin/init")
	for _, marker := range []string{
		"--bounding-set=-all",
		"--inh-caps=-all",
		"--ambient-caps=-all",
		"--securebits=+keep_caps_locked",
		"--no-new-privs",
		"--reuid 1000",
		"--regid 1000",
	} {
		if !strings.Contains(init, marker) {
			t.Errorf("guest init missing privilege-drop marker %q", marker)
		}
	}
	if strings.Index(init, "--bounding-set=-all") > strings.Index(init, "--reuid 1000") {
		t.Fatal("guest init clears the capability bounding set after the UID transition")
	}
	for _, invalid := range []string{"--securebits=-keep_caps", "+keep_caps,"} {
		if strings.Contains(init, invalid) {
			t.Fatalf("guest init uses invalid keep-caps transition %q", invalid)
		}
	}
}

func TestL7BusyBoxAppletTargetResolverFixtures(t *testing.T) {
	tests := []struct {
		name       string
		applet     string
		target     string
		wantAccept bool
	}{
		{name: "absolute", applet: "/bin/sh", target: "/bin/busybox", wantAccept: true},
		{name: "same directory", applet: "/bin/sh", target: "busybox", wantAccept: true},
		{name: "one parent", applet: "/sbin/ip", target: "../bin/busybox", wantAccept: true},
		{name: "two parents", applet: "/usr/bin/env", target: "../../bin/busybox", wantAccept: true},
		{name: "wrong relative depth", applet: "/usr/bin/env", target: "../bin/busybox"},
		{name: "other absolute", applet: "/bin/sh", target: "/usr/bin/busybox"},
		{name: "traversal elsewhere", applet: "/bin/sh", target: "../../tmp/busybox"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command := exec.Command("bash", "verify-applet-target.sh", tt.applet, tt.target)
			err := command.Run()
			if (err == nil) != tt.wantAccept {
				t.Fatalf("resolver exit error = %v, want accept %t", err, tt.wantAccept)
			}
		})
	}
}
