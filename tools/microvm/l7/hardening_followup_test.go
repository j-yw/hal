package l7profile

import (
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

func TestL7GuestPrivilegeDropClearsEveryCapabilityPath(t *testing.T) {
	init := readProfileFile(t, "rootfs-overlay/sbin/init")
	for _, marker := range []string{
		"--bounding-set=-all",
		"--inh-caps=-all",
		"--ambient-caps=-all",
		"--securebits=-keep_caps",
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
}
