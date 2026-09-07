//go:build linux

package firecrackerhost

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// This reaches actual sealed eight-role admission, retained FD request assembly
// and coordinator validation. The seed-UID observation is the existing ordinary
// fixture's caller UID, not root authority. No runtime constructor, host policy,
// namespace entry, cgroup, process or VM is instantiated by this fixture.
func minimalRuntimeRequestFixture(t *testing.T, consume func(*minimalControlSupervisorAdmission, strictJailerCoordinatorRequest)) {
	t.Helper()
	f := newMinimalControlAdmissionFixture(t)
	// Byte admission does not validate PCI/resource consistency. Make this new
	// fixture agree with its actual FC vsock before sealing, so it cannot hide a
	// second, unrelated failure behind the missing selected NIC handoff.
	f.config.EnablePCI = true
	f.reseal(nil)
	requireMinimalControlFCFixtureValid(t, f)
	code := f.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		projection := admission.request
		selected := &jailerRecoveryRuntime{config: admission.config.jailerRecoverySupervisorConfig, minimalControl: &projection}
		for index, position := range []int{3, 4, 6} {
			borrowed := admission.borrowed[position]
			var before unix.Stat_t
			if unix.Fstat(borrowed, &before) != nil {
				t.Fatal("borrowed asset unavailable inside actual admission")
			}
			duplicate, err := unix.FcntlInt(uintptr(borrowed), unix.F_DUPFD_CLOEXEC, 10)
			if err != nil {
				t.Fatal(err)
			}
			file := os.NewFile(uintptr(duplicate), "minimal-request-asset-test")
			selected.files[index] = file
			defer func() {
				if file.Close() != nil {
					t.Error("owned request duplicate close failed")
				}
				var after unix.Stat_t
				if unix.Fstat(borrowed, &after) != nil || after.Dev != before.Dev || after.Ino != before.Ino {
					t.Error("request duplicate cleanup affected borrowed asset")
				}
			}()
			asset := []jailerRecoveryAsset{selected.config.Kernel, selected.config.Rootfs, selected.config.Config}[index]
			if before.Ino != asset.Inode || uint64(before.Dev) != asset.Device || before.Size != asset.Size ||
				validateL8RuntimeOwnerAssetFD(duplicate, l8RuntimeOwnerDescriptorIdentityV1{Kind: asset.Kind, Device: asset.Device, Inode: asset.Inode, Digest: asset.SHA256}) != nil {
				t.Fatal("request did not retain the actually admitted measured asset")
			}
		}
		request, err := selected.request()
		if err != nil {
			t.Fatalf("actual request assembly failed before coordinator boundary: %v", err)
		}
		if request.minimalControl == nil || *request.minimalControl != projection || request.minimalControl == selected.minimalControl || request.minimalL7 != nil {
			t.Fatal("selected value handoff absent/aliased or fabricated L7 descriptor")
		}
		consume(admission, request)
		return nil
	})
	if code != 0 || f.admissions != 1 || f.legacy != 0 || len(f.closed) != 8 {
		t.Fatalf("actual admission prerequisite/cleanup failed: exit=%d callbacks=%d legacy=%d closes=%d", code, f.admissions, f.legacy, len(f.closed))
	}
}

func TestMinimalRuntimeRequestAcceptsActualAdmittedEightRoleNIC(t *testing.T) {
	minimalRuntimeRequestFixture(t, func(admission *minimalControlSupervisorAdmission, request strictJailerCoordinatorRequest) {
		rendered, err := readStrictJailerConfig(request.config)
		if err != nil || len(rendered.NetworkInterfaces) == 0 || rendered.Vsock == nil || !request.enablePCI {
			t.Fatal("measured NIC/vsock prerequisite absent; selected handoff not reached")
		}
		_, public, err := decodeMinimalControlSupervisorConfig(mustMinimalRuntimeConfigPayload(t, admission))
		if err != nil || validateMinimalControlFirecrackerConfig(rendered, admission.config, public) != nil {
			t.Fatal("existing independent public/FC equality prerequisite rejected")
		}
		// The fixture has passed actual admission, strict measured config parsing,
		// independent public equality and real request assembly. This is the RED:
		// the unchanged coordinator still treats nil legacy minimalL7 as no NIC.
		if err := validateStrictJailerCoordinatorConfig(request); err != nil {
			t.Errorf("actual admitted eight-role NIC rejected at coordinator handoff: %v", err)
		}
	})
}

func TestMinimalRuntimeRequestSnapshotIsIndependentAndValueOnly(t *testing.T) {
	minimalRuntimeRequestFixture(t, func(admission *minimalControlSupervisorAdmission, request strictJailerCoordinatorRequest) {
		before := admission.request
		payload := mustMinimalRuntimeConfigPayload(t, admission)
		if before.configCorrelation != sha256.Sum256(payload) || before.configCorrelation != admission.configDigest ||
			before.configSHA256 != admission.config.Config.SHA256 || before.job != admission.config.Job ||
			before.nic != admission.config.Control.NetworkInterface || before.static != admission.config.Control.StaticNetwork {
			t.Fatal("expectation is not correlated with actual sealed admission")
		}
		if hex.EncodeToString(before.configCorrelation[:]) != admission.recovery.configCorrelation ||
			hex.EncodeToString(before.configCorrelation[:]) == jailerRecoveryConfigDigest(admission.config.jailerRecoverySupervisorConfig) {
			t.Fatal("request projection reused seven-role rather than complete eight-role correlation")
		}
		admission.config.Control.Prelaunch["workerJobId"] = "changed-worker-job"
		admission.config.Control.StaticNetwork[5] = "http://192.0.2.1:3129"
		admission.config.Control.NetworkInterface.HostDeviceName = "changedtap"
		_, public, err := decodeMinimalControlSupervisorConfig(payload)
		changed, changedErr := captureMinimalControlConfigExpectation(admission.config, public, admission.configDigest)
		if err != nil || changedErr != nil || changed.boot == before.boot {
			t.Fatal("independent public boot mutation did not distinguish captured BootConfig")
		}
		admission.config.Job.RuntimeGeneration = "changed-generation"
		admission.config.Config.SHA256 = "changed-digest"
		if admission.request != before || *request.minimalControl != before {
			t.Fatal("mutable callback metadata rewrote captured expectation")
		}
	})
}

func TestMinimalRuntimeRequestLegacySevenWithoutNICStillValid(t *testing.T) {
	owned, _, _, _ := jailerRecoveryRuntimeFixture(t)
	request, err := owned.selected.request()
	if err != nil || owned.selected.config.Version != jailerRecoveryConfigVersion || request.minimalL7 != nil || request.minimalControl != nil {
		t.Fatal("ordinary seven-role request fixture changed")
	}
	rendered, err := readStrictJailerConfig(request.config)
	if err != nil || len(rendered.NetworkInterfaces) != 0 || validateStrictJailerCoordinatorConfig(request) != nil {
		t.Fatal("legacy nil expectation no longer accepts no-NIC request")
	}
}

func TestMinimalRuntimeRequestMissingBothExpectationsStillRejectsNIC(t *testing.T) {
	minimalRuntimeRequestFixture(t, func(_ *minimalControlSupervisorAdmission, request strictJailerCoordinatorRequest) {
		request.minimalControl = nil
		if request.minimalL7 != nil || validateStrictJailerCoordinatorConfig(request) == nil {
			t.Fatal("NIC accepted without either independent expectation")
		}
	})
}

func mustMinimalRuntimeConfigPayload(t *testing.T, admission *minimalControlSupervisorAdmission) []byte {
	t.Helper()
	fd := admission.borrowed[2]
	identity, err := validateL8RuntimeOwnerSealedRegularFD(fd, l8RuntimeOwnerSupervisorConfigLimit)
	if err != nil || identity.Size <= 0 {
		t.Fatal("missing bounded sealed public config")
	}
	payload := make([]byte, identity.Size)
	if n, err := unix.Pread(fd, payload, 0); err != nil || n != len(payload) {
		t.Fatal("read admitted public config")
	}
	return payload
}
