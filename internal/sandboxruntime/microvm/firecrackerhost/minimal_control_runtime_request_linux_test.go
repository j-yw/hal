//go:build linux

package firecrackerhost

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMinimalRuntimeRequestSelectedExpectationRejectsDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *minimalControlSupervisorAdmission, *strictJailerCoordinatorRequest)
	}{
		{"both-present", func(t *testing.T, _ *minimalControlSupervisorAdmission, r *strictJailerCoordinatorRequest) {
			// A genuinely fixture-issued descriptor, not decoded metadata. The
			// two expectation variants must not compete for acceptance priority.
			r.minimalL7 = minimalL7ConfigTestExpectation(t, "127.0.0.1:43123")
		}},
		{"missing", func(_ *testing.T, _ *minimalControlSupervisorAdmission, r *strictJailerCoordinatorRequest) {
			r.minimalControl = nil
		}},
		{"empty-correlation", func(_ *testing.T, _ *minimalControlSupervisorAdmission, r *strictJailerCoordinatorRequest) {
			r.minimalControl.configCorrelation = [32]byte{}
		}},
		{"expected-runtime", func(_ *testing.T, _ *minimalControlSupervisorAdmission, r *strictJailerCoordinatorRequest) {
			r.minimalControl.job.RuntimeID = "other-runtime"
		}},
		{"actual-runtime", func(_ *testing.T, _ *minimalControlSupervisorAdmission, r *strictJailerCoordinatorRequest) {
			r.runtimeID = "other-runtime"
		}},
		{"expected-config-digest", func(_ *testing.T, _ *minimalControlSupervisorAdmission, r *strictJailerCoordinatorRequest) {
			r.minimalControl.configSHA256 = strings.Repeat("e", 64)
		}},
		{"nic-interface", func(_ *testing.T, _ *minimalControlSupervisorAdmission, r *strictJailerCoordinatorRequest) {
			r.minimalControl.nic.InterfaceID = "net2"
		}},
		{"nic-tap", func(_ *testing.T, _ *minimalControlSupervisorAdmission, r *strictJailerCoordinatorRequest) {
			r.minimalControl.nic.HostDeviceName = "othertap"
		}},
		{"nic-mac", func(_ *testing.T, _ *minimalControlSupervisorAdmission, r *strictJailerCoordinatorRequest) {
			r.minimalControl.nic.GuestMAC = "02:00:00:00:00:02"
		}},
		{"foreign-shared-boot", func(t *testing.T, a *minimalControlSupervisorAdmission, r *strictJailerCoordinatorRequest) {
			// Render an independently valid public boot value, while retaining
			// the exact previously admitted and measured FC bytes.
			config, public, err := decodeMinimalControlSupervisorConfig(mustMinimalRuntimeConfigPayload(t, a))
			if err != nil {
				t.Fatal(err)
			}
			config.Control.Prelaunch["workerJobId"] = "other-worker-job"
			other, err := captureMinimalControlConfigExpectation(config, public, a.configDigest)
			if err != nil || other.boot == r.minimalControl.boot {
				t.Fatal("foreign boot fixture did not produce a distinct valid value")
			}
			r.minimalControl.boot = other.boot
		}},
	}
	for index, key := range minimalL7BootKeys {
		tests = append(tests, struct {
			name   string
			mutate func(*testing.T, *minimalControlSupervisorAdmission, *strictJailerCoordinatorRequest)
		}{key, func(_ *testing.T, _ *minimalControlSupervisorAdmission, r *strictJailerCoordinatorRequest) {
			r.minimalControl.static[index] += "-different"
		}})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			minimalRuntimeRequestFixture(t, func(a *minimalControlSupervisorAdmission, request strictJailerCoordinatorRequest) {
				if validateStrictJailerCoordinatorConfig(request) != nil {
					t.Fatal("valid selected branch not reached; negative not exercised")
				}
				test.mutate(t, a, &request)
				if validateStrictJailerCoordinatorConfig(request) == nil {
					t.Fatal("selected expectation drift accepted")
				}
			})
		})
	}
}

func TestMinimalRuntimeRequestAssemblyRequiresExactSelectedMetadata(t *testing.T) {
	minimalRuntimeRequestFixture(t, func(a *minimalControlSupervisorAdmission, _ strictJailerCoordinatorRequest) {
		projection := a.request
		original := &jailerRecoveryRuntime{config: a.config.jailerRecoverySupervisorConfig, minimalControl: &projection}
		for index, position := range []int{3, 4, 6} {
			fd, err := unix.FcntlInt(uintptr(a.borrowed[position]), unix.F_DUPFD_CLOEXEC, 10)
			if err != nil {
				t.Fatal(err)
			}
			original.files[index] = os.NewFile(uintptr(fd), "minimal-metadata-request-test")
			defer original.files[index].Close()
		}
		if request, err := original.request(); err != nil || validateStrictJailerCoordinatorConfig(request) != nil {
			t.Fatal("exact retained request prerequisite failed")
		}
		for _, test := range []struct {
			name   string
			mutate func(*jailerRecoveryRuntime)
		}{
			{"missing-expectation", func(r *jailerRecoveryRuntime) { r.minimalControl = nil }},
			{"seven-with-selected-expectation", func(r *jailerRecoveryRuntime) { r.config.Version = jailerRecoveryConfigVersion }},
			{"unknown-version", func(r *jailerRecoveryRuntime) { r.config.Version = "unknown" }},
			{"sandbox", func(r *jailerRecoveryRuntime) { r.config.Job.SandboxID = "other-sandbox" }},
			{"execution", func(r *jailerRecoveryRuntime) { r.config.Job.ExecutionID = "other-execution" }},
			{"worker", func(r *jailerRecoveryRuntime) { r.config.Job.WorkerID = "other-worker" }},
			{"host", func(r *jailerRecoveryRuntime) { r.config.Job.HostID = "other-host" }},
			{"runtime", func(r *jailerRecoveryRuntime) { r.config.Job.RuntimeID = "other-runtime" }},
			{"generation", func(r *jailerRecoveryRuntime) { r.config.Job.RuntimeGeneration = "other-generation" }},
			{"config-digest", func(r *jailerRecoveryRuntime) { r.config.Config.SHA256 = strings.Repeat("e", 64) }},
		} {
			t.Run(test.name, func(t *testing.T) {
				candidate := &jailerRecoveryRuntime{config: original.config, minimalControl: original.minimalControl, files: original.files}
				test.mutate(candidate)
				if _, err := candidate.request(); err == nil {
					t.Fatal("mismatched selected metadata reached coordinator request")
				}
			})
		}
	})
}

func TestMinimalRuntimeRequestPreservesStrictChecksAfterSelectedMatch(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *strictJailerCoordinatorRequest)
	}{
		{"kernel-mode", func(_ *testing.T, r *strictJailerCoordinatorRequest) { r.kernel.Mode = 0o600 }},
		{"rootfs-mode", func(_ *testing.T, r *strictJailerCoordinatorRequest) { r.rootfs.Mode = 0o400 }},
		{"config-mode", func(_ *testing.T, r *strictJailerCoordinatorRequest) { r.config.Mode = 0o600 }},
		{"kernel-path", func(_ *testing.T, r *strictJailerCoordinatorRequest) { r.kernel.JailPath = "/wrong-kernel" }},
		{"config-path", func(_ *testing.T, r *strictJailerCoordinatorRequest) { r.config.JailPath = "/wrong-config" }},
		{"missing-support", func(_ *testing.T, r *strictJailerCoordinatorRequest) { r.support = nil }},
		{"pci", func(_ *testing.T, r *strictJailerCoordinatorRequest) { r.enablePCI = false }},
		{"config-bytes", func(_ *testing.T, r *strictJailerCoordinatorRequest) { r.config.Source = bytes.NewReader([]byte("{}")) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			minimalRuntimeRequestFixture(t, func(_ *minimalControlSupervisorAdmission, request strictJailerCoordinatorRequest) {
				if validateStrictJailerCoordinatorConfig(request) != nil {
					t.Fatal("valid selected branch not reached")
				}
				test.mutate(t, &request)
				if validateStrictJailerCoordinatorConfig(request) == nil {
					t.Fatal("selected equality bypassed existing strict check")
				}
			})
		})
	}
}
