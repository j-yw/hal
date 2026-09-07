//go:build linux

package firecrackerhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// These ordinary-file tests exercise the actual below-root admission validator,
// not the runtime constructor. The separate tagged fixture supplies real
// namespace-root constructor coverage without substituting an owner observer.
func TestMinimalRuntimeAssemblyAdmissionBinding(t *testing.T) {
	cases := []struct {
		name   string
		change func(*minimalControlSupervisorAdmission)
	}{
		{"callback_map", func(a *minimalControlSupervisorAdmission) { a.config.Control.Prelaunch["workerJobId"] = "changed" }},
		{"callback_version", func(a *minimalControlSupervisorAdmission) { a.config.Version = jailerRecoveryConfigVersion }},
		{"callback_roles", func(a *minimalControlSupervisorAdmission) { a.config.Roles = a.config.Roles[:7] }},
		{"callback_uid", func(a *minimalControlSupervisorAdmission) { a.config.Policy.UID++ }},
		{"callback_gid", func(a *minimalControlSupervisorAdmission) { a.config.Policy.GID++ }},
		{"callback_fc_digest", func(a *minimalControlSupervisorAdmission) { a.config.Config.SHA256 = strings.Repeat("a", 64) }},
		{"callback_deadline", func(a *minimalControlSupervisorAdmission) { a.config.Control.PreparationDeadlineUnixNano++ }},
		{"full_digest", func(a *minimalControlSupervisorAdmission) { a.configDigest[0] ^= 1 }},
		{"coherent_copied_correlations", func(a *minimalControlSupervisorAdmission) {
			a.configDigest[0] ^= 1
			a.recovery.configCorrelation = hex.EncodeToString(a.configDigest[:])
			a.namespace.configCorrelation = a.recovery.configCorrelation
			a.request.configCorrelation = a.configDigest
		}},
		{"recovery_seven_digest", func(a *minimalControlSupervisorAdmission) {
			a.recovery.configCorrelation = jailerRecoveryConfigDigest(a.config.jailerRecoverySupervisorConfig)
		}},
		{"recovery_uid", func(a *minimalControlSupervisorAdmission) { a.recovery.uid++ }},
		{"recovery_gid", func(a *minimalControlSupervisorAdmission) { a.recovery.gid++ }},
		{"recovery_fc_digest", func(a *minimalControlSupervisorAdmission) {
			a.recovery.firecrackerConfigSHA256 = strings.Repeat("a", 64)
		}},
		{"namespace_correlation", func(a *minimalControlSupervisorAdmission) { a.namespace.configCorrelation = strings.Repeat("a", 64) }},
		{"namespace_tuple", func(a *minimalControlSupervisorAdmission) { a.namespace.namespaces.NetworkInode++ }},
		{"request_correlation", func(a *minimalControlSupervisorAdmission) { a.request.configCorrelation[0] ^= 1 }},
		{"request_fc_digest", func(a *minimalControlSupervisorAdmission) { a.request.configSHA256 = strings.Repeat("a", 64) }},
		{"request_nic", func(a *minimalControlSupervisorAdmission) { a.request.nic.HostDeviceName = "changed" }},
		{"request_static", func(a *minimalControlSupervisorAdmission) { a.request.static[5] = "http://192.0.2.1:3999" }},
		{"key_extent", func(a *minimalControlSupervisorAdmission) { a.controllerKey = a.controllerKey[:31] }},
		{"key_seed", func(a *minimalControlSupervisorAdmission) { a.controllerKey[0] ^= 1 }},
		{"key_public", func(a *minimalControlSupervisorAdmission) { a.controllerKey[63] ^= 1 }},
		{"key_cleared", func(a *minimalControlSupervisorAdmission) { clear(a.controllerKey) }},
	}
	for _, field := range []string{"sandbox", "execution", "worker", "host", "runtime", "generation"} {
		for _, origin := range []string{"callback", "recovery", "request"} {
			cases = append(cases, struct {
				name   string
				change func(*minimalControlSupervisorAdmission)
			}{origin + "_job_" + field, func(a *minimalControlSupervisorAdmission) {
				job := &a.config.Job
				if origin == "recovery" {
					job = &a.recovery.job
				}
				if origin == "request" {
					job = &a.request.job
				}
				switch field {
				case "sandbox":
					job.SandboxID = "changed"
				case "execution":
					job.ExecutionID = "changed"
				case "worker":
					job.WorkerID = "changed"
				case "host":
					job.HostID = "changed"
				case "runtime":
					job.RuntimeID = "changed"
				case "generation":
					job.RuntimeGeneration = "changed"
				}
			}})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newMinimalControlAdmissionFixture(t)
			code := f.run("supervise", func(a *minimalControlSupervisorAdmission) error {
				if _, err := validateMinimalControlRuntimeAdmission(a); err != nil {
					t.Fatal("positive admission prerequisite", err)
				}
				tc.change(a)
				if _, err := validateMinimalControlRuntimeAdmission(a); err == nil {
					t.Fatal("changed callback/projection/key accepted against original sealed bytes")
				}
				return nil
			})
			if code != 0 || f.admissions != 1 || f.legacy != 0 {
				t.Fatal("ordinary admission/cleanup prerequisite")
			}
		})
	}
}

func TestMinimalRuntimeAssemblySealedConfigReadback(t *testing.T) {
	for _, scenario := range []string{"replaced_measured_config", "noncanonical", "legacy_version", "zero", "overlimit", "missing_seals", "closed", "aliased"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMinimalControlAdmissionFixture(t)
			code := f.run("supervise", func(a *minimalControlSupervisorAdmission) error {
				if _, err := validateMinimalControlRuntimeAdmission(a); err != nil {
					t.Fatal("positive validator prerequisite", err)
				}
				payload := bytes.Clone(f.payload)
				seals := l8RuntimeOwnerRequiredSeals
				switch scenario {
				case "replaced_measured_config":
					payload = bytes.Replace(payload, []byte(`"launch-grant-1"`), []byte(`"launch-grant-2"`), 1)
				case "noncanonical":
					payload = append(payload, '\n')
				case "legacy_version":
					payload = bytes.Replace(payload, []byte(minimalControlSupervisorConfigVersion), []byte(jailerRecoveryConfigVersion), 1)
				case "zero":
					payload = nil
				case "overlimit":
					payload = bytes.Repeat([]byte{' '}, l8RuntimeOwnerSupervisorConfigLimit+1)
				case "missing_seals":
					seals = 0
				}
				file := minimalControlTestMemfd(t, payload, seals, 0o400, true)
				defer file.Close()
				a.borrowed[2] = int(file.Fd())
				if scenario != "replaced_measured_config" {
					a.configDigest = sha256.Sum256(payload)
				}
				if scenario == "closed" {
					if err := file.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "aliased" {
					a.borrowed[2] = a.borrowed[3]
				}
				if _, err := validateMinimalControlRuntimeAdmission(a); err == nil {
					t.Fatal("untrusted config readback accepted")
				}
				return nil
			})
			if code != 0 || f.admissions != 1 {
				t.Fatal("actual admission/cleanup prerequisite")
			}
		})
	}
}

func TestMinimalRuntimeAssemblyValidationDoesNotTransferBorrowedFDs(t *testing.T) {
	f := newMinimalControlAdmissionFixture(t)
	code := f.run("supervise", func(a *minimalControlSupervisorAdmission) error {
		original := bytes.Clone(a.controllerKey)
		for i := 0; i < 2; i++ {
			if _, err := validateMinimalControlRuntimeAdmission(a); err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(a.controllerKey, original) {
			t.Fatal("validation consumed borrowed signing key")
		}
		for _, fd := range a.borrowed {
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
				t.Fatal("validation closed borrowed descriptor")
			}
		}
		entries, err := os.ReadDir(f.files[1].Name())
		if err != nil || len(entries) != 0 {
			t.Fatal("validation allocated owner state")
		}
		return nil
	})
	if code != 0 || f.admissions != 1 {
		t.Fatal("actual admission/cleanup prerequisite")
	}
}
