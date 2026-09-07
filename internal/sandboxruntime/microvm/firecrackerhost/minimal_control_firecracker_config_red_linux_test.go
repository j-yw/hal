//go:build linux

package firecrackerhost

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"reflect"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// These are ordinary sealed memfds and an injected expected seed UID. They
// exercise actual eight-role byte admission, not a root supervisor or live L7.
func TestMinimalControlFirecrackerConfigRejectsSealedPublicMismatch(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*minimalControlAdmissionFixture)
	}{
		{"nic-tap", func(f *minimalControlAdmissionFixture) {
			f.config.Control.NetworkInterface.HostDeviceName = "hftapother"
		}},
		{"nic-mac", func(f *minimalControlAdmissionFixture) {
			f.config.Control.NetworkInterface.GuestMAC = "02:00:00:00:00:02"
		}},
		// Both IPv4 endpoints must move together to remain a valid /30 pair.
		{"static-ipv4-pair", func(f *minimalControlAdmissionFixture) {
			f.config.Control.StaticNetwork[1], f.config.Control.StaticNetwork[2] = "192.0.2.6/30", "192.0.2.5"
		}},
		{"static-ipv6-address", func(f *minimalControlAdmissionFixture) { f.config.Control.StaticNetwork[3] = "fd00::3/126" }},
		{"static-ipv6-gateway", func(f *minimalControlAdmissionFixture) { f.config.Control.StaticNetwork[4] = "fd00::3" }},
		{"static-proxy", func(f *minimalControlAdmissionFixture) { f.config.Control.StaticNetwork[5] = "http://192.0.2.1:3129" }},
		{"controller-key-generation", func(f *minimalControlAdmissionFixture) { f.config.Control.ControllerKeyGeneration = "controller-key-2" }},
		{"boot-nonce", func(f *minimalControlAdmissionFixture) {
			nonce := [32]byte{43}
			f.config.Control.BootNonce = base64.RawURLEncoding.EncodeToString(nonce[:])
		}},
		{"controller-public-key-and-matching-seed", func(f *minimalControlAdmissionFixture) {
			// An unmatched seed would already fail admission and hide the gap.
			seed := bytes.Repeat([]byte{51}, ed25519.SeedSize)
			defer clear(seed)
			key := ed25519.NewKeyFromSeed(seed)
			defer clear(key)
			f.config.Control.ControllerPublicKey = base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
			if err := f.files[7].Close(); err != nil {
				f.t.Fatal(err)
			}
			f.files[7] = minimalControlTestMemfd(f.t, seed, l8RuntimeOwnerRequiredSeals, 0o400, true)
		}},
	}
	// All 24 variable members of the exact 25-field tuple are exercised.
	// runtimeDriver is fixed to microvm and has a separate rejection control.
	for _, field := range []string{
		"sandboxId", "executionId", "workerId", "hostId", "runtimeId", "runtimeGeneration",
		"bootGeneration", "imageGeneration", "imageDigest", "workerJobId", "submissionId", "planId", "jobGeneration",
		"admissionGrantId", "admissionRevision", "principalId", "templatePolicyId", "workspacePolicyId", "networkPlanId",
		"policySnapshotId", "proxySessionId", "proxyGenerationId", "topologyGenerationId", "ruleGenerationId",
	} {
		tests = append(tests, struct {
			name   string
			mutate func(*minimalControlAdmissionFixture)
		}{"prelaunch-" + field, func(f *minimalControlAdmissionFixture) {
			value := f.config.Control.Prelaunch[field] + "-other"
			switch field {
			case "sandboxId":
				f.config.Job.SandboxID = value
			case "executionId":
				f.config.Job.ExecutionID = value
			case "workerId":
				f.config.Job.WorkerID = value
			case "hostId":
				f.config.Job.HostID = value
			case "runtimeId":
				f.config.Job.RuntimeID = value
			case "runtimeGeneration":
				f.config.Job.RuntimeGeneration = value
			case "admissionRevision":
				value = "8"
			case "imageDigest":
				// Keep the selected rootfs measurement genuine and correlated;
				// only the separately retained FC bytes remain the old version.
				payload := []byte("independently-measured-other-test-rootfs")
				if err := f.files[4].Close(); err != nil {
					f.t.Fatal(err)
				}
				f.files[4] = minimalControlTestMemfd(f.t, payload, l8RuntimeOwnerRequiredSeals, 0o400, true)
				f.config.Rootfs = minimalControlTestMeasuredAsset(f.t, f.files[4], "rootfs", payload)
				value = "sha256-" + f.config.Rootfs.SHA256
			}
			f.config.Control.Prelaunch[field] = value
		}})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newMinimalControlAdmissionFixture(t)
			originalFC, originalAsset := minimalControlFCFixtureBytes(t, f), f.config.Config
			test.mutate(f)
			f.reseal(nil)
			requireMinimalControlFCFixtureValid(t, f)
			if f.config.Config != originalAsset || !bytes.Equal(minimalControlFCFixtureBytes(t, f), originalFC) {
				t.Fatal("mismatch fixture changed the independently measured Firecracker config")
			}
			code := f.run("supervise", func(*minimalControlSupervisorAdmission) error { return nil })
			if code != 127 || f.admissions != 0 || f.legacy != 0 {
				t.Errorf("sealed public mismatch reached admission: exit=%d callbacks=%d legacy=%d", code, f.admissions, f.legacy)
			}
			if len(f.closed) != 8 || !slices.Equal(f.opened, []uintptr{3, 4, 5, 6, 7, 8, 9, 10}) {
				t.Errorf("eight-role ownership changed: imports=%v closes=%d", f.opened, len(f.closed))
			}
		})
	}
}

func TestMinimalControlFirecrackerConfigMatchingAdmission(t *testing.T) {
	f := newMinimalControlAdmissionFixture(t)
	requireMinimalControlFCFixtureValid(t, f)
	payload, fc := bytes.Clone(f.payload), minimalControlFCFixtureBytes(t, f)
	if _, err := unix.Seek(int(f.files[6].Fd()), 7, 0); err != nil {
		t.Fatal(err)
	}
	code := f.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		if !reflect.DeepEqual(admission.config, f.config) || !bytes.Equal(f.payload, payload) || !bytes.Equal(minimalControlFCFixtureBytes(t, f), fc) {
			t.Error("matching admission mutated its independently sealed inputs")
		}
		if offset, err := unix.Seek(int(f.files[6].Fd()), 0, 1); err != nil || offset != 7 {
			t.Error("admission changed the borrowed config descriptor offset")
		}
		return nil
	})
	if code != 0 || f.admissions != 1 || f.legacy != 0 || len(f.closed) != 8 {
		t.Fatalf("matching eight-role fixture failed: exit=%d callbacks=%d legacy=%d closes=%d", code, f.admissions, f.legacy, len(f.closed))
	}
}

func TestMinimalControlFirecrackerConfigFixedProfileControls(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*minimalControlAdmissionFixture)
	}{
		{"runtime-driver", func(f *minimalControlAdmissionFixture) { f.config.Control.Prelaunch["runtimeDriver"] = "other" }},
		{"interface-id", func(f *minimalControlAdmissionFixture) { f.config.Control.NetworkInterface.InterfaceID = "net2" }},
		{"guest-interface", func(f *minimalControlAdmissionFixture) { f.config.Control.StaticNetwork[0] = "eth1" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newMinimalControlAdmissionFixture(t)
			test.mutate(f)
			f.reseal(nil)
			if _, _, err := decodeMinimalControlSupervisorConfig(f.payload); err == nil {
				t.Fatal("existing fixed-profile decoder accepted invalid input")
			}
			if code := f.run("supervise", func(*minimalControlSupervisorAdmission) error { return nil }); code != 127 || f.admissions != 0 || f.legacy != 0 {
				t.Fatal("fixed-profile rejection fell back or reached admission")
			}
		})
	}
}

func minimalControlFCFixtureBytes(t *testing.T, f *minimalControlAdmissionFixture) []byte {
	t.Helper()
	if f.config.Config.Size <= 0 || f.config.Config.Size > maxStrictJailerConfigBytes {
		t.Fatal("unbounded fixture config")
	}
	payload := make([]byte, f.config.Config.Size)
	if n, err := unix.Pread(int(f.files[6].Fd()), payload, 0); err != nil || n != len(payload) {
		t.Fatal("read retained fixture config")
	}
	return payload
}

func requireMinimalControlFCFixtureValid(t *testing.T, f *minimalControlAdmissionFixture) {
	t.Helper()
	config, public, err := decodeMinimalControlSupervisorConfig(f.payload)
	if err != nil || !reflect.DeepEqual(config, f.config) {
		t.Fatal("pure config prerequisite rejected fixture; mismatch regression not reached")
	}
	for index, asset := range []jailerRecoveryAsset{config.Kernel, config.Rootfs, config.Config} {
		fd := int(f.files[[]int{3, 4, 6}[index]].Fd())
		actual, err := validateL8RuntimeOwnerSealedRegularFD(fd, asset.Size)
		if err != nil || actual.Size != asset.Size || validateL8RuntimeOwnerAssetFD(fd, l8RuntimeOwnerDescriptorIdentityV1{Kind: asset.Kind, Device: asset.Device, Inode: asset.Inode, Digest: asset.SHA256}) != nil {
			t.Fatal("sealed asset prerequisite rejected fixture; mismatch regression not reached")
		}
	}
	fc := minimalControlFCFixtureBytes(t, f)
	if _, err := readStrictJailerConfig(jailerStagingResourceInput{Source: bytes.NewReader(fc), SizeBytes: int64(len(fc)), SHA256: config.Config.SHA256}); err != nil {
		t.Fatal("existing strict config parser rejected fixture; mismatch regression not reached")
	}
	// Validate a duplicate with the actual consuming loader, leaving the
	// original seed descriptor intact for the real admission call below.
	duplicate, err := unix.FcntlInt(f.files[7].Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	key, err := loadMinimalControllerKey(duplicate, f.seedUID, public, unix.Pread, unix.Close)
	defer clear(key)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		t.Fatal("actual seed loader rejected fixture; mismatch regression not reached")
	}
}
