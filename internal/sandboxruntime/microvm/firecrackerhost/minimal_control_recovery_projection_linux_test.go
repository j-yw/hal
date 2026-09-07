//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Actual selected byte/seed admission and ordinary same-UID store IO only.
// No root supervisor, real reservation, namespace, controller or VM is started.
func TestMinimalSupervisorRecoveryAdmissionBorrowsExactHandles(t *testing.T) {
	f := newMinimalControlAdmissionFixture(t)
	var expected [7]int
	for i := range expected {
		expected[i] = int(f.files[i].Fd())
	}
	seed := int(f.files[7].Fd())
	var key []byte
	code := f.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		if admission.borrowed != expected {
			t.Errorf("actual validated callback omitted first-six/FD9 handoff: got %v want %v", admission.borrowed, expected)
		}
		for _, fd := range expected {
			flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
			if err != nil || flags&unix.FD_CLOEXEC == 0 {
				t.Fatal("borrowed input was closed or lost CLOEXEC inside admission")
			}
		}
		if _, err := unix.FcntlInt(uintptr(seed), unix.F_GETFD, 0); err != unix.EBADF {
			t.Fatal("consumed seed descriptor remains available to consumer")
		}
		key = admission.controllerKey
		return nil
	})
	if code != 0 || f.admissions != 1 || f.legacy != 0 || len(f.closed) != 8 || !bytes.Equal(key, make([]byte, ed25519.PrivateKeySize)) {
		t.Fatal("selected callback ownership, key wipe or exact close behavior changed")
	}
	for _, fd := range expected {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != unix.EBADF {
			t.Fatal("callback borrow escaped outer ownership cleanup")
		}
	}
}

func TestMinimalSupervisorRecoveryStoreUsesFullEightConfig(t *testing.T) {
	for _, scenario := range []string{"original", "selected-public-change", "decoded-callback-mutation"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMinimalControlAdmissionFixture(t)
			originalFull := sha256.Sum256(f.payload)
			originalFC := f.config.Config.SHA256
			if scenario == "selected-public-change" {
				// The preparation grant is selected-only and does not change FC
				// bytes or pretend to validate guest boot/network consistency.
				f.config.Control.LaunchGrantID = "another-launch-grant"
				f.reseal(nil)
				if sha256.Sum256(f.payload) == originalFull || f.config.Config.SHA256 != originalFC {
					t.Fatal("fixture did not isolate full selected-config correlation")
				}
			}
			full := sha256.Sum256(f.payload)
			expectedDigest := hex.EncodeToString(full[:])
			// This deliberately omits selected fields but NEVER relabels the
			// eight discriminator or roles as seven-role authority.
			incompleteDigest := jailerRecoveryConfigDigest(f.config.jailerRecoverySupervisorConfig)
			if expectedDigest == incompleteDigest || expectedDigest == originalFC {
				t.Fatal("fixture failed to separate the three digest meanings")
			}
			code := f.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
				if admission.configDigest != full || admission.config.Version != minimalControlSupervisorConfigVersion {
					t.Fatal("actual selected byte admission changed the frozen input")
				}
				record, _ := jailerRecoveryTestRecord(t)
				j := f.config.Job
				record.SeedCorrelationDigest = expectedDigest
				record.SandboxID, record.ExecutionID, record.WorkerID = j.SandboxID, j.ExecutionID, j.WorkerID
				record.HostID, record.RuntimeID, record.RuntimeGeneration = j.HostID, j.RuntimeID, j.RuntimeGeneration
				// Use the fixture's actual retained owner directory so missing
				// borrow wiring cannot mask the independent store-validator RED.
				// The projection comes ONLY from actual admission, never test
				// construction of its scalar fields or a supplied digest.
				store := &l8RuntimeOwnerLinuxRecordStore{directoryFD: int(f.files[1].Fd()), bootID: record.HostBootID,
					selected: &jailerRecoveryStore{config: admission.config.jailerRecoverySupervisorConfig, minimal: &admission.recovery}}
				defer func() {
					if store.selected.file != nil {
						_ = store.selected.file.Close()
					}
				}()
				if scenario == "decoded-callback-mutation" {
					admission.config.Control.Prelaunch["runtimeId"] = "changed-decoded-map"
					admission.config.Job.RuntimeID = "changed-decoded-job"
					admission.config.Policy.UID++
					admission.config.Config.SHA256 = strings.Repeat("e", 64)
					admission.configDigest = [32]byte{}
				}
				ctx := context.Background()
				if got, err := store.CreateGenesis(ctx, record); err != nil || got != record {
					t.Fatalf("actual eight-config genesis rejected before record/readback/currentness assertions: %v", err)
				}
				if got, err := store.Load(ctx); err != nil || got != record {
					t.Fatalf("selected retained record readback: %v", err)
				}
				payload, err := io.ReadAll(io.NewSectionReader(store.selected.file, 0, l8RuntimeOwnerRecordLimit+1))
				var disk jailerRecoveryDiskRecord
				if err != nil || json.Unmarshal(payload, &disk) != nil || disk.ConfigCorrelation != expectedDigest || disk.Job != j {
					t.Fatal("record did not bind exact complete eight-config bytes and job")
				}
				if got, err := decodeJailerRecoveryCleanupRecord(payload, j); err != nil || got != record {
					t.Fatalf("cleanup-only record decoder changed: %v", err)
				}
				if _, _, _, err := decodeJailerRecoveryRecord(payload, f.config.jailerRecoverySupervisorConfig); err == nil {
					t.Fatal("eight-role record accepted by seven-only wrapper")
				}
				for _, forbidden := range []string{`"minimalControl"`, `"controllerPublicKey"`, `"prelaunch"`, `"namespace"`, `"borrowed"`} {
					if bytes.Contains(payload, []byte(forbidden)) {
						t.Fatal("private selected inputs entered unchanged record schema")
					}
				}
				authority := store.recoveryAuthority()
				if authority.current(ctx, j.RuntimeID, originalFC) != nil || authority.current(ctx, j.RuntimeID, expectedDigest) == nil ||
					authority.current(ctx, "another-runtime", originalFC) == nil {
					t.Fatal("recovery currentness confused measured FC SHA with supervisor correlation/runtime")
				}
				write := func(next firecrackerRuntimeOwnerRecordV1, busy *jailerIdentityRecord) error {
					_, _, err := store.withLock(ctx, unix.LOCK_EX, func() (firecrackerRuntimeOwnerRecordV1, bool, error) {
						err := store.writeSelectedRecord(next, busy, false)
						return next, err == nil, err
					})
					return err
				}
				for _, digest := range []string{incompleteDigest, originalFC} {
					changed := record
					changed.SeedCorrelationDigest = digest
					if write(changed, nil) == nil {
						t.Fatal("incomplete supervisor or FC-file digest accepted as full eight-config correlation")
					}
				}
				changedJob := record
				changedJob.ExecutionID = "another-execution"
				if write(changedJob, nil) == nil {
					t.Fatal("changed execution accepted")
				}
				busy := jailerIdentityRecord{Version: 1, UID: f.config.Policy.UID, GID: f.config.Policy.GID,
					State: "busy", RuntimeID: j.RuntimeID, Config: originalFC, Nonce: strings.Repeat("a", 64)}
				for _, mutate := range []func(*jailerIdentityRecord){
					func(b *jailerIdentityRecord) { b.Config = expectedDigest },
					func(b *jailerIdentityRecord) { b.UID++ },
					func(b *jailerIdentityRecord) { b.GID++ },
				} {
					wrong := busy
					mutate(&wrong)
					if write(record, &wrong) == nil {
						t.Fatal("uncorrelated reservation metadata accepted")
					}
				}
				// Exercise existing codec/store metadata only, not lease issuance
				// or a terminal cleanup checkpoint from a constructed reservation.
				if err := write(record, &busy); err != nil {
					t.Fatalf("exact FC-correlated reservation metadata rejected: %v", err)
				}
				if got, err := store.Load(ctx); err != nil || got != record || store.selected.terminal || store.selected.reservation != nil {
					t.Fatal("metadata write manufactured cleanup or lease authority")
				}
				frozen := make([]byte, len(f.payload))
				if n, err := unix.Pread(int(f.files[2].Fd()), frozen, 0); err != nil || n != len(frozen) || !bytes.Equal(frozen, f.payload) {
					t.Fatal("selected handoff rewrote or relabeled original eight-config bytes")
				}
				return nil
			})
			if code != 0 || f.admissions != 1 || f.legacy != 0 {
				t.Fatal("selected store test did not complete through actual admission")
			}
		})
	}
}

func TestMinimalSupervisorRecoveryMissingProjectionStaysUnavailable(t *testing.T) {
	for _, absent := range []bool{true, false} {
		f := newMinimalControlAdmissionFixture(t)
		code := f.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
			record, _ := jailerRecoveryTestRecord(t)
			digest := sha256.Sum256(f.payload)
			record.SeedCorrelationDigest = hex.EncodeToString(digest[:])
			store := &l8RuntimeOwnerLinuxRecordStore{directoryFD: int(f.files[1].Fd()), bootID: record.HostBootID,
				selected: &jailerRecoveryStore{config: admission.config.jailerRecoverySupervisorConfig}}
			if !absent {
				store.selected.minimal = &minimalControlRecoveryProjection{}
			}
			if _, err := store.CreateGenesis(context.Background(), record); err == nil || store.selected.file != nil {
				t.Fatal("missing/zero projection entered store or fallback")
			}
			return unavailableMinimalControlSupervisor(admission)
		})
		if code != 127 || f.admissions != 1 || f.legacy != 0 {
			t.Fatal("missing projection bypassed unavailable selected consumer")
		}
	}
}

func TestMinimalSupervisorRecoverySevenRoleBytesRemainExact(t *testing.T) {
	// Locked independently from the unchanged seven codec and fixture at
	// cb45dd6f (byte-identical to the 99b58782 base), before this RED seam.
	const configSHA = "b147e2f5ac46dc72104224e2b92d92f7176d751c4755b24053ceb0a22292f7d0"
	const recordSHA = "329cc9ad5b56c7feb62e9b9e027633ada2042d2d18d423b5ad7ff951b1ab05bc"
	record, config := jailerRecoveryTestRecord(t)
	encodedConfig, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configDigest := sha256.Sum256(encodedConfig)
	payload, err := encodeJailerRecoveryRecord(record, config, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	recordDigest := sha256.Sum256(payload)
	if hex.EncodeToString(configDigest[:]) != configSHA || hex.EncodeToString(recordDigest[:]) != recordSHA {
		t.Fatal("seven-role config or full canonical disk bytes changed")
	}
	if got, busy, terminal, err := decodeJailerRecoveryRecord(payload, config); err != nil || got != record || busy != nil || terminal {
		t.Fatal("seven-role wrapper behavior changed")
	}
}
