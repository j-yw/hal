//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The real admission hands its borrowed directory and scalar snapshot to the
// existing store. No constructor, namespace, real reservation or runtime is used.
func withMinimalRecoveryStore(t *testing.T, test func(*l8RuntimeOwnerLinuxRecordStore, firecrackerRuntimeOwnerRecordV1)) {
	t.Helper()
	f := newMinimalControlAdmissionFixture(t)
	code := f.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		record, _ := jailerRecoveryTestRecord(t)
		digest := sha256.Sum256(f.payload)
		record.SeedCorrelationDigest = hex.EncodeToString(digest[:])
		store := &l8RuntimeOwnerLinuxRecordStore{directoryFD: admission.borrowed[1], bootID: record.HostBootID,
			selected: &jailerRecoveryStore{config: admission.config.jailerRecoverySupervisorConfig, minimal: &admission.recovery}}
		defer func() {
			if store.selected.file != nil {
				_ = store.selected.file.Close()
			}
		}()
		test(store, record)
		return nil
	})
	if code != 0 || f.admissions != 1 || f.legacy != 0 {
		t.Fatal("actual selected admission did not retain ownership through store test")
	}
}

func TestMinimalSupervisorRecoveryRetainedTamperingPoisonsOwner(t *testing.T) {
	for _, mode := range []string{"full-correlation", "reservation-fc-sha", "reservation-uid", "reservation-gid", "reservation-runtime", "zero-projection", "missing-projection", "same-bytes-successor"} {
		t.Run(mode, func(t *testing.T) {
			withMinimalRecoveryStore(t, func(store *l8RuntimeOwnerLinuxRecordStore, record firecrackerRuntimeOwnerRecordV1) {
				ctx := context.Background()
				if _, err := store.CreateGenesis(ctx, record); err != nil {
					t.Fatal(err)
				}
				if strings.HasPrefix(mode, "reservation-") {
					c := store.selected.config
					busy := jailerIdentityRecord{Version: 1, UID: c.Policy.UID, GID: c.Policy.GID, State: "busy",
						RuntimeID: c.Job.RuntimeID, Config: c.Config.SHA256, Nonce: strings.Repeat("a", 64)}
					if _, _, err := store.withLock(ctx, unix.LOCK_EX, func() (firecrackerRuntimeOwnerRecordV1, bool, error) {
						err := store.writeSelectedRecord(record, &busy, false)
						return record, err == nil, err
					}); err != nil {
						t.Fatal(err)
					}
				}
				original, err := io.ReadAll(io.NewSectionReader(store.selected.file, 0, l8RuntimeOwnerRecordLimit+1))
				if err != nil {
					t.Fatal(err)
				}
				var disk jailerRecoveryDiskRecord
				if json.Unmarshal(original, &disk) != nil {
					t.Fatal("read actual selected record")
				}
				var successor *os.File
				switch mode {
				case "full-correlation":
					disk.ConfigCorrelation = store.selected.config.Config.SHA256
				case "reservation-fc-sha":
					disk.Reservation.Config = disk.ConfigCorrelation
				case "reservation-uid":
					disk.Reservation.UID++
				case "reservation-gid":
					disk.Reservation.GID++
				case "reservation-runtime":
					disk.Reservation.RuntimeID = "another-runtime"
				case "zero-projection":
					store.selected.minimal = &minimalControlRecoveryProjection{}
				case "missing-projection":
					store.selected.minimal = nil
				case "same-bytes-successor":
					if unix.Renameat(store.directoryFD, l8RuntimeOwnerRecordName, store.directoryFD, "retained-original") != nil {
						t.Fatal("move original fixture record")
					}
					fd, err := unix.Openat(store.directoryFD, l8RuntimeOwnerRecordName, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
					if err != nil {
						t.Fatal(err)
					}
					successor = os.NewFile(uintptr(fd), "same-uid-successor-fixture")
					defer successor.Close()
					if _, err := successor.Write(original); err != nil {
						t.Fatal(err)
					}
				}
				changed, err := json.Marshal(disk)
				if err != nil || store.selected.file.Truncate(int64(len(changed))) != nil {
					t.Fatal("encode fixture mutation")
				}
				if _, err := store.selected.file.WriteAt(changed, 0); err != nil {
					t.Fatal(err)
				}
				if _, err := store.Load(ctx); err == nil || !store.selected.poisoned {
					t.Fatal("tampered selected record/projection restored authority")
				}
				if store.selected.file.Truncate(int64(len(original))) != nil {
					t.Fatal("restore fixture bytes")
				}
				if _, err := store.selected.file.WriteAt(original, 0); err != nil {
					t.Fatal(err)
				}
				if _, err := store.Load(ctx); err == nil || store.recoveryAuthority().current(ctx, record.RuntimeID, store.selected.config.Config.SHA256) == nil {
					t.Fatal("restored bytes bypassed retained quarantine")
				}
				if successor != nil {
					current, err := openJailerRecoveryRecordFile(store.directoryFD)
					if err != nil {
						t.Fatal(err)
					}
					defer current.Close()
					data, err := io.ReadAll(io.NewSectionReader(current, 0, l8RuntimeOwnerRecordLimit+1))
					if err != nil || !sameJailerRecoveryFile(current, successor) || !bytes.Equal(data, original) {
						t.Fatal("unowned successor bytes or inode changed during failed validation")
					}
				}
				if store.selected.terminal || store.selected.reservation != nil || store.selected.retired {
					t.Fatal("tampering manufactured reservation/cleanup/retirement authority")
				}
			})
		})
	}
}

func TestMinimalSupervisorRecoveryPublicationReadbackCannotPromoteTamperedBytes(t *testing.T) {
	for _, mode := range []string{"record-bytes", "projection-during-publication"} {
		t.Run(mode, func(t *testing.T) {
			withMinimalRecoveryStore(t, func(store *l8RuntimeOwnerLinuxRecordStore, record firecrackerRuntimeOwnerRecordV1) {
				syncs := 0
				store.selected.publication = &jailerRecoveryRecordPublicationOps{rename: renameJailerRecoveryRecord, syncDirectory: func(fd int) error {
					syncs++
					if mode == "projection-during-publication" {
						changed := *store.selected.minimal
						changed.uid++
						store.selected.minimal = &changed
						return unix.Fsync(fd)
					}
					file, err := unix.Openat(fd, l8RuntimeOwnerRecordName, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
					if err != nil {
						t.Fatal(err)
					}
					n, writeErr := unix.Pwrite(file, []byte("!"), 0)
					closeErr := unix.Close(file)
					if n != 1 || writeErr != nil || closeErr != nil {
						t.Fatal("inject actual post-rename readback mutation")
					}
					return unix.Fsync(fd)
				}}
				if _, err := store.CreateGenesis(context.Background(), record); err == nil || syncs != 1 || !store.selected.poisoned || store.selected.file != nil {
					t.Fatal("tampered initial readback promoted selected ownership")
				}
				if store.selected.terminal || store.selected.reservation != nil {
					t.Fatal("publication failure issued terminal/lease authority")
				}
			})
		})
	}
}
