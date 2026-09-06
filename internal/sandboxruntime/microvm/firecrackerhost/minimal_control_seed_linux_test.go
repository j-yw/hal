//go:build linux

package firecrackerhost

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMinimalControlSeedActualFDNegatives(t *testing.T) {
	for name, mutate := range map[string]func(*minimalControlAdmissionFixture){
		"missing": func(f *minimalControlAdmissionFixture) { _ = f.files[7].Close(); f.files[7] = nil },
		"wrong public key": func(f *minimalControlAdmissionFixture) {
			f.config.Control.ControllerPublicKey = f.config.Control.BootNonce
			f.reseal(nil)
		},
		"wrong owner": func(f *minimalControlAdmissionFixture) { f.seedUID++ },
		"zero seed": func(f *minimalControlAdmissionFixture) {
			f.replaceSeed(make([]byte, 32), l8RuntimeOwnerRequiredSeals, 0o400, true)
		},
		"31 bytes": func(f *minimalControlAdmissionFixture) {
			f.replaceSeed(bytes.Repeat([]byte{41}, 31), l8RuntimeOwnerRequiredSeals, 0o400, true)
		},
		"33 bytes": func(f *minimalControlAdmissionFixture) {
			f.replaceSeed(bytes.Repeat([]byte{41}, 33), l8RuntimeOwnerRequiredSeals, 0o400, true)
		},
		"writable description": func(f *minimalControlAdmissionFixture) {
			f.replaceSeed(bytes.Repeat([]byte{41}, 32), l8RuntimeOwnerRequiredSeals, 0o400, false)
		},
		"owner writable mode": func(f *minimalControlAdmissionFixture) {
			f.replaceSeed(bytes.Repeat([]byte{41}, 32), l8RuntimeOwnerRequiredSeals, 0o600, true)
		},
		"group readable mode": func(f *minimalControlAdmissionFixture) {
			f.replaceSeed(bytes.Repeat([]byte{41}, 32), l8RuntimeOwnerRequiredSeals, 0o440, true)
		},
		"missing write seal": func(f *minimalControlAdmissionFixture) {
			f.replaceSeed(bytes.Repeat([]byte{41}, 32), l8RuntimeOwnerRequiredSeals & ^unix.F_SEAL_WRITE, 0o400, true)
		},
		"missing grow seal": func(f *minimalControlAdmissionFixture) {
			f.replaceSeed(bytes.Repeat([]byte{41}, 32), l8RuntimeOwnerRequiredSeals & ^unix.F_SEAL_GROW, 0o400, true)
		},
		"missing shrink seal": func(f *minimalControlAdmissionFixture) {
			f.replaceSeed(bytes.Repeat([]byte{41}, 32), l8RuntimeOwnerRequiredSeals & ^unix.F_SEAL_SHRINK, 0o400, true)
		},
		"missing final seal": func(f *minimalControlAdmissionFixture) {
			f.replaceSeed(bytes.Repeat([]byte{41}, 32), l8RuntimeOwnerRequiredSeals & ^unix.F_SEAL_SEAL, 0o400, true)
		},
		"extra seal": func(f *minimalControlAdmissionFixture) {
			f.replaceSeed(bytes.Repeat([]byte{41}, 32), l8RuntimeOwnerRequiredSeals|unix.F_SEAL_FUTURE_WRITE, 0o400, true)
		},
		"linked regular": func(f *minimalControlAdmissionFixture) {
			_ = f.files[7].Close()
			file, err := os.CreateTemp(f.t.TempDir(), "public-test-seed-")
			if err != nil {
				f.t.Fatal(err)
			}
			f.files[7] = file
			if _, err := file.Write(bytes.Repeat([]byte{41}, 32)); err != nil {
				f.t.Fatal(err)
			}
			if file.Chmod(0o400) != nil {
				f.t.Fatal("mode")
			}
			name := file.Name()
			_ = file.Close()
			f.files[7], err = os.Open(name)
			if err != nil {
				f.t.Fatal(err)
			}
		},
		"nonregular": func(f *minimalControlAdmissionFixture) {
			_ = f.files[7].Close()
			file, err := os.Open(f.t.TempDir())
			if err != nil {
				f.t.Fatal(err)
			}
			f.files[7] = file
		},
	} {
		t.Run(name, func(t *testing.T) {
			requireMinimalControlAdmission(t)
			f := newMinimalControlAdmissionFixture(t)
			mutate(f)
			code := f.run("supervise", func(*minimalControlSupervisorAdmission) error { t.Fatal("invalid seed admitted"); return nil })
			if code != 127 || f.legacy != 0 || f.admissions != 0 {
				t.Fatal("invalid seed fell through or produced admission")
			}
		})
	}
}

func (f *minimalControlAdmissionFixture) replaceSeed(payload []byte, seals int, mode uint32, readOnly bool) {
	_ = f.files[7].Close()
	f.files[7] = minimalControlTestMemfd(f.t, payload, seals, mode, readOnly)
}

func TestMinimalControlSeedReadOnceWipesScratchAndCloses(t *testing.T) {
	for _, outcome := range []string{"success", "short read", "read error", "wrong public", "close error", "missing cloexec"} {
		t.Run(outcome, func(t *testing.T) {
			seed := bytes.Repeat([]byte{41}, 32)
			file := minimalControlTestMemfd(t, seed, l8RuntimeOwnerRequiredSeals, 0o400, true)
			t.Cleanup(func() { _ = file.Close() })
			fd := int(file.Fd())
			key := ed25519.NewKeyFromSeed(seed)
			clear(seed)
			defer clear(key)
			public := bytes.Clone(key.Public().(ed25519.PublicKey))
			if outcome == "wrong public" {
				public[0] ^= 1
			}
			if outcome == "missing cloexec" {
				if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0); err != nil {
					t.Fatal(err)
				}
			}
			reads, closes := 0, 0
			var scratch []byte
			got, err := loadMinimalControllerKey(fd, uint32(os.Geteuid()), public, func(actual int, buffer []byte, offset int64) (int, error) {
				reads++
				if actual != fd || offset != 0 || len(buffer) != 32 || cap(buffer) != 32 {
					t.Fatal("seed read is not one exact bounded 32-byte buffer")
				}
				scratch = buffer
				n, err := unix.Pread(actual, buffer, offset)
				if outcome == "short read" {
					return n - 1, nil
				}
				if outcome == "read error" {
					return n, unix.EIO
				}
				return n, err
			}, func(actual int) error {
				closes++
				if actual != fd {
					t.Fatal("closed unrelated FD")
				}
				err := file.Close()
				if outcome == "close error" {
					return unix.EIO
				}
				return err
			})
			defer clear(got)
			wantReads := 1
			if outcome == "missing cloexec" {
				wantReads = 0
			}
			if reads != wantReads || closes != 1 {
				t.Fatalf("seed boundary not exercised: reads=%d closes=%d", reads, closes)
			}
			if scratch != nil && !bytes.Equal(scratch, make([]byte, 32)) {
				t.Fatal("seed scratch not wiped on return")
			}
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				t.Fatal("consumed seed FD still open")
			}
			if outcome == "success" {
				if err != nil || !bytes.Equal(got, key) {
					t.Fatal("valid sealed seed rejected")
				}
			} else if err == nil || len(got) != 0 {
				t.Fatal("failed seed load returned private key")
			}
		})
	}
}
