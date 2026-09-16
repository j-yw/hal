//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMinimalControlSeedProducerUnchangedLoaderControl(t *testing.T) {
	seed := minimalSeedProducerTestSeed()
	defer clear(seed[:])
	key := ed25519.NewKeyFromSeed(seed[:])
	defer clear(key)
	var public [32]byte
	copy(public[:], key[32:])
	file := minimalControlTestMemfd(t, seed[:], l8RuntimeOwnerRequiredSeals, 0o400, true)
	defer file.Close()
	minimalSeedProducerAssertFD(t, int(file.Fd()), uint32(os.Geteuid()))
	minimalSeedProducerRoundTrip(t, file, public, seed)
}

func TestMinimalControlSeedProducerCreatesOwnedSealedSeed(t *testing.T) {
	f := newMinimalSeedProducerFixture(t)
	owner, err := newMinimalControllerSeedWithOps(context.Background(), uint32(os.Geteuid()), f.ops)
	if err != nil || owner == nil {
		t.Fatal("missing seed creation: valid bounded entropy and local memfd did not produce an owner")
	}
	t.Cleanup(func() { _ = owner.close() })
	file, err := owner.borrowFile()
	if err != nil || file == nil {
		t.Fatal("seed owner has no borrowed descriptor")
	}
	fd := int(file.Fd())
	minimalSeedProducerAssertFD(t, fd, uint32(os.Geteuid()))
	minimalSeedProducerRoundTrip(t, file, owner.publicKey(), minimalSeedProducerTestSeed())
	for _, stage := range []string{"entropy", "derive", "create", "write", "chmod", "seal", "open"} {
		if f.calls[stage] != 1 {
			t.Fatalf("stage %s: got %d calls, want one", stage, f.calls[stage])
		}
	}
	f.assertWiped()
	for allocated, count := range f.closes {
		if allocated != fd && count != 1 {
			t.Fatal("writable seed alias was not closed before publication")
		}
	}
	public := owner.publicKey()
	public[0] ^= 1
	if owner.publicKey() == public {
		t.Fatal("public key accessor returned a mutable alias")
	}
	copyOfOwner := *owner
	if _, err := copyOfOwner.borrowFile(); err == nil || copyOfOwner.close() == nil {
		t.Fatal("copied owner obtained descriptor or closure authority")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
		t.Fatal("copied owner closed the original descriptor")
	}
	if owner.close() != nil || owner.close() != nil {
		t.Fatal("owner close was not successful and idempotent")
	}
	if _, err := owner.borrowFile(); err == nil {
		t.Fatal("closed owner still lends its descriptor")
	}
	f.assertClosed()
}

func TestMinimalControlSeedProducerAbsentOwnerCannotBorrow(t *testing.T) {
	for _, owner := range []*minimalControllerSeedOwner{nil, {}} {
		if file, err := owner.borrowFile(); err == nil || file != nil || owner.close() == nil || owner.publicKey() != ([32]byte{}) {
			t.Fatal("absent owner granted access")
		}
	}
}

type minimalSeedProducerFixture struct {
	t       *testing.T
	ops     minimalControllerSeedOps
	calls   map[string]int
	closes  map[int]int
	created map[int]unix.Stat_t
	scratch []byte
	write   []byte
	private ed25519.PrivateKey
}

func newMinimalSeedProducerFixture(t *testing.T) *minimalSeedProducerFixture {
	t.Helper()
	f := &minimalSeedProducerFixture{t: t, calls: make(map[string]int), closes: make(map[int]int), created: make(map[int]unix.Stat_t)}
	f.ops = minimalControllerSeedOps{
		entropy: func(buffer []byte) (int, error) {
			f.calls["entropy"]++
			f.scratch = buffer
			return readMinimalControllerEntropy(buffer, func(actual []byte, flags int) (int, error) {
				if len(actual) != 32 || cap(actual) != 32 || flags != unix.GRND_NONBLOCK {
					t.Fatal("entropy is not a single exact nonblocking draw")
				}
				seed := minimalSeedProducerTestSeed()
				copy(actual, seed[:])
				clear(seed[:])
				return len(actual), nil
			})
		},
		derive: func(seed []byte) ed25519.PrivateKey {
			f.calls["derive"]++
			f.private = ed25519.NewKeyFromSeed(seed)
			return f.private
		},
		memfdCreate: func(name string, flags int) (int, error) {
			f.calls["create"]++
			if flags != unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING {
				t.Fatal("memfd creation omitted fixed flags")
			}
			fd, err := unix.MemfdCreate(name, flags)
			f.recordFD(fd)
			return fd, err
		},
		write: func(fd int, buffer []byte) (int, error) {
			f.calls["write"]++
			f.write = buffer
			if len(buffer) != 32 || cap(buffer) != 32 {
				t.Fatal("seed write is not exactly bounded")
			}
			return unix.Write(fd, buffer)
		},
		chmod: func(fd int, mode uint32) error {
			f.calls["chmod"]++
			if mode != 0o400 {
				t.Fatal("seed mode is not fixed 0400")
			}
			return unix.Fchmod(fd, mode)
		},
		fcntl: func(fd uintptr, command, value int) (int, error) {
			f.calls["seal"]++
			if command != unix.F_ADD_SEALS || value != l8RuntimeOwnerRequiredSeals {
				t.Fatal("seed seal operation differs from exact existing requirement")
			}
			return unix.FcntlInt(fd, command, value)
		},
		open: func(path string, flags int, mode uint32) (int, error) {
			f.calls["open"]++
			if flags != unix.O_RDONLY|unix.O_CLOEXEC || mode != 0 {
				t.Fatal("seed reopen is not read-only CLOEXEC")
			}
			fd, err := unix.Open(path, flags, mode)
			f.recordFD(fd)
			return fd, err
		},
		closeFile: func(file *os.File) error {
			fd := int(file.Fd())
			if _, owned := f.created[fd]; !owned {
				t.Fatal("attempt to close unowned descriptor")
			}
			f.closes[fd]++
			if f.closes[fd] != 1 {
				t.Fatal("descriptor closed more than once")
			}
			return file.Close()
		},
	}
	t.Cleanup(func() {
		for fd, original := range f.created {
			var current unix.Stat_t
			if unix.Fstat(fd, &current) == nil && original.Dev == current.Dev && original.Ino == current.Ino {
				_ = unix.Close(fd)
			}
		}
	})
	return f
}

func (f *minimalSeedProducerFixture) recordFD(fd int) {
	if fd < 0 {
		return
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		f.t.Fatal(err)
	}
	f.created[fd] = stat
	f.closes[fd] = 0
}

func (f *minimalSeedProducerFixture) assertWiped() {
	f.t.Helper()
	for _, retained := range [][]byte{f.scratch, f.write, f.private} {
		if !bytes.Equal(retained, make([]byte, len(retained))) {
			f.t.Fatal("retained secret allocation was not wiped")
		}
	}
}

func (f *minimalSeedProducerFixture) assertClosed() {
	f.t.Helper()
	for fd, count := range f.closes {
		if count != 1 {
			f.t.Fatalf("owned descriptor closure count = %d, want one", count)
		}
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			f.t.Fatal("owned seed descriptor remains open")
		}
	}
}

func minimalSeedProducerTestSeed() (seed [32]byte) {
	for i := range seed {
		seed[i] = byte(i + 41)
	}
	return seed
}

func minimalSeedProducerAssertFD(t *testing.T, fd int, uid uint32) {
	t.Helper()
	identity, err := validateL8RuntimeOwnerSealedRegularFD(fd, 32)
	var stat unix.Stat_t
	flags, flagsErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	access, accessErr := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	seals, sealsErr := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	if err != nil || identity.Size != 32 || unix.Fstat(fd, &stat) != nil || stat.Size != 32 || stat.Uid != uid || stat.Nlink != 0 ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o400 || flagsErr != nil || flags&unix.FD_CLOEXEC == 0 ||
		accessErr != nil || access&unix.O_ACCMODE != unix.O_RDONLY || sealsErr != nil || seals != l8RuntimeOwnerRequiredSeals {
		t.Fatal("actual seed FD violates exact metadata contract")
	}
}

func minimalSeedProducerRoundTrip(t *testing.T, file *os.File, public [32]byte, seed [32]byte) {
	t.Helper()
	defer clear(seed[:])
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	copyFile := os.NewFile(uintptr(fd), "seed-producer-loader-control")
	defer copyFile.Close()
	reads, closes := 0, 0
	var scratch []byte
	key, err := loadMinimalControllerKey(fd, uint32(os.Geteuid()), public[:], func(actual int, buffer []byte, offset int64) (int, error) {
		reads++
		scratch = buffer
		return unix.Pread(actual, buffer, offset)
	}, func(actual int) error {
		closes++
		if actual != fd {
			t.Fatal("loader closed wrong descriptor")
		}
		return copyFile.Close()
	})
	defer clear(key)
	if err != nil || len(key) != 64 || !bytes.Equal(key[:32], seed[:]) || !bytes.Equal(key[32:], public[:]) || reads != 1 || closes != 1 {
		t.Fatal("unchanged real seed loader failed actual seed/public-key correspondence")
	}
	if !bytes.Equal(scratch, make([]byte, 32)) {
		t.Fatal("unchanged loader did not clear its scratch")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatal("unchanged loader retained consumed descriptor")
	}
}
