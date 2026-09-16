//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// The production boundary never accepts a caller-selected UID or entropy source.
func newMinimalControllerSeed(ctx context.Context) (*minimalControllerSeedOwner, error) {
	return newMinimalControllerSeedWithOps(ctx, 0, minimalControllerSeedOps{
		entropy:     minimalControlControllerEntropy{}.Read,
		memfdCreate: unix.MemfdCreate,
		write:       unix.Write,
		chmod:       unix.Fchmod,
		fcntl:       unix.FcntlInt,
		open:        unix.Open,
		closeFile:   (*os.File).Close,
		derive:      ed25519.NewKeyFromSeed,
	})
}

// This lower boundary permits ordinary-UID syscall/retained-allocation tests.
// It is not provider configuration and never replaces actual FD validation.
type minimalControllerSeedOps struct {
	entropy     func([]byte) (int, error)
	memfdCreate func(string, int) (int, error)
	write       func(int, []byte) (int, error)
	chmod       func(int, uint32) error
	fcntl       func(uintptr, int, int) (int, error)
	open        func(string, int, uint32) (int, error)
	closeFile   func(*os.File) error
	derive      func([]byte) ed25519.PrivateKey
}

type minimalControllerSeedOwner struct {
	self      *minimalControllerSeedOwner
	file      *os.File
	public    [ed25519.PublicKeySize]byte
	closeFile func(*os.File) error
	closed    bool
	closeErr  error
}

func newMinimalControllerSeedWithOps(ctx context.Context, expectedUID uint32, ops minimalControllerSeedOps) (owner *minimalControllerSeedOwner, resultErr error) {
	resultErr = errL8RuntimeOwnerInvalid
	var scratch [ed25519.SeedSize]byte
	var private ed25519.PrivateKey
	var files [2]*os.File
	defer func() {
		_ = recover() // No callback panic payload leaves this private boundary.
		clear(scratch[:])
		clear(private[:cap(private)])
		for _, file := range files {
			if file != nil && closeMinimalControllerSeedFile(file, ops.closeFile) != nil {
				resultErr = errL8RuntimeOwnerInvalid
			}
		}
	}()
	if !minimalControllerSeedContextCurrent(ctx) || ops.entropy == nil || ops.memfdCreate == nil || ops.write == nil ||
		ops.chmod == nil || ops.fcntl == nil || ops.open == nil || ops.closeFile == nil || ops.derive == nil {
		return nil, resultErr
	}
	if n, err := ops.entropy(scratch[:]); err != nil || n != len(scratch) || scratch == ([32]byte{}) || !minimalControllerSeedContextCurrent(ctx) {
		return nil, resultErr
	}
	private = ops.derive(scratch[:])
	if len(private) != ed25519.PrivateKeySize || cap(private) != ed25519.PrivateKeySize || !bytes.Equal(private[:ed25519.SeedSize], scratch[:]) || !minimalControllerSeedContextCurrent(ctx) {
		return nil, resultErr
	}
	var public [ed25519.PublicKeySize]byte
	copy(public[:], private[ed25519.SeedSize:])
	clear(private)
	if public == ([ed25519.PublicKeySize]byte{}) {
		return nil, resultErr
	}
	fd, err := ops.memfdCreate("hal-minimal-controller-seed", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if fd >= 0 {
		files[0] = os.NewFile(uintptr(fd), "minimal-controller-seed-writable")
	}
	if err != nil || files[0] == nil || !minimalControllerSeedContextCurrent(ctx) {
		return nil, resultErr
	}
	var original unix.Stat_t
	if unix.Fstat(fd, &original) != nil {
		return nil, resultErr
	}
	if n, err := ops.write(fd, scratch[:]); err != nil || n != len(scratch) || !minimalControllerSeedContextCurrent(ctx) {
		return nil, resultErr
	}
	clear(scratch[:])
	if ops.chmod(fd, 0o400) != nil || !minimalControllerSeedContextCurrent(ctx) {
		return nil, resultErr
	}
	if _, err := ops.fcntl(uintptr(fd), unix.F_ADD_SEALS, l8RuntimeOwnerRequiredSeals); err != nil || !minimalControllerSeedContextCurrent(ctx) {
		return nil, resultErr
	}
	readFD, err := ops.open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if readFD >= 0 && readFD != fd {
		files[1] = os.NewFile(uintptr(readFD), "minimal-controller-seed")
	}
	if err != nil || files[1] == nil || !minimalControllerSeedContextCurrent(ctx) {
		return nil, resultErr
	}
	// Consume each descriptor number before calling close, including failures.
	writable := files[0]
	files[0] = nil
	if closeMinimalControllerSeedFile(writable, ops.closeFile) != nil || !minimalControllerSeedContextCurrent(ctx) {
		return nil, resultErr
	}
	// Validate after the last callback; even the close callback cannot silently
	// substitute the reopened object or change its mutable mode/descriptor flags.
	identity, err := validateL8RuntimeOwnerSealedRegularFD(readFD, ed25519.SeedSize)
	var current unix.Stat_t
	if err != nil || identity.Size != ed25519.SeedSize || unix.Fstat(readFD, &current) != nil ||
		current.Dev != original.Dev || current.Ino != original.Ino || current.Uid != expectedUID || current.Mode&0o7777 != 0o400 || !minimalControllerSeedContextCurrent(ctx) {
		return nil, resultErr
	}
	owner = &minimalControllerSeedOwner{file: files[1], public: public, closeFile: ops.closeFile}
	owner.self = owner
	files[1] = nil
	return owner, nil
}

func minimalControllerSeedContextCurrent(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	deadline, limited := ctx.Deadline()
	return !limited || time.Now().Before(deadline)
}

func closeMinimalControllerSeedFile(file *os.File, closeFile func(*os.File) error) (resultErr error) {
	resultErr = errL8RuntimeOwnerInvalid
	defer func() { _ = recover() }()
	if file == nil || closeFile == nil || closeFile(file) != nil {
		return resultErr
	}
	return nil
}

func (owner *minimalControllerSeedOwner) publicKey() [ed25519.PublicKeySize]byte {
	if owner == nil || owner.self != owner {
		return [ed25519.PublicKeySize]byte{}
	}
	return owner.public
}

// Borrowing is caller-serialized and never transfers or permits closure.
func (owner *minimalControllerSeedOwner) borrowFile() (*os.File, error) {
	if owner == nil || owner.self != owner || owner.closed || owner.file == nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	return owner.file, nil
}

func (owner *minimalControllerSeedOwner) close() error {
	if owner == nil || owner.self != owner {
		return errL8RuntimeOwnerInvalid
	}
	if !owner.closed {
		owner.closed = true
		file := owner.file
		owner.file = nil
		owner.closeErr = closeMinimalControllerSeedFile(file, owner.closeFile)
	}
	return owner.closeErr
}
