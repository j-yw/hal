//go:build linux

package firecrackerhost

import (
	"context"
	"crypto/ed25519"
	"os"

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

// Compiling RED checkpoint: no producer creates or publishes seed authority yet.
func newMinimalControllerSeedWithOps(context.Context, uint32, minimalControllerSeedOps) (*minimalControllerSeedOwner, error) {
	return nil, errL8RuntimeOwnerInvalid
}

func (*minimalControllerSeedOwner) publicKey() [ed25519.PublicKeySize]byte {
	return [ed25519.PublicKeySize]byte{}
}

func (*minimalControllerSeedOwner) borrowFile() (*os.File, error) {
	return nil, errL8RuntimeOwnerInvalid
}

func (*minimalControllerSeedOwner) close() error {
	return errL8RuntimeOwnerInvalid
}
