//go:build linux

package firecrackerhost

import (
	"bytes"
	"crypto/ed25519"

	"golang.org/x/sys/unix"
)

// The selected loader calls this only after owning both additional roles.
// It consumes fd even on rejection; ownership must not close that number again.
func loadMinimalControllerKey(fd int, expectedUID uint32, publicKey ed25519.PublicKey, pread func(int, []byte, int64) (int, error), closeFD func(int) error) (key ed25519.PrivateKey, resultErr error) {
	if closeFD == nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	var scratch [ed25519.SeedSize]byte
	defer clear(scratch[:])
	defer func() {
		if closeFD(fd) != nil {
			resultErr = errL8RuntimeOwnerInvalid
		}
		if resultErr != nil {
			clear(key)
			key = nil
		}
	}()
	var stat unix.Stat_t
	identity, err := validateL8RuntimeOwnerSealedRegularFD(fd, ed25519.SeedSize)
	if err != nil || identity.Size != ed25519.SeedSize || unix.Fstat(fd, &stat) != nil ||
		stat.Uid != expectedUID || stat.Mode&0o7777 != 0o400 || pread == nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, errL8RuntimeOwnerInvalid
	}
	if n, err := pread(fd, scratch[:], 0); err != nil || n != len(scratch) || scratch == ([ed25519.SeedSize]byte{}) {
		return nil, errL8RuntimeOwnerInvalid
	}
	// Seals freeze bytes but do not freeze owner/mode or FD flags. Recheck the
	// same retained object after the sole read, before deriving its key.
	current, err := validateL8RuntimeOwnerSealedRegularFD(fd, ed25519.SeedSize)
	var after unix.Stat_t
	if err != nil || current != identity || unix.Fstat(fd, &after) != nil || after.Uid != stat.Uid || after.Mode != stat.Mode {
		return nil, errL8RuntimeOwnerInvalid
	}
	key = ed25519.NewKeyFromSeed(scratch[:])
	if !bytes.Equal(key[ed25519.SeedSize:], publicKey) {
		return key, errL8RuntimeOwnerInvalid
	}
	return key, nil
}
