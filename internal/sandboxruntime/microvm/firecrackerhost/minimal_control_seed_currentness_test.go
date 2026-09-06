//go:build linux

package firecrackerhost

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMinimalControlSeedMetadataStillCurrentAfterRead(t *testing.T) {
	seed := bytes.Repeat([]byte{41}, 32)
	file := minimalControlTestMemfd(t, seed, l8RuntimeOwnerRequiredSeals, 0o400, true)
	t.Cleanup(func() { _ = file.Close() })
	key := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	defer clear(key)
	var scratch []byte
	reads, closes := 0, 0
	got, err := loadMinimalControllerKey(int(file.Fd()), uint32(os.Geteuid()), key.Public().(ed25519.PublicKey), func(fd int, buffer []byte, offset int64) (int, error) {
		reads++
		scratch = buffer
		n, err := unix.Pread(fd, buffer, offset)
		// File seals protect bytes, not ownership/permissions. This is an
		// ordinary owner chmod, not a privileged UID change or descriptor swap.
		if unix.Fchmod(fd, 0o444) != nil {
			t.Fatal("change test memfd mode")
		}
		return n, err
	}, func(int) error { closes++; return file.Close() })
	defer clear(got)
	if err == nil || len(got) != 0 {
		t.Fatal("seed admitted after its private metadata changed during read")
	}
	if reads != 1 || closes != 1 || !bytes.Equal(scratch, make([]byte, 32)) {
		t.Fatal("failed currentness did not read/wipe/consume exactly once")
	}
}
