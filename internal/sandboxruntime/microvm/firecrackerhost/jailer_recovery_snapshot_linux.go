//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

func sealJailerRecoveryBytes(ctx context.Context, payload []byte) (*os.File, error) {
	digest := sha256.Sum256(payload)
	file, _, err := snapshotJailerRecoveryAsset(ctx, "config", bytes.NewReader(payload), int64(len(payload)), hex.EncodeToString(digest[:]), maxStrictJailerConfigBytes)
	return file, err
}

// Hash the copied stream and independently hash the sealed read-only snapshot.
// The producer retains input leases through acknowledgement; this immutable
// output is the cross-process byte authority, not source-path currentness.
func snapshotJailerRecoveryAsset(ctx context.Context, kind string, source io.Reader, size int64, digest string, limit int64) (result *os.File, identity jailerRecoveryAsset, resultErr error) {
	if ctx == nil || ctx.Err() != nil || source == nil || size <= 0 || size > limit || !validJailerStagingDigest(digest) {
		return nil, identity, errL8RuntimeOwnerInvalid
	}
	fd, err := unix.MemfdCreate("jailer-owner-input", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, identity, errL8RuntimeOwnerInvalid
	}
	file := os.NewFile(uintptr(fd), "jailer-owner-input")
	defer file.Close()
	hash := sha256.New()
	buffer := make([]byte, 128<<10)
	remaining := size
	for remaining > 0 {
		if ctx.Err() != nil {
			return nil, identity, errL8RuntimeOwnerInvalid
		}
		n, err := io.ReadFull(source, buffer[:min(int64(len(buffer)), remaining)])
		if err != nil || n <= 0 {
			return nil, identity, errL8RuntimeOwnerInvalid
		}
		if _, err := file.Write(buffer[:n]); err != nil {
			return nil, identity, errL8RuntimeOwnerInvalid
		}
		_, _ = hash.Write(buffer[:n])
		remaining -= int64(n)
	}
	var extra [1]byte
	if n, err := source.Read(extra[:]); n != 0 || err != io.EOF || hex.EncodeToString(hash.Sum(nil)) != digest || ctx.Err() != nil {
		return nil, identity, errL8RuntimeOwnerInvalid
	}
	if file.Chmod(0o400) != nil {
		return nil, identity, errL8RuntimeOwnerInvalid
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, l8RuntimeOwnerRequiredSeals); err != nil {
		return nil, identity, errL8RuntimeOwnerInvalid
	}
	readFD, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, identity, errL8RuntimeOwnerInvalid
	}
	readFile := os.NewFile(uintptr(readFD), "jailer-owner-sealed-input")
	stat, err := validateL8RuntimeOwnerSealedRegularFD(readFD, limit)
	identity = jailerRecoveryAsset{Kind: kind, Device: stat.Device, Inode: stat.Inode, Size: stat.Size, SHA256: digest}
	if err != nil || stat.Size != size || validateL8RuntimeOwnerAssetFD(readFD, l8RuntimeOwnerDescriptorIdentityV1{Kind: kind, Device: stat.Device, Inode: stat.Inode, Digest: digest}) != nil || ctx.Err() != nil {
		_ = readFile.Close()
		return nil, jailerRecoveryAsset{}, errL8RuntimeOwnerInvalid
	}
	return readFile, identity, nil
}
