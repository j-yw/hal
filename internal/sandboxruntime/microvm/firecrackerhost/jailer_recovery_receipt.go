package firecrackerhost

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
)

func (owner *l8RuntimeOwnerSupervisor) commitID(digest [32]byte, revision uint64) (string, error) {
	if owner.opts.CommitID != nil {
		return owner.opts.CommitID(owner.opts.CommitKey, digest, revision)
	}
	return l8RuntimeOwnerCommitID(owner.opts.CommitKey, digest, revision)
}

func jailerRecoveryCommitID(key []byte, configDigest [32]byte, revision uint64) (string, error) {
	if len(key) != 32 || configDigest == ([32]byte{}) || revision == 0 {
		return "", errL8RuntimeOwnerInvalid
	}
	digest := hmac.New(sha256.New, key)
	l8RuntimeOwnerWriteString(digest, "hal/jailer-minimal-owned-cleanup/receipt/v1")
	l8RuntimeOwnerWriteString(digest, jailerRecoveryRecordVersion)
	_, _ = digest.Write(configDigest[:])
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], revision)
	_, _ = digest.Write(number[:])
	return base64.RawURLEncoding.EncodeToString(digest.Sum(nil)), nil
}
