//go:build linux

package firecrackerhost

import "crypto/ed25519"

// RED: the selected loader will call this bounded one-read helper after it
// owns both additional roles. Pread/close are the retained loader operations,
// allowing tests to retain the actual scratch slice without exposing secrets.
func loadMinimalControllerKey(fd int, expectedUID uint32, publicKey ed25519.PublicKey, pread func(int, []byte, int64) (int, error), closeFD func(int) error) (ed25519.PrivateKey, error) {
	return nil, errL8RuntimeOwnerInvalid
}
