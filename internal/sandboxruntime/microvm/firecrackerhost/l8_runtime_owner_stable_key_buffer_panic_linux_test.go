//go:build linux

package firecrackerhost

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestL8StableKeyBufferPanicUnwindsWithoutChangingPropagation(t *testing.T) {
	for _, phase := range []string{"first stat", "read", "second stat", "close before syscall", "close after syscall"} {
		t.Run(phase, func(t *testing.T) {
			source, err := os.CreateTemp(t.TempDir(), "stable-key-panic-control-")
			if err != nil {
				t.Fatal("create ordinary input")
			}
			defer source.Close()
			var marker [32]byte
			for i := range marker {
				marker[i] = byte(i + 53)
			}
			defer clear(marker[:])
			if n, err := source.Write(marker[:]); err != nil || n != len(marker) || source.Chmod(0o600) != nil {
				t.Fatal("prepare exact ordinary input")
			}
			fd, err := unix.FcntlInt(source.Fd(), unix.F_DUPFD_CLOEXEC, 0)
			if err != nil {
				t.Fatal("duplicate input")
			}
			closed := false
			defer func() {
				if !closed {
					_ = unix.Close(fd)
				}
			}()
			actual := realL8RuntimeOwnerKeyFDOps()
			stats, reads, closes := 0, 0, 0
			var retained []byte
			defer func() { clear(retained) }()
			panicMarker := errors.New("fixed-stable-key-callback-panic")
			var propagated any
			func() {
				defer func() { propagated = recover() }()
				key, err := loadL8RuntimeOwnerStableKeyFD(fd, uint32(os.Geteuid()), l8RuntimeOwnerKeyFDOps{
					Stat: func(got int) (l8RuntimeOwnerKeyIdentity, error) {
						stats++
						identity, err := actual.Stat(got)
						if got != fd || err != nil {
							t.Fatal("actual stat boundary failed")
						}
						if phase == "first stat" || stats == 2 && phase == "second stat" {
							panic(panicMarker)
						}
						return identity, nil
					},
					Pread: func(got int, buffer []byte, offset int64) (int, error) {
						reads++
						retained = buffer
						n, err := actual.Pread(got, buffer, offset)
						if got != fd || offset != 0 || len(buffer) != 32 || cap(buffer) != 32 || n != 32 || err != nil {
							t.Fatal("actual key read was not reached")
						}
						if phase == "read" {
							panic(panicMarker)
						}
						return n, nil
					},
					Close: func(got int) error {
						closes++
						if got != fd {
							t.Fatal("close on unrelated descriptor")
						}
						if phase == "close before syscall" {
							panic(panicMarker) // Preserve existing one-attempt raw-FD semantics.
						}
						if err := actual.Close(got); err != nil {
							t.Fatal("actual close failed")
						}
						closed = true
						if phase == "close after syscall" {
							panic(panicMarker)
						}
						return nil
					},
				})
				clear(key)
				_ = err
				t.Fatal("callback panic was swallowed")
			}()
			if propagated != panicMarker || closes != 1 {
				t.Fatal("panic identity or close invocation count changed")
			}
			wantReads, wantStats := 1, 2
			if phase == "first stat" {
				wantReads, wantStats = 0, 1
			} else if phase == "read" {
				wantStats = 1
			}
			if reads != wantReads || stats != wantStats {
				t.Fatal("targeted panic boundary was not reached")
			}
			_, fdErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
			consumed := errors.Is(fdErr, unix.EBADF)
			if consumed != (phase != "close before syscall") {
				t.Fatal("existing descriptor-consumption behavior changed")
			}
			if _, err := source.Stat(); err != nil {
				t.Fatal("borrowed source closed")
			}
			if !bytes.Equal(retained, make([]byte, len(retained))) {
				t.Fatal("propagated panic left the owned key allocation nonzero")
			}
		})
	}
}
