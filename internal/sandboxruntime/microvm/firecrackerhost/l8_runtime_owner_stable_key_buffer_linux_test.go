//go:build linux

package firecrackerhost

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// Exercise the actual loader and retained allocation without changing old cases.
func TestL8StableKeyBufferFailureHygiene(t *testing.T) {
	for _, scenario := range []string{"success", "first stat invalid", "short read", "read error after partial bytes", "second stat mismatch", "second stat error", "close error after real close"} {
		t.Run(scenario, func(t *testing.T) {
			source, err := os.CreateTemp(t.TempDir(), "stable-key-diagnostic-")
			if err != nil {
				t.Fatal("create ordinary diagnostic input")
			}
			defer source.Close()
			var marker [32]byte
			for i := range marker {
				marker[i] = byte(i + 53)
			}
			defer clear(marker[:])
			if n, err := source.Write(marker[:]); err != nil || n != len(marker) || source.Chmod(0o600) != nil {
				t.Fatal("prepare exact ordinary file")
			}
			fd, err := unix.FcntlInt(source.Fd(), unix.F_DUPFD_CLOEXEC, 0)
			if err != nil {
				t.Fatal("duplicate diagnostic input")
			}
			closed := false
			defer func() {
				if !closed {
					_ = unix.Close(fd)
				}
			}()
			if scenario == "first stat invalid" && unix.Fchmod(fd, 0o640) != nil {
				t.Fatal("prepare real invalid mode")
			}
			actual := realL8RuntimeOwnerKeyFDOps()
			stats, reads, closes := 0, 0, 0
			var retained []byte
			defer func() { clear(retained) }()
			key, err := loadL8RuntimeOwnerStableKeyFD(fd, uint32(os.Geteuid()), l8RuntimeOwnerKeyFDOps{
				Stat: func(got int) (l8RuntimeOwnerKeyIdentity, error) {
					if got != fd {
						t.Fatal("stat used unrelated descriptor")
					}
					stats++
					identity, err := actual.Stat(got)
					if err != nil {
						t.Fatal("actual stat failed unexpectedly")
					}
					if stats == 2 && scenario == "second stat error" {
						return l8RuntimeOwnerKeyIdentity{}, unix.EIO
					}
					return identity, err
				},
				Pread: func(got int, buffer []byte, offset int64) (int, error) {
					if got != fd || len(buffer) != 32 || cap(buffer) != 32 || offset != 0 {
						t.Fatal("actual helper did not use exact bounded read")
					}
					reads++
					retained = buffer
					switch scenario {
					case "short read":
						return actual.Pread(got, buffer[:31], offset)
					case "read error after partial bytes":
						n, err := actual.Pread(got, buffer[:16], offset)
						if err != nil || n != 16 {
							t.Fatal("actual partial read did not reach bytes")
						}
						return n, unix.EIO // Injected error following actual partial read.
					}
					n, err := actual.Pread(got, buffer, offset)
					if scenario == "second stat mismatch" && unix.Fchmod(got, 0o400) != nil {
						t.Fatal("could not mutate actual file metadata")
					}
					return n, err
				},
				Close: func(got int) error {
					if got != fd {
						t.Fatal("close used unrelated descriptor")
					}
					closes++
					closeErr := actual.Close(got)
					closed = true
					if closeErr != nil {
						t.Fatal("actual owned close failed unexpectedly")
					}
					if scenario == "close error after real close" {
						return unix.EIO
					}
					return nil
				},
			})
			defer clear(key)
			_, fdErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
			consumed := errors.Is(fdErr, unix.EBADF)
			nonzero := !bytes.Equal(retained, make([]byte, len(retained)))
			t.Logf("reads=%d stats=%d closes=%d returned_key_length=%d retained_nonzero=%t fd_consumed=%t", reads, stats, closes, len(key), nonzero, consumed)
			if !consumed || closes != 1 {
				t.Fatal("owned descriptor was not consumed exactly once")
			}
			if _, err := source.Stat(); err != nil {
				t.Fatal("borrowed source was closed")
			}
			if scenario == "success" {
				if err != nil || !bytes.Equal(key, marker[:]) || reads != 1 || stats != 2 || len(retained) != 32 || &key[0] != &retained[0] {
					t.Fatal("successful control did not transfer the exact allocation")
				}
				clear(key) // The success caller can and does clear its transferred key.
				if !bytes.Equal(retained, make([]byte, 32)) {
					t.Fatal("success caller clear did not reach the retained allocation")
				}
				return
			}
			if err != errL8RuntimeOwnerInvalid || key != nil {
				t.Fatal("failure did not return the existing sanitized nil-key result")
			}
			wantReads, wantStats := 1, 2
			if scenario == "first stat invalid" {
				wantReads, wantStats = 0, 1
			} else if scenario == "short read" || scenario == "read error after partial bytes" {
				wantStats = 1
			}
			if reads != wantReads || stats != wantStats {
				t.Fatal("targeted failure boundary was not reached")
			}
			if nonzero {
				t.Fatal("confirmed: helper discarded nil result while owned key buffer remained nonzero")
			}
		})
	}
}
