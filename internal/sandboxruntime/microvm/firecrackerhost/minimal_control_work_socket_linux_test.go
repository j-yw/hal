//go:build linux

package firecrackerhost

import (
	"bytes"
	"os"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func minimalWorkTestPair(t *testing.T, kind int) [2]int {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, kind|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fds[0]); _ = unix.Close(fds[1]) })
	return fds
}

func TestMinimalWorkReadyEndpointRightsOwnership(t *testing.T) {
	for _, name := range []string{"valid", "legacy", "no-rights", "two-rights", "truncated-rights", "truncated-wire", "bad-magic", "regular", "datagram", "seqpacket", "named", "abstract", "empty-abstract"} {
		t.Run(name, func(t *testing.T) {
			original := minimalWorkTestPair(t, unix.SOCK_SEQPACKET)
			endpoint := minimalWorkTestPair(t, unix.SOCK_STREAM)
			legacy, value := minimalReadinessGolden(t)
			wire, err := encodeMinimalWorkReady(value)
			if err != nil {
				t.Fatal(err)
			}
			rights := []int{endpoint[0]}
			switch name {
			case "legacy":
				wire = legacy
			case "no-rights":
				rights = nil
			case "two-rights":
				rights = append(rights, endpoint[1])
			case "truncated-rights":
				for index := 0; index < 16; index++ {
					rights = append(rights, endpoint[0])
				}
			case "truncated-wire":
				wire = append(wire, bytes.Repeat([]byte{1}, minimalControlReadinessEventMax)...)
			case "bad-magic":
				wire[0] ^= 1
			case "regular":
				file, err := os.CreateTemp(t.TempDir(), "regular")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = file.Close() })
				rights[0] = int(file.Fd())
			case "datagram", "seqpacket":
				kind := unix.SOCK_DGRAM
				if name == "seqpacket" {
					kind = unix.SOCK_SEQPACKET
				}
				other := minimalWorkTestPair(t, kind)
				rights[0] = other[0]
			case "named", "abstract", "empty-abstract":
				address := "@hal-work-test-" + strconv.Itoa(os.Getpid())
				if name == "empty-abstract" {
					address = "@"
				} else if name == "named" {
					directory, err := os.Open(t.TempDir())
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = directory.Close() })
					address = "/proc/self/fd/" + strconv.Itoa(int(directory.Fd())) + "/work.sock"
				}
				if err := unix.Bind(endpoint[0], &unix.SockaddrUnix{Name: address}); err != nil {
					t.Fatal("actual connected endpoint address prerequisite", err)
				}
				if minimalWorkAnonymousAddress(endpoint[0], unix.SYS_GETSOCKNAME) {
					t.Fatal("actual bound address was mistaken for unnamed family-only extent")
				}
			}
			var oob []byte
			if len(rights) != 0 {
				oob = unix.UnixRights(rights...)
			}
			before, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			if n, err := unix.SendmsgN(original[0], wire, oob, nil, unix.MSG_NOSIGNAL); err != nil || n != len(wire) {
				t.Fatal("actual original-channel rights send prerequisite", err)
			}
			got, received, err := receiveMinimalWorkReady(original[1])
			if name == "valid" {
				if err != nil || got != value || received == nil || int(received.Fd()) == endpoint[0] {
					t.Fatal("actual single endpoint ownership not transferred", err)
				}
				var sentIdentity, receivedIdentity unix.Stat_t
				if unix.Fstat(endpoint[0], &sentIdentity) != nil || unix.Fstat(int(received.Fd()), &receivedIdentity) != nil ||
					sentIdentity.Dev != receivedIdentity.Dev || sentIdentity.Ino != receivedIdentity.Ino || !validMinimalWorkEndpoint(received) {
					t.Error("received endpoint is not the same original anonymous socket with CLOEXEC")
				}
				if received.Close() != nil {
					t.Fatal("received endpoint cleanup failed")
				}
			} else if err == nil || received != nil || got != (minimalControlReadinessEventV1{}) {
				if received != nil {
					_ = received.Close()
				}
				t.Fatal("invalid endpoint, rights, extent or discriminator accepted")
			}
			after, err := os.ReadDir("/proc/self/fd")
			if err != nil || len(before) != len(after) {
				t.Fatal("actual rights receive leaked an owned descriptor")
			}
			for _, borrowed := range rights {
				if _, err := unix.FcntlInt(uintptr(borrowed), unix.F_GETFD, 0); err != nil {
					t.Fatal("receiver disposed a borrowed sender descriptor")
				}
			}
		})
	}
}
