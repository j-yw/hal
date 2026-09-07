//go:build linux

package firecrackerhost

import (
	"bytes"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMinimalControlControllerEntropySingleNonblockingDraw(t *testing.T) {
	for _, test := range []struct {
		name string
		n    int
		err  error
	}{
		{"zero", 0, nil}, {"short", 31, nil}, {"negative", -1, nil},
		{"oversized", 33, nil}, {"interrupted", 0, unix.EINTR},
		{"unavailable", 0, unix.EAGAIN}, {"full-with-error", 32, unix.EINTR},
		{"complete", 32, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			buffer := bytes.Repeat([]byte{0x73}, 32)
			calls := 0
			n, err := readMinimalControllerEntropy(buffer, func(p []byte, flags int) (int, error) {
				calls++
				if len(p) != 32 || flags != unix.GRND_NONBLOCK || &p[0] != &buffer[0] {
					t.Fatal("wrong entropy extent, flags or buffer")
				}
				for i := range p {
					p[i] = 0x45
				}
				return test.n, test.err
			})
			if calls != 1 {
				t.Fatal("entropy draw retried")
			}
			if test.name == "complete" {
				if n != 32 || err != nil || !bytes.Equal(buffer, bytes.Repeat([]byte{0x45}, 32)) {
					t.Fatal("complete entropy draw changed")
				}
			} else if n != 0 || err != errMinimalControlController || !bytes.Equal(buffer, make([]byte, 32)) {
				t.Fatal("unknown entropy completion escaped or retained bytes")
			}
		})
	}
}

func TestMinimalControlControllerEntropyPanicClearsBorrowedBuffer(t *testing.T) {
	buffer := make([]byte, 32)
	marker := &struct{}{}
	calls := 0
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_, _ = readMinimalControllerEntropy(buffer, func(p []byte, flags int) (int, error) {
			calls++
			if len(p) != 32 || flags != unix.GRND_NONBLOCK || &p[0] != &buffer[0] {
				t.Fatal("wrong entropy syscall shape")
			}
			for i := range p {
				p[i] = 0x73
			}
			panic(marker)
		})
	}()
	if recovered != marker || calls != 1 || !bytes.Equal(buffer, make([]byte, 32)) {
		t.Fatal("panic changed, retried, or retained entropy scratch")
	}
}

func TestMinimalControlControllerEntropyExtentRejectsBeforeSyscall(t *testing.T) {
	for _, size := range []int{0, 1, 31, 33, 64} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			buffer := bytes.Repeat([]byte{0x73}, size)
			calls := 0
			n, err := readMinimalControllerEntropy(buffer, func([]byte, int) (int, error) {
				calls++
				return 32, nil
			})
			if calls != 0 || n != 0 || err != errMinimalControlController || !bytes.Equal(buffer, make([]byte, size)) {
				t.Fatal("wrong extent reached syscall or escaped uncleared")
			}
		})
	}
}
