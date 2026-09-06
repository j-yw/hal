//go:build linux

package minimalcontrol

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBootstrapLinuxBootReadRetainsBytesAndRejectsUnsafeSources(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cmdline")
	line := testBootLine(t) + "\n"
	if err := os.WriteFile(path, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readLinuxBootCommandLinePath(context.Background(), path)
	if err != nil || got != line {
		t.Fatalf("immutable boot bytes: error=%v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, dir, fifo, filepath.Join(dir, "missing")} {
		if got, err := readLinuxBootCommandLinePath(context.Background(), path); !errors.Is(err, ErrInvalid) || got != "" {
			t.Fatalf("unsafe boot source accepted: %v", err)
		}
	}
	for _, size := range []int{4096, 4097, 8192} {
		if err := os.WriteFile(path, []byte(strings.Repeat("x", size-1)+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := readLinuxBootCommandLinePath(context.Background(), path)
		if size == 4096 {
			if err != nil || len(got) != size {
				t.Fatalf("4096 including newline: len=%d err=%v", len(got), err)
			}
		} else if !errors.Is(err, ErrInvalid) || got != "" {
			t.Fatalf("oversized source: len=%d err=%v", len(got), err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := readLinuxBootCommandLinePath(ctx, path); !errors.Is(err, context.Canceled) || got != "" {
		t.Fatal("canceled boot read continued")
	}
	if got, err := readLinuxBootCommandLinePath(nil, path); !errors.Is(err, ErrInvalid) || got != "" {
		t.Fatal("nil context accepted")
	}
}

func TestBootstrapEntropyIsOneExactNonblockingCall(t *testing.T) {
	for _, scenario := range []string{"success", "eagain", "eintr", "error", "short", "short-error", "oversize-result", "wrong-request-size"} {
		t.Run(scenario, func(t *testing.T) {
			value := bytes.Repeat([]byte{91}, 32)
			if scenario == "wrong-request-size" {
				value = value[:31]
			}
			calls := 0
			n, err := readBootstrapEntropy(value, func(out []byte, flags int) (int, error) {
				calls++
				if flags != unix.GRND_NONBLOCK || len(out) != 32 {
					t.Fatal("entropy call changed exact nonblocking contract")
				}
				copy(out, bytes.Repeat([]byte{42}, len(out)))
				switch scenario {
				case "eagain":
					return 0, unix.EAGAIN
				case "eintr":
					return 0, unix.EINTR
				case "error":
					return 0, errors.New("private adapter canary")
				case "short":
					return 31, nil
				case "short-error":
					return 31, unix.EAGAIN
				case "oversize-result":
					return 33, nil
				default:
					return len(out), nil
				}
			})
			if scenario == "success" {
				if n != 32 || err != nil || !bytes.Equal(value, bytes.Repeat([]byte{42}, 32)) {
					t.Fatal("successful exact entropy changed")
				}
			} else if n != 0 || err != ErrUnavailable || !bytes.Equal(value, make([]byte, len(value))) {
				t.Fatalf("partial entropy escaped: n=%d error=%v", n, err)
			}
			wantCalls := 1
			if scenario == "wrong-request-size" {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatalf("syscall count=%d, want %d; retry/fallback occurred", calls, wantCalls)
			}
		})
	}
	value := bytes.Repeat([]byte{1}, 32)
	if n, err := readBootstrapEntropy(value, nil); n != 0 || err != ErrUnavailable || !bytes.Equal(value, make([]byte, 32)) {
		t.Fatal("nil entropy dependency accepted")
	}
}
