//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMinimalControlSeedProducerRejectsBeforeAllocation(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	for name, ctx := range map[string]context.Context{"nil": nil, "canceled": canceled, "expired": expired} {
		t.Run(name, func(t *testing.T) {
			f := newMinimalSeedProducerFixture(t)
			owner, err := newMinimalControllerSeedWithOps(ctx, uint32(os.Geteuid()), f.ops)
			if owner != nil || err == nil || len(f.calls) != 0 {
				t.Fatal("invalid context reached entropy or allocation")
			}
			if owner, err := newMinimalControllerSeed(ctx); owner != nil || err == nil {
				t.Fatal("production wrapper accepted invalid context")
			}
		})
	}
}

func TestMinimalControlSeedProducerReachedFaultsCloseAndWipe(t *testing.T) {
	for _, tc := range []struct{ name, stage string }{
		{"entropy short", "entropy"}, {"entropy oversized", "entropy"},
		{"entropy error", "entropy"}, {"entropy panic", "entropy"}, {"entropy zero", "entropy"},
		{"create fd plus error", "create"}, {"create panic", "create"},
		{"write short", "write"}, {"write error", "write"}, {"write panic", "write"},
		{"chmod error", "chmod"}, {"seal error", "seal"},
		{"open fd plus error", "open"}, {"open same fd plus error", "open"},
		{"open same fd", "open"}, {"open panic", "open"},
		{"close error", "open"}, {"close panic", "open"},
		{"metadata mode", "open"}, {"metadata cloexec", "open"},
		{"metadata writable", "open"}, {"metadata seals", "open"}, {"metadata size", "open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMinimalSeedProducerFixture(t)
			minimalSeedProducerInstallFault(f, tc.name)
			canary, err := os.Open("/dev/null")
			if err != nil {
				t.Fatal(err)
			}
			defer canary.Close()
			owner, err, panicked := minimalSeedProducerCall(context.Background(), uint32(os.Geteuid()), f.ops)
			if owner != nil {
				_ = owner.close()
			}
			if f.calls[tc.stage] != 1 {
				t.Fatalf("fault stage %s unreached: got %d calls; early rejection is not fault coverage", tc.stage, f.calls[tc.stage])
			}
			if owner != nil || err != errL8RuntimeOwnerInvalid || panicked {
				t.Fatal("reached failure leaked owner, callback error detail or panic")
			}
			if _, err := canary.Stat(); err != nil {
				t.Fatal("seed cleanup closed unrelated borrowed descriptor")
			}
			if f.calls["entropy"] != 1 {
				t.Fatal("failed seed generation redrew entropy")
			}
			if tc.stage != "entropy" && len(f.private) != 64 {
				t.Fatal("later failure did not reach actual derived private allocation")
			}
			f.assertWiped()
			f.assertClosed()
		})
	}
}

func TestMinimalControlSeedProducerCancellationAfterOwnedSteps(t *testing.T) {
	for _, stage := range []string{"entropy", "create", "open"} {
		t.Run(stage, func(t *testing.T) {
			f := newMinimalSeedProducerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch stage {
			case "entropy":
				original := f.ops.entropy
				f.ops.entropy = func(buffer []byte) (int, error) {
					n, err := original(buffer)
					cancel()
					return n, err
				}
			case "create":
				original := f.ops.memfdCreate
				f.ops.memfdCreate = func(name string, flags int) (int, error) {
					fd, err := original(name, flags)
					cancel()
					return fd, err
				}
			case "open":
				original := f.ops.open
				f.ops.open = func(path string, flags int, mode uint32) (int, error) {
					fd, err := original(path, flags, mode)
					cancel()
					return fd, err
				}
			}
			owner, err := newMinimalControllerSeedWithOps(ctx, uint32(os.Geteuid()), f.ops)
			if owner != nil {
				_ = owner.close()
			}
			if f.calls[stage] != 1 {
				t.Fatalf("cancellation stage %s unreached; missing creation is not cancellation coverage", stage)
			}
			if owner != nil || err == nil || f.calls["entropy"] != 1 {
				t.Fatal("canceled seed creation returned authority or retried entropy")
			}
			f.assertWiped()
			f.assertClosed()
		})
	}
}

func minimalSeedProducerCall(ctx context.Context, uid uint32, ops minimalControllerSeedOps) (owner *minimalControllerSeedOwner, err error, panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	owner, err = newMinimalControllerSeedWithOps(ctx, uid, ops)
	return
}

func minimalSeedProducerInstallFault(f *minimalSeedProducerFixture, name string) {
	marker := errors.New("private-callback-detail-must-not-escape")
	switch name {
	case "entropy short", "entropy oversized", "entropy error", "entropy panic", "entropy zero":
		original := f.ops.entropy
		f.ops.entropy = func(buffer []byte) (int, error) {
			n, err := original(buffer)
			switch name {
			case "entropy short":
				return n - 1, nil
			case "entropy oversized":
				return n + 1, nil
			case "entropy error":
				return n, marker
			case "entropy panic":
				panic(marker)
			case "entropy zero":
				clear(buffer)
			}
			return n, err
		}
	case "create fd plus error", "create panic":
		original := f.ops.memfdCreate
		f.ops.memfdCreate = func(nameArg string, flags int) (int, error) {
			if name == "create panic" {
				f.calls["create"]++
				panic(marker) // No unreturned allocation is hidden by this callback.
			}
			fd, err := original(nameArg, flags)
			if err != nil {
				f.t.Fatal(err)
			}
			return fd, marker
		}
	case "write short", "write error", "write panic", "metadata size":
		original := f.ops.write
		f.ops.write = func(fd int, buffer []byte) (int, error) {
			if name == "write short" || name == "metadata size" {
				f.calls["write"]++
				f.write = buffer
				n, err := unix.Write(fd, buffer[:31])
				if name == "metadata size" && err == nil {
					return 32, nil // Synthetic false callback count; real FD remains 31 bytes.
				}
				return n, err
			}
			n, _ := original(fd, buffer)
			if name == "write panic" {
				panic(marker)
			}
			return n, marker
		}
	case "chmod error":
		original := f.ops.chmod
		f.ops.chmod = func(fd int, mode uint32) error { _ = original(fd, mode); return marker }
	case "seal error":
		original := f.ops.fcntl
		f.ops.fcntl = func(fd uintptr, command, value int) (int, error) {
			n, _ := original(fd, command, value)
			return n, marker
		}
	case "metadata seals":
		f.ops.fcntl = func(fd uintptr, command, value int) (int, error) {
			f.calls["seal"]++
			return unix.FcntlInt(fd, command, value & ^unix.F_SEAL_WRITE)
		}
	case "open fd plus error", "open same fd plus error", "open same fd", "open panic", "metadata mode", "metadata cloexec", "metadata writable":
		original := f.ops.open
		f.ops.open = func(path string, flags int, mode uint32) (int, error) {
			if name == "open panic" {
				f.calls["open"]++
				panic(marker)
			}
			if name == "open same fd plus error" || name == "open same fd" || name == "metadata writable" {
				f.calls["open"]++
				for fd := range f.created {
					if name == "open same fd plus error" {
						return fd, marker // Synthetic alias of an already-owned FD.
					}
					if name == "open same fd" {
						return fd, nil
					}
					duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
					f.recordFD(duplicate)
					return duplicate, err // Actual writable description despite mode 0400.
				}
				f.t.Fatal("reopen did not retain its original allocation")
			}
			fd, err := original(path, flags, mode)
			if err != nil {
				f.t.Fatal(err)
			}
			switch name {
			case "open fd plus error":
				return fd, marker
			case "metadata mode":
				if unix.Fchmod(fd, 0o440) != nil {
					f.t.Fatal("could not mutate actual mode")
				}
			case "metadata cloexec":
				if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0); err != nil {
					f.t.Fatal(err)
				}
			}
			return fd, err
		}
	case "close error", "close panic":
		original := f.ops.closeFile
		f.ops.closeFile = func(file *os.File) error {
			_ = original(file)
			if name == "close panic" {
				panic(marker)
			}
			return marker
		}
	default:
		f.t.Fatal("unknown fault case")
	}
}
