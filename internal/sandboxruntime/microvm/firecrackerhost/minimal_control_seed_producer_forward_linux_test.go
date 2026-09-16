//go:build linux

package firecrackerhost

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMinimalControlSeedProducerForwardActualObjectRejection(t *testing.T) {
	for _, name := range []string{"wrong uid", "valid foreign sealed object", "linked object"} {
		t.Run(name, func(t *testing.T) {
			f := newMinimalSeedProducerFixture(t)
			uid := uint32(os.Geteuid())
			var borrowed *os.File
			switch name {
			case "wrong uid":
				uid++
			case "valid foreign sealed object":
				seed := minimalSeedProducerTestSeed()
				defer clear(seed[:])
				borrowed = minimalControlTestMemfd(t, seed[:], l8RuntimeOwnerRequiredSeals, 0o400, true)
				minimalSeedProducerAssertFD(t, int(borrowed.Fd()), uid)
			case "linked object":
				var err error
				borrowed, err = os.CreateTemp(t.TempDir(), "seed-linked-negative-")
				if err != nil {
					t.Fatal(err)
				}
				seed := minimalSeedProducerTestSeed()
				if n, err := borrowed.Write(seed[:]); err != nil || n != len(seed) || borrowed.Chmod(0o400) != nil {
					_ = borrowed.Close()
					t.Fatal("prepare linked object")
				}
				clear(seed[:])
				path := borrowed.Name()
				_ = borrowed.Close()
				borrowed, err = os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			if borrowed != nil {
				defer borrowed.Close()
				f.ops.open = func(string, int, uint32) (int, error) {
					f.calls["open"]++
					fd, err := unix.FcntlInt(borrowed.Fd(), unix.F_DUPFD_CLOEXEC, 0)
					f.recordFD(fd)
					return fd, err
				}
			}
			owner, err := newMinimalControllerSeedWithOps(context.Background(), uid, f.ops)
			if owner != nil {
				_ = owner.close()
			}
			if f.calls["open"] != 1 {
				t.Fatal("actual-object rejection did not reach reopened FD")
			}
			if owner != nil || err != errL8RuntimeOwnerInvalid {
				t.Fatal("actual mismatched object was accepted")
			}
			if borrowed != nil {
				if _, err := borrowed.Stat(); err != nil {
					t.Fatal("creator closed the borrowed source rather than its duplicate")
				}
			}
			f.assertWiped()
			f.assertClosed()
		})
	}
}

func TestMinimalControlSeedProducerForwardMalformedDerivedAllocation(t *testing.T) {
	for _, name := range []string{"nil", "short length", "oversized length", "wrong seed", "zero public"} {
		t.Run(name, func(t *testing.T) {
			f := newMinimalSeedProducerFixture(t)
			original := f.ops.derive
			f.ops.derive = func(seed []byte) ed25519.PrivateKey {
				if name == "nil" {
					f.calls["derive"]++
					return nil
				}
				key := original(seed)
				switch name {
				case "short length":
					return key[:63] // Retained f.private observes the entire allocation.
				case "oversized length":
					larger := make(ed25519.PrivateKey, 65)
					copy(larger, key)
					clear(key)
					larger[64] = 77
					f.private = larger
					return larger
				case "wrong seed":
					key[0] ^= 1
				case "zero public":
					clear(key[32:])
				}
				return key
			}
			owner, err, panicked := minimalSeedProducerCall(context.Background(), uint32(os.Geteuid()), f.ops)
			if owner != nil {
				_ = owner.close()
			}
			if f.calls["derive"] != 1 {
				t.Fatal("malformed derived allocation was not reached")
			}
			if owner != nil || err != errL8RuntimeOwnerInvalid || panicked || f.calls["create"] != 0 {
				t.Fatal("malformed derived allocation escaped or created a descriptor")
			}
			f.assertWiped()
			f.assertClosed()
		})
	}
}

func TestMinimalControlSeedProducerForwardFreshDrawPerOwner(t *testing.T) {
	var publicKeys [2][32]byte
	var identities [2]l8RuntimeOwnerKeyIdentity
	draws := 0
	for i := range publicKeys {
		f := newMinimalSeedProducerFixture(t)
		original := f.ops.entropy
		f.ops.entropy = func(buffer []byte) (int, error) {
			draws++
			n, err := original(buffer)
			buffer[0] += byte(draws)
			return n, err
		}
		owner, err := newMinimalControllerSeedWithOps(context.Background(), uint32(os.Geteuid()), f.ops)
		if err != nil || owner == nil {
			t.Fatal("fresh seed creation missing")
		}
		t.Cleanup(func() { _ = owner.close() })
		file, err := owner.borrowFile()
		if err != nil {
			t.Fatal(err)
		}
		publicKeys[i] = owner.publicKey()
		identities[i], err = validateL8RuntimeOwnerSealedRegularFD(int(file.Fd()), 32)
		if err != nil || f.calls["entropy"] != 1 {
			t.Fatal("fresh owner lacks exact new seed descriptor")
		}
		seed := minimalSeedProducerTestSeed()
		seed[0] += byte(draws)
		minimalSeedProducerRoundTrip(t, file, publicKeys[i], seed)
		clear(seed[:])
		f.assertWiped()
	}
	if draws != 2 || publicKeys[0] == publicKeys[1] || identities[0] == identities[1] {
		t.Fatal("independent creation reused entropy, public key or descriptor")
	}
}

func TestMinimalControlSeedProducerForwardProductionUIDBoundary(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("nonroot rejection requires an ordinary UID; no root admission is exercised")
		return
	}
	owner, err := newMinimalControllerSeed(context.Background())
	if owner != nil {
		_ = owner.close()
	}
	if owner != nil || err != errL8RuntimeOwnerInvalid {
		t.Fatal("production boundary accepted an ordinary-UID seed")
	}
}

func TestMinimalControlSeedProducerForwardOwnerCloseFailureIsConsumed(t *testing.T) {
	for _, name := range []string{"error", "panic"} {
		t.Run(name, func(t *testing.T) {
			f := newMinimalSeedProducerFixture(t)
			original := f.ops.closeFile
			calls := 0
			f.ops.closeFile = func(file *os.File) error {
				calls++
				err := original(file)
				if calls == 1 {
					return err // Writable alias closes normally before publication.
				}
				if name == "panic" {
					panic("private-close-panic-detail")
				}
				return errors.New("private-close-error-detail")
			}
			owner, err := newMinimalControllerSeedWithOps(context.Background(), uint32(os.Geteuid()), f.ops)
			if err != nil || owner == nil {
				t.Fatal("returned-owner close fault is unreached")
			}
			t.Cleanup(func() { _ = owner.close() })
			if owner.close() != errL8RuntimeOwnerInvalid || owner.close() != errL8RuntimeOwnerInvalid || calls != 2 {
				t.Fatal("close failure escaped or retried a consumed descriptor")
			}
			if file, err := owner.borrowFile(); err == nil || file != nil {
				t.Fatal("close failure retained lending authority")
			}
			f.assertWiped()
			f.assertClosed()
		})
	}
}

func TestMinimalControlSeedProducerForwardCancellationAtRemainingSteps(t *testing.T) {
	for _, stage := range []string{"derive", "write", "chmod", "seal", "close"} {
		t.Run(stage, func(t *testing.T) {
			f := newMinimalSeedProducerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reached := 0
			switch stage {
			case "derive":
				original := f.ops.derive
				f.ops.derive = func(seed []byte) ed25519.PrivateKey { key := original(seed); reached++; cancel(); return key }
			case "write":
				original := f.ops.write
				f.ops.write = func(fd int, b []byte) (int, error) { n, err := original(fd, b); reached++; cancel(); return n, err }
			case "chmod":
				original := f.ops.chmod
				f.ops.chmod = func(fd int, mode uint32) error { err := original(fd, mode); reached++; cancel(); return err }
			case "seal":
				original := f.ops.fcntl
				f.ops.fcntl = func(fd uintptr, command, value int) (int, error) {
					n, err := original(fd, command, value)
					reached++
					cancel()
					return n, err
				}
			case "close":
				original := f.ops.closeFile
				f.ops.closeFile = func(file *os.File) error { err := original(file); reached++; cancel(); return err }
			}
			owner, err := newMinimalControllerSeedWithOps(ctx, uint32(os.Geteuid()), f.ops)
			if owner != nil {
				_ = owner.close()
			}
			if reached == 0 {
				t.Fatal("remaining cancellation boundary was not reached")
			}
			if owner != nil || err != errL8RuntimeOwnerInvalid || f.calls["entropy"] != 1 {
				t.Fatal("observed cancellation published seed authority or retried entropy")
			}
			f.assertWiped()
			f.assertClosed()
		})
	}
}

func TestMinimalControlSeedProducerForwardBeforeCloseFailureStillDisposes(t *testing.T) {
	for _, phase := range []string{"partial", "returned owner"} {
		for _, fault := range []string{"error", "panic"} {
			t.Run(phase+"/"+fault, func(t *testing.T) {
				f := newMinimalSeedProducerFixture(t)
				var retained []*os.File
				t.Cleanup(func() {
					for _, file := range retained {
						_ = file.Close()
					}
				})
				calls := 0
				f.ops.closeFile = func(file *os.File) error {
					retained = append(retained, file) // A finalizer cannot hide a missing close.
					calls++
					fd := int(file.Fd())
					if _, owned := f.created[fd]; !owned {
						t.Fatal("close invoked on unowned descriptor")
					}
					f.closes[fd]++
					if phase == "partial" && calls == 1 || phase == "returned owner" && calls == 2 {
						if fault == "panic" {
							panic("private-before-close-panic")
						}
						return errors.New("private-before-close-error")
					}
					return file.Close()
				}
				owner, err := newMinimalControllerSeedWithOps(context.Background(), uint32(os.Geteuid()), f.ops)
				if phase == "partial" {
					if owner != nil || err != errL8RuntimeOwnerInvalid || calls != 2 {
						t.Fatal("partial close fault did not preserve failure and attempt both closes")
					}
				} else {
					if owner == nil || err != nil {
						t.Fatal("returned-owner before-close fault not reached")
					}
					t.Cleanup(func() { _ = owner.close() })
					if owner.close() != errL8RuntimeOwnerInvalid || owner.close() != errL8RuntimeOwnerInvalid || calls != 2 {
						t.Fatal("before-close failure escaped or retried callback")
					}
				}
				f.assertWiped()
				f.assertClosed()
			})
		}
	}
}

func TestMinimalControlSeedProducerForwardAfterCloseFailurePreservesReusedFD(t *testing.T) {
	for _, fault := range []string{"error", "panic"} {
		t.Run(fault, func(t *testing.T) {
			f := newMinimalSeedProducerFixture(t)
			original := f.ops.closeFile
			calls := 0
			var successor *os.File
			f.ops.closeFile = func(file *os.File) error {
				calls++
				fd := int(file.Fd())
				if err := original(file); err != nil || calls == 1 {
					return err
				}
				fresh, err := os.Open("/dev/null")
				if err != nil {
					t.Fatal(err)
				}
				if int(fresh.Fd()) == fd {
					successor = fresh
				} else {
					if err := unix.Dup3(int(fresh.Fd()), fd, unix.O_CLOEXEC); err != nil {
						_ = fresh.Close()
						t.Fatal(err)
					}
					_ = fresh.Close()
					successor = os.NewFile(uintptr(fd), "seed-close-successor")
				}
				t.Cleanup(func() { _ = successor.Close() })
				if fault == "panic" {
					panic("private-after-reuse-close-panic")
				}
				return errors.New("private-after-reuse-close-error")
			}
			owner, err := newMinimalControllerSeedWithOps(context.Background(), uint32(os.Geteuid()), f.ops)
			if owner == nil || err != nil {
				t.Fatal("after-close reuse fault did not reach owner")
			}
			t.Cleanup(func() { _ = owner.close() })
			if owner.close() != errL8RuntimeOwnerInvalid || owner.close() != errL8RuntimeOwnerInvalid || calls != 2 || successor == nil {
				t.Fatal("after-close fault escaped or retried callback")
			}
			if _, err := successor.Stat(); err != nil {
				t.Fatal("cleanup closed a successor reusing the consumed FD number")
			}
			_ = successor.Close()
			f.assertWiped()
			f.assertClosed()
		})
	}
}
