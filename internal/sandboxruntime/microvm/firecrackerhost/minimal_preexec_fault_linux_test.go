//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"golang.org/x/sys/unix"
)

var errMinimalPreexecTestFault = errors.New("private fault credential must not escape")

func minimalPreexecAssertUnavailable(t *testing.T, err error) {
	t.Helper()
	if err != sandboxruntime.ErrMinimalLaunchUnavailable {
		t.Fatal("expected fixed unavailable, without callback details", err)
	}
}

func minimalPreexecFinalizeFixture(t *testing.T, f *minimalPreexecAssemblyFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	receipt, err := f.base.owner.Finalize(ctx)
	minimalPreexecAssertUnavailable(t, err)
	if receipt != (sandboxruntime.MinimalLaunchCleanupReceipt{}) || !f.base.owner.assetsClosed || !f.base.owner.closed || f.base.owner.closeErr != nil {
		t.Fatal("actual owner cleanup lost assets or minted terminal evidence")
	}
	if a := f.base.owner.attempt; a != nil {
		if !a.filesClosed || !a.rollbackComplete || a.closeErr != nil {
			t.Fatal("retained attempt cleanup did not complete", a.filesClosed, a.rollbackComplete, a.closeErr)
		}
		for _, done := range []chan struct{}{a.setupDone, a.contextDone, a.lossDone} {
			if done != nil {
				select {
				case <-done:
				default:
					t.Fatal("owned task not joined")
				}
			}
		}
		for _, file := range []*os.File{a.hostFiles[0], a.hostFiles[1], a.hostFiles[2], a.directory, a.namespace[0], a.namespace[1], a.fcFile, a.configFile} {
			if file != nil {
				if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatal("retained owned FD still open", err)
				}
			}
		}
		if a.seed != nil && (!a.seed.closed || a.seed.closeErr != nil) {
			t.Fatal("seed owner not closed")
		}
	}
	for _, file := range f.base.owner.files {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("original asset remains open", err)
		}
	}
	minimalPreexecAssertBorrowedInputs(t, f.base.inputs)
}

func TestMinimalPreexecRejectsForeignAndCopiedAuthority(t *testing.T) {
	for _, kind := range []string{"nil owner", "copied owner", "copied host", "foreign provider", "changed request", "changed scope", "canceled", "closed owner", "closed host"} {
		t.Run(kind, func(t *testing.T) {
			f := newMinimalPreexecAssemblyFixture(t)
			owner, host := f.base.owner, f.host
			switch kind {
			case "nil owner":
				owner = nil
			case "copied owner":
				copy := *owner
				owner = &copy
			case "copied host":
				// Deliberately copy the whole noncopyable object to exercise
				// its runtime self guard, without a vet copylocks assignment.
				copy := new(minimalPreexecHost)
				reflect.ValueOf(copy).Elem().Set(reflect.ValueOf(host).Elem())
				host = copy
			case "foreign provider":
				other := newMinimalPreexecAssemblyFixture(t)
				host = other.host
			case "changed request":
				owner.request.AdmissionGrantRevision++
				defer func() { owner.request.AdmissionGrantRevision-- }()
			case "changed scope":
				host.association.scope.Revision++
				defer func() { host.association.scope.Revision-- }()
			case "canceled":
				f.base.reservation.Revoke()
			case "closed owner":
				minimalPreexecFinalizeFixture(t, f)
			case "closed host":
				if host.close() != nil {
					t.Fatal("close control")
				}
			}
			minimalPreexecAssertUnavailable(t, owner.prepareMinimalInputsWithOps(host, f.ops))
			if f.base.owner.attempt != nil || f.duplicateCalls.Load() != 0 || f.networkCalls.Load() != 0 {
				t.Fatal("invalid authority reached allocation")
			}
		})
	}
}

func TestMinimalPreexecRetainsActualPartialAllocations(t *testing.T) {
	for _, fault := range []string{"duplicate error", "duplicate alias", "duplicate panic", "network error", "seed error", "seed panic", "first seal error", "second seal error", "second seal panic"} {
		t.Run(fault, func(t *testing.T) {
			f := newMinimalPreexecAssemblyFixture(t)
			var returned *os.File
			baseDuplicate, baseNetwork, baseSeed, baseSeal := f.ops.duplicate, f.ops.network, f.ops.seed, f.ops.seal
			switch fault {
			case "duplicate error", "duplicate alias", "duplicate panic":
				f.ops.duplicate = func(file *os.File) (*os.File, error) {
					if fault == "duplicate panic" && f.duplicateCalls.Load() == 1 {
						panic(errMinimalPreexecTestFault)
					}
					actual, err := baseDuplicate(file)
					if err != nil {
						return actual, err
					}
					if fault == "duplicate alias" {
						_ = actual.Close()
						return file, nil
					}
					if fault == "duplicate error" {
						returned = actual
						return actual, errMinimalPreexecTestFault
					}
					return actual, nil
				}
			case "network error":
				f.ops.network = func(input minimalPreexecHostInputs, identity l7network.Identity, plan networkenforcement.Plan) (*l7network.Coordinator, error) {
					actual, err := baseNetwork(input, identity, plan)
					if err != nil {
						return actual, err
					}
					return actual, errMinimalPreexecTestFault
				}
			case "seed error", "seed panic":
				f.ops.seed = func(ctx context.Context) (*minimalControllerSeedOwner, error) {
					if fault == "seed panic" {
						panic(errMinimalPreexecTestFault)
					}
					actual, err := baseSeed(ctx)
					if err != nil {
						return actual, err
					}
					return actual, errMinimalPreexecTestFault
				}
			default:
				f.ops.seal = func(ctx context.Context, payload []byte) (*os.File, error) {
					if fault == "second seal panic" && f.sealCalls.Load() == 1 {
						panic(errMinimalPreexecTestFault)
					}
					actual, err := baseSeal(ctx, payload)
					if err != nil {
						return actual, err
					}
					if fault == "first seal error" || fault == "second seal error" && f.sealCalls.Load() == 2 {
						returned = actual
						return actual, errMinimalPreexecTestFault
					}
					return actual, nil
				}
			}
			minimalPreexecAssertUnavailable(t, f.base.owner.prepareMinimalInputsWithOps(f.host, f.ops))
			a := f.base.owner.attempt
			if a == nil || a.prepared || a.owner != f.base.owner {
				t.Fatal("lost original partial attempt")
			}
			switch fault {
			case "duplicate error":
				if a.hostFiles[0] != returned || f.duplicateCalls.Load() != 1 {
					t.Fatal("uncaptured actual FD plus error")
				}
			case "duplicate alias":
				if a.hostFiles[0] != nil || f.duplicateCalls.Load() != 1 {
					t.Fatal("borrowed alias became owned")
				}
			case "duplicate panic":
				if a.hostFiles[0] == nil || f.duplicateCalls.Load() != 1 {
					t.Fatal("prior actual FD lost on panic")
				}
			case "network error":
				if a.coordinator == nil || a.prepareStarted || f.networkCalls.Load() != 1 {
					t.Fatal("lost actual returned Coordinator")
				}
			case "seed error":
				if a.seed == nil || f.seedCalls.Load() != 1 || !a.successfulPrepare {
					t.Fatal("lost actual returned seed owner")
				}
			case "seed panic":
				if a.seed != nil || !a.successfulPrepare || a.namespace[1] == nil {
					t.Fatal("did not reach after namespace capture")
				}
			case "first seal error":
				if a.fcFile != returned || f.sealCalls.Load() != 1 {
					t.Fatal("lost first partial seal")
				}
			case "second seal error":
				if a.configFile != returned || a.fcFile == nil || f.sealCalls.Load() != 2 {
					t.Fatal("lost second partial seal")
				}
			case "second seal panic":
				if a.fcFile == nil || f.sealCalls.Load() != 1 || a.configFile != nil {
					t.Fatal("lost earlier seal on later panic")
				}
			}
			minimalPreexecFinalizeFixture(t, f)
			f.seed.assertWiped()
			if returned != nil {
				if _, err := returned.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatal("returned partial FD escaped cleanup")
				}
			}
		})
	}
}

func TestMinimalPreexecRejectsEntropyWithoutRetry(t *testing.T) {
	for _, fault := range []string{"zero", "short", "error", "duplicate"} {
		t.Run(fault, func(t *testing.T) {
			f := newMinimalPreexecAssemblyFixture(t)
			read := f.ops.entropy
			var aliases [][]byte
			f.ops.entropy = func(buffer []byte) (int, error) {
				n, err := read(buffer)
				aliases = append(aliases, buffer)
				if err != nil {
					return n, err
				}
				switch fault {
				case "zero":
					clear(buffer)
				case "short":
					return n - 1, nil
				case "error":
					return n, errMinimalPreexecTestFault
				case "duplicate":
					for i := range buffer {
						buffer[i] = 1
					}
				}
				return n, nil
			}
			minimalPreexecAssertUnavailable(t, f.base.owner.prepareMinimalInputsWithOps(f.host, f.ops))
			want := int32(1)
			if fault == "duplicate" {
				want = 2
			}
			if f.entropyCalls.Load() != want || f.networkCalls.Load() != 0 || f.base.owner.attempt == nil {
				t.Fatal("entropy failure retried or was not reached")
			}
			for _, alias := range aliases {
				for _, value := range alias {
					if value != 0 {
						t.Fatal("entropy scratch retained")
					}
				}
			}
			minimalPreexecFinalizeFixture(t, f)
		})
	}
}

func TestMinimalPreexecRejectsCollisionsAndReplacement(t *testing.T) {
	for _, fault := range []string{"directory collision", "directory symlink", "directory replacement", "namespace replacement", "FC FD replacement", "selected bytes", "FC bytes", "resource limits"} {
		t.Run(fault, func(t *testing.T) {
			f := newMinimalPreexecAssemblyFixture(t)
			root, name := int(f.base.inputs.stateRoot.Fd()), f.base.owner.identity.RuntimeGeneration
			seal := f.ops.seal
			if fault == "directory collision" {
				if unix.Mkdirat(root, name, 0o700) != nil {
					t.Fatal("mkdir control")
				}
			}
			if fault == "directory symlink" {
				if unix.Symlinkat("stable-key", root, name) != nil {
					t.Fatal("symlink control")
				}
			}
			if fault == "resource limits" {
				f.host.input.policy.MemoryMax = 1 << 20
			}
			f.ops.seal = func(ctx context.Context, payload []byte) (*os.File, error) {
				if fault == "selected bytes" && f.sealCalls.Load() == 1 || fault == "FC bytes" && f.sealCalls.Load() == 0 {
					payload = append(append([]byte(nil), payload...), ' ')
				}
				actual, err := seal(ctx, payload)
				if err != nil {
					return actual, err
				}
				if f.sealCalls.Load() == 2 {
					switch fault {
					case "FC FD replacement":
						original := f.base.owner.attempt.fcFile
						data, readErr := io.ReadAll(io.NewSectionReader(original, 0, maxStrictJailerConfigBytes+1))
						if readErr != nil {
							t.Error("actual FC read control", readErr)
							return actual, readErr
						}
						replacement, replacementErr := sealJailerRecoveryBytes(ctx, data)
						if replacementErr != nil {
							t.Error("actual replacement snapshot control", replacementErr)
							return actual, replacementErr
						}
						defer replacement.Close()
						if unix.Dup3(int(replacement.Fd()), int(original.Fd()), unix.O_CLOEXEC) != nil {
							t.Error("actual same-byte FC FD replacement")
						}
					case "directory replacement":
						if unix.Renameat(root, name, root, "retained-"+name) != nil || unix.Mkdirat(root, name, 0o700) != nil {
							t.Error("actual entry replacement control")
						}
					case "namespace replacement":
						// Real same-number replacement; the retained os.File is
						// still the sole owner of this duplicated descriptor.
						if unix.Dup3(int(f.base.inputs.stableKey.Fd()), int(f.base.owner.attempt.namespace[1].Fd()), unix.O_CLOEXEC) != nil {
							t.Error("actual FD replacement control")
						}
					}
				}
				return actual, nil
			}
			minimalPreexecAssertUnavailable(t, f.base.owner.prepareMinimalInputsWithOps(f.host, f.ops))
			a := f.base.owner.attempt
			if a == nil || a.prepared {
				t.Fatal("replacement published inputs")
			}
			switch fault {
			case "directory collision", "directory symlink":
				if a.directoryCreated || f.entropyCalls.Load() != 0 {
					t.Fatal("reused preexisting name")
				}
			case "FC bytes", "resource limits":
				if f.sealCalls.Load() != 1 {
					t.Fatal("first sealed config fault unreached")
				}
			default:
				if f.sealCalls.Load() != 2 {
					t.Fatal("last callback fault unreached")
				}
			}
			minimalPreexecFinalizeFixture(t, f)
			var entry unix.Stat_t
			if unix.Fstatat(root, name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil {
				t.Fatal("cleanup deleted an entry without retirement authority")
			}
		})
	}
}
