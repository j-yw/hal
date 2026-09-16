//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

type minimalTemplateReadFunc func([]byte) (int, error)

func (read minimalTemplateReadFunc) Read(p []byte) (int, error) { return read(p) }

func TestMinimalTemplateHandoffPartialSnapshotOwnershipAndBorrowExpiry(t *testing.T) {
	for _, fault := range []string{"first-file-error", "second-file-error", "second-panic", "metadata", "cancel-after-kernel", "expire-after-rootfs", "mutate-restore-rootfs", "replace-parent"} {
		t.Run(fault, func(t *testing.T) {
			f, probe, r := newMinimalTemplateHandoffProbe(t, func(inputs *minimalTemplateHandoffInputs) {
				if fault == "expire-after-rootfs" {
					inputs.preparation = 500 * time.Millisecond
				}
			})
			rootfsPath := filepath.Join(f.inputs.association.bundleDir, "rootfs.ext4")
			originalRootfs, err := os.ReadFile(rootfsPath)
			if err != nil {
				t.Fatal(err)
			}
			var readers []io.Reader
			var returned []*os.File
			calls := 0
			probe.snapshot = func(ctx context.Context, kind string, reader io.Reader, size int64, digest string, limit int64) (*os.File, jailerRecoveryAsset, error) {
				calls++
				readers = append(readers, reader)
				owner := probe.source.owner
				if owner == nil || owner.lease == nil || ctx != r.Context() || owner.context != r.OwnedContext() || calls == 2 && owner.files[0] != returned[0] {
					t.Error("partial owner/result was not retained before allocating callback")
					return nil, jailerRecoveryAsset{}, errors.New("test prerequisite")
				}
				if fault == "second-panic" && calls == 2 {
					panic("private snapshot panic canary")
				}
				input := reader
				if fault == "mutate-restore-rootfs" && calls == 2 {
					input = minimalTemplateReadFunc(func(p []byte) (int, error) {
						n, err := reader.Read(p)
						if n > 0 {
							if writeErr := os.WriteFile(rootfsPath, originalRootfs, 0600); writeErr != nil {
								return n, writeErr
							}
						}
						return n, err
					})
				}
				file, measured, err := snapshotJailerRecoveryAsset(ctx, kind, input, size, digest, limit)
				if file != nil {
					returned = append(returned, file)
				}
				if err != nil {
					return file, measured, err
				}
				switch {
				case fault == "first-file-error" && calls == 1, fault == "second-file-error" && calls == 2:
					return file, measured, errors.New("private allocated-file error canary")
				case fault == "metadata":
					measured.SHA256 = strings.Repeat("e", 64)
				case fault == "cancel-after-kernel" && calls == 1:
					r.Revoke()
				case fault == "expire-after-rootfs" && calls == 2:
					<-ctx.Done()
				case fault == "mutate-restore-rootfs" && calls == 1:
					changed := append([]byte(nil), originalRootfs...)
					changed[0] ^= 1
					if err := os.WriteFile(rootfsPath, changed, 0600); err != nil {
						return file, measured, err
					}
				case fault == "replace-parent" && calls == 1:
					replaceMinimalTemplatePath(t, filepath.Join(f.inputs.association.parentL7Dir, "rootfs.ext4"))
				}
				return file, measured, nil
			}
			bound, err := f.binding.Start(r, f.selected, func() error { return nil })
			owner := probe.owner
			if bound == nil || owner == nil || owner.sealed || !errors.Is(err, sandboxruntime.ErrMinimalLaunchUnavailable) || strings.Contains(err.Error(), "canary") || calls == 0 || len(returned) == 0 {
				t.Fatal("snapshot failure lost original partial ownership or leaked payload", err)
			}
			for index, file := range returned {
				if owner.files[index] != file {
					t.Fatal("allocated result escaped its exact partial owner")
				}
			}
			for _, reader := range readers {
				var p [1]byte
				if _, err := reader.Read(p[:]); !errors.Is(err, io.ErrClosedPipe) {
					t.Fatal("borrowed view survived callback return or panic", err)
				}
			}
			if f.selected.Current(f.ctx) == nil || f.inputs.requests.Load() != 2 {
				t.Fatal("partial failed handoff was current or reacquired")
			}
			if receipt, err := owner.Finalize(f.ctx); receipt != (sandboxruntime.MinimalLaunchCleanupReceipt{}) || err == nil || !owner.closed || owner.closeErr != nil {
				t.Fatal("partial assets did not close without issuing a receipt")
			}
			for _, file := range returned {
				if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatal("partial snapshot leaked", err)
				}
			}
			if owner.lease.ConfirmCurrent(f.ctx) == nil {
				t.Fatal("partial owner retained launch files after Finalize")
			}
		})
	}
}

// Replace with byte-identical content outside the retained directory, preserving
// the expected inventory so identity checks, not an extra backup entry, reject it.
func replaceMinimalTemplatePath(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "original")
	if err := os.Rename(path, backup); err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		value, err := os.ReadFile(backup)
		if err != nil || os.WriteFile(path, value, 0600) != nil {
			t.Fatal("fixture replacement", err)
		}
		return
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(backup)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		value, err := os.ReadFile(filepath.Join(backup, entry.Name()))
		if err != nil || os.WriteFile(filepath.Join(path, entry.Name()), value, 0600) != nil {
			t.Fatal("fixture directory replacement", err)
		}
	}
}

func TestMinimalTemplateHandoffRetainsOwnerBeforeFailedTransfer(t *testing.T) {
	for _, target := range []string{"kernel", "rootfs", "child-metadata", "parent-metadata", "parent-rootfs", "child-directory", "parent-directory"} {
		t.Run(target, func(t *testing.T) {
			f, probe, r := newMinimalTemplateHandoffProbe(t, nil)
			entry := f.inputs.association
			path := map[string]string{"kernel": filepath.Join(entry.bundleDir, "vmlinux"), "rootfs": filepath.Join(entry.bundleDir, "rootfs.ext4"),
				"child-metadata": filepath.Join(entry.bundleDir, "sources.lock.json"), "parent-metadata": filepath.Join(entry.parentL7Dir, "provenance.json"),
				"parent-rootfs": filepath.Join(entry.parentL7Dir, "rootfs.ext4"), "child-directory": entry.bundleDir, "parent-directory": entry.parentL7Dir}[target]
			replaceMinimalTemplatePath(t, path)
			// Direct concrete entry still uses the genuine armed reservation and
			// Claim; this reaches its own pre-transfer check, not binding.Current.
			result, err := f.provider.StartMinimalJob(r.Context(), r, probe.source)
			owner, ok := result.(*minimalTemplateAssetOwner)
			if !ok || owner == nil || err == nil || owner != probe.source.owner || owner.lease != nil || owner.sealed || owner.files != ([2]*os.File{}) {
				t.Fatal("failed transfer discarded partial original ownership")
			}
			if _, err := r.ClaimLaunch(r.Context()); err == nil || f.inputs.requests.Load() != 2 {
				t.Fatal("replacement permitted renewed claim/acquisition")
			}
			if receipt, err := owner.Finalize(f.ctx); receipt != (sandboxruntime.MinimalLaunchCleanupReceipt{}) || err == nil || !owner.closed || owner.closeErr != nil {
				t.Fatal("untransferred partial files were not closed without a receipt")
			}
		})
	}
}

func TestMinimalTemplateHandoffPartialCloseUncertaintyIsSticky(t *testing.T) {
	f, probe, r := newMinimalTemplateHandoffProbe(t, nil)
	owner := startMinimalTemplateProbe(t, f, probe, r)
	if err := owner.files[0].Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if receipt, err := owner.Finalize(f.ctx); receipt != (sandboxruntime.MinimalLaunchCleanupReceipt{}) || err == nil || !owner.closed || owner.closeErr == nil {
			t.Fatal("partial close uncertainty became successful terminal proof")
		}
	}
	if _, err := owner.files[1].Stat(); !errors.Is(err, os.ErrClosed) || owner.lease.ConfirmCurrent(f.ctx) == nil || owner.Identity() != r.Identity() {
		t.Fatal("close error prevented remaining cleanup or lost original identity")
	}
}

func waitMinimalTemplateMutex(t *testing.T, method string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	buffer := make([]byte, 256<<10)
	for {
		n := runtime.Stack(buffer, true)
		for _, stack := range strings.Split(string(buffer[:n]), "\n\n") {
			if strings.Contains(stack, method) && strings.Contains(stack, "sync.(*Mutex).Lock") {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("actual handoff did not reach retained mutex wait")
		}
		runtime.Gosched()
	}
}

func TestMinimalTemplateHandoffCancellationAfterSerializationWait(t *testing.T) {
	for _, mode := range []string{"cancel", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			f, probe, r := newMinimalTemplateHandoffProbe(t, func(inputs *minimalTemplateHandoffInputs) {
				if mode == "expiry" {
					inputs.preparation = 500 * time.Millisecond
				}
			})
			probe.source.mu.Lock()
			var unlock sync.Once
			done := make(chan struct{})
			var result sandboxruntime.MinimalJobRuntimeOwner
			var err error
			go func() {
				defer close(done)
				result, err = f.provider.StartMinimalJob(r.Context(), r, probe.source)
			}()
			defer func() { unlock.Do(probe.source.mu.Unlock); <-done }()
			waitMinimalTemplateMutex(t, "firecrackerhost.(*minimalLaunchProvider).startMinimalJob")
			if mode == "cancel" {
				r.Revoke()
			} else {
				<-r.Context().Done()
			}
			unlock.Do(probe.source.mu.Unlock)
			<-done
			if result != nil || err == nil || probe.source.owner != nil || probe.source.assets.ConfirmCurrent(f.ctx) != nil {
				t.Fatal("post-wait cancellation transferred original assets")
			}
		})
	}
}

func TestMinimalTemplateHandoffConcurrentIndependentOwners(t *testing.T) {
	f := newMinimalTemplateHandoffFixture(t) // actual production provider, no probe
	second, err := f.authorizer.ResolveSelection(f.ctx, f.principal, f.inputs.association.scope.WorkerID, minimalTemplateHints(), f.inputs.association.template)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	selected := []*sandboxruntime.MinimalLaunchPreparedSelection{f.selected, second}
	owners := make([]*sandboxruntime.MinimalLaunchOwnerBinding, 2)
	reservations := make([]*sandboxruntime.MinimalLaunchReservation, 2)
	for index, selection := range selected {
		r, err := selection.Reserve(f.ctx, f.owned, []string{"first-job", "second-job"}[index], "job-generation", "request-v2-"+strings.Repeat("a", 64), time.Now().Add(2*time.Second),
			sandboxruntime.MinimalLaunchRequestCorrelation{AdmissionGrantID: "original-admission", AdmissionGrantRevision: 7})
		if err != nil || r.ArmDispatch(f.ctx, r.Identity()) != nil {
			t.Fatal(err)
		}
		t.Cleanup(r.Revoke)
		reservations[index] = r
	}
	var group sync.WaitGroup
	for index, selection := range selected {
		group.Add(1)
		go func() {
			defer group.Done()
			var err error
			owners[index], err = f.binding.Start(reservations[index], selection, func() error { return nil })
			if owners[index] == nil || !errors.Is(err, sandboxruntime.ErrMinimalLaunchUnavailable) {
				t.Error("independent concurrent owner not retained", err)
			}
		}()
	}
	group.Wait()
	for _, owner := range owners {
		if owner != nil {
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_, _ = owner.Finalize(ctx)
			})
		}
	}
	if owners[0] == nil || owners[1] == nil || owners[0] == owners[1] || selected[0].Identity().RuntimeGeneration == selected[1].Identity().RuntimeGeneration || f.inputs.requests.Load() != 4 {
		t.Fatal("concurrent jobs shared acquisition or owner")
	}
	_, _ = owners[0].Finalize(f.ctx)
	if selected[0].Current(f.ctx) == nil || selected[1].Current(f.ctx) != nil {
		t.Fatal("first finalization closed the independent second owner")
	}
	_, _ = owners[1].Finalize(f.ctx)
	if selected[1].Current(f.ctx) == nil {
		t.Fatal("second owner did not close")
	}
}

func TestMinimalTemplateHandoffCloseAndFinalizeJoinActualBorrow(t *testing.T) {
	f, probe, r := newMinimalTemplateHandoffProbe(t, nil)
	entered := make(chan *minimalTemplateAssetOwner, 1)
	release := make(chan struct{})
	var unblock sync.Once
	probe.snapshot = func(ctx context.Context, kind string, reader io.Reader, size int64, digest string, limit int64) (*os.File, jailerRecoveryAsset, error) {
		file, measured, err := snapshotJailerRecoveryAsset(ctx, kind, reader, size, digest, limit)
		if kind == "kernel" {
			entered <- probe.source.owner
			<-release
		}
		return file, measured, err
	}
	started := make(chan struct{})
	var bound *sandboxruntime.MinimalLaunchOwnerBinding
	var startErr error
	go func() {
		defer close(started)
		bound, startErr = f.binding.Start(r, f.selected, func() error { return nil })
	}()
	defer func() { unblock.Do(func() { close(release) }); <-started }()
	var owner *minimalTemplateAssetOwner
	select {
	case owner = <-entered:
	case <-started:
		t.Fatal("actual snapshot borrow was not reached", startErr)
	case <-f.ctx.Done():
		t.Fatal("actual snapshot borrow did not arrive")
	}
	finalized, aliased := make(chan struct{}), make(chan struct{})
	var receipt sandboxruntime.MinimalLaunchCleanupReceipt
	var finalErr, aliasErr error
	go func() { defer close(finalized); receipt, finalErr = owner.Finalize(f.ctx) }()
	go func() { defer close(aliased); aliasErr = f.selected.Close() }()
	defer func() { unblock.Do(func() { close(release) }); <-finalized; <-aliased }()
	waitMinimalTemplateMutex(t, "firecrackerhost.(*minimalTemplateAssetOwner).Finalize")
	select {
	case <-finalized:
		t.Fatal("Finalize returned before original borrow released")
	default:
	}
	select {
	case <-aliased:
		t.Fatal("selection Close returned before its active Start joined")
	default:
	}
	unblock.Do(func() { close(release) })
	<-started
	<-finalized
	<-aliased
	if bound == nil || !errors.Is(startErr, sandboxruntime.ErrMinimalLaunchUnavailable) || receipt != (sandboxruntime.MinimalLaunchCleanupReceipt{}) || !errors.Is(finalErr, sandboxruntime.ErrMinimalLaunchUnavailable) || aliasErr != nil || !owner.closed || owner.closeErr != nil {
		t.Fatal("serialized borrow/close/finalization lost actual ownership")
	}
	for _, file := range owner.files {
		if file == nil {
			t.Fatal("borrow did not produce both real snapshots")
		}
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("joined finalization retained snapshot FD")
		}
	}
}
