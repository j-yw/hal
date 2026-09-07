//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Observe only this test's actual serving task. The bounded snapshot is never
// logged; a timeout is setup failure, not evidence of cancellation or progress.
func waitMinimalPreparationGenesisLock(t *testing.T, storeLock bool) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	buffer := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buffer, true)
		for _, stack := range strings.Split(string(buffer[:n]), "\n\n") {
			if !strings.Contains(stack, "firecrackerhost.(*l8RuntimeOwnerLinuxRuntime).serveMinimalControlPreparation") ||
				!strings.Contains(stack, "firecrackerhost.(*l8RuntimeOwnerSupervisor).HandleBootstrap") ||
				!strings.Contains(stack, "sync.(*Mutex).Lock") {
				continue
			}
			inStore := strings.Contains(stack, "firecrackerhost.(*l8RuntimeOwnerLinuxRecordStore).withLock") &&
				strings.Contains(stack, "firecrackerhost.(*l8RuntimeOwnerLinuxRecordStore).CreateGenesis")
			if inStore == storeLock {
				return
			}
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("actual preparation did not reach the held genesis lock")
		}
	}
}

func requireMinimalPreparationNoGenesis(t *testing.T, f *minimalPreparationFixture) {
	t.Helper()
	store := f.owned.store.selected
	var stat unix.Stat_t
	if err := unix.Fstatat(f.owned.store.directoryFD, l8RuntimeOwnerRecordName, &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) ||
		store.file != nil || store.reservation != nil || store.busy != nil || store.poisoned || store.terminal ||
		f.owned.selected.attempted || f.owned.selected.starter.released || f.owned.selected.coordinator.generation != nil {
		t.Fatal("observed pre-genesis cancellation reached record/launch state", err)
	}
	// A fresh independent read remains usable. Missing record means only no
	// record here; it is not process/resource absence or cleanup authority.
	absent, err := f.owned.store.RecordAbsent(context.Background())
	if err != nil || !absent {
		t.Fatal("pre-mutation rejection poisoned independent store inspection", err)
	}
}

func TestMinimalPreparationGenesisRejectsCancellationAfterLockWait(t *testing.T) {
	for _, held := range []string{"owner", "selected_store"} {
		for _, loss := range []string{"original_eof", "absolute_P"} {
			t.Run(held+"/"+loss, func(t *testing.T) {
				deadline := time.Now().Add(time.Minute)
				if loss == "absolute_P" {
					deadline = time.Now().Add(4 * time.Second)
				}
				withMinimalPreparationFixture(t, deadline, func(f *minimalPreparationFixture) {
					prep := f.owned.minimalPreparation
					lock := &f.owner.mu
					if held == "selected_store" {
						lock = &f.owned.store.selected.mu
					}
					lock.Lock()
					locked := true
					var operation, closed <-chan error
					defer func() {
						if locked {
							lock.Unlock()
						}
						prep.revoke()
						if operation != nil {
							_ = minimalPreparationJoin(t, operation)
						}
						if closed != nil {
							_ = minimalPreparationJoin(t, closed)
						}
					}()
					operation = f.start(t)
					waitMinimalPreparationGenesisLock(t, held == "selected_store")
					prep.mu.Lock()
					monitor := prep.monitorDone
					prep.mu.Unlock()
					if monitor == nil || !prep.current() {
						t.Fatal("actual live reader transfer prerequisite not reached before P")
					}
					if loss == "original_eof" && unix.Shutdown(f.peer, unix.SHUT_RDWR) != nil {
						t.Fatal("original peer loss prerequisite")
					}
					// P is the unchanged sealed value. Waiting for real expiration
					// does not mutate the context or manufacture a timer callback.
					select {
					case <-prep.ctx.Done():
					case <-time.After(5 * time.Second):
						t.Fatal("held-lock preparation did not observe loss")
					}
					waitMinimalPreparationSignal(t, monitor, "monitor while genesis lock held")
					waitMinimalPreparationSignal(t, prep.ioDone, "I/O interrupter while genesis lock held")
					result := make(chan error, 1)
					closed = result
					go func() { result <- f.owned.shutdownMinimalControlPreparation() }()
					select {
					case <-closed:
						t.Fatal("shutdown completed before blocked bootstrap joined")
					default:
					}
					if _, err := prep.original.Stat(); err != nil {
						t.Fatal("retained original closed while bootstrap still blocked", err)
					}
					lock.Unlock()
					locked = false
					operationErr := minimalPreparationJoin(t, operation)
					operation = nil
					closeErr := minimalPreparationJoin(t, closed)
					closed = nil
					if operationErr == nil || closeErr != nil {
						t.Fatal("canceled bootstrap/join result", operationErr, closeErr)
					}
					requireMinimalPreparationNoGenesis(t, f)
				})
			})
		}
	}
}

// A test-only context isolates the synchronous Deadline obligation from timer
// scheduling. It is passed directly to the actual private store, not used to
// fabricate preparation admission, process ownership or a production parent.
type minimalPreparationDeferredDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (ctx minimalPreparationDeferredDeadlineContext) Deadline() (time.Time, bool) {
	return ctx.deadline, true
}

func TestMinimalPreparationGenesisRejectsExpiredUncontendedMutation(t *testing.T) {
	for _, mode := range []string{"canceled", "deadline_without_timer_observation"} {
		t.Run(mode, func(t *testing.T) {
			withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
				var ctx context.Context
				if mode == "canceled" {
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(context.Background())
					cancel()
				} else {
					ctx = minimalPreparationDeferredDeadlineContext{Context: context.Background(), deadline: time.Now().Add(-time.Second)}
				}
				// Demonstrate the exact real directory flock is uncontended;
				// cancellation must not depend on the EWOULDBLOCK retry branch.
				if unix.Flock(f.owned.store.directoryFD, unix.LOCK_EX|unix.LOCK_NB) != nil || unix.Flock(f.owned.store.directoryFD, unix.LOCK_UN) != nil {
					t.Fatal("ordinary directory flock prerequisite")
				}
				_, err := f.owned.store.CreateGenesis(ctx, f.owned.genesis)
				if err == nil {
					t.Error("expired caller reached actual uncontended genesis mutation")
				}
				requireMinimalPreparationNoGenesis(t, f)
			})
		})
	}
}

func TestMinimalPreparationGenesisValidAndIndependentCleanupControls(t *testing.T) {
	t.Run("minimal_valid_bootstrap_and_cleanup_after_cancel", func(t *testing.T) {
		withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
			if err := minimalPreparationJoin(t, f.start(t)); err != nil {
				t.Fatal("actual valid bootstrap", err)
			}
			f.owned.minimalPreparation.revoke()
			if err := f.owned.shutdownMinimalControlPreparation(); err != nil {
				t.Fatal("join canceled preparation", err)
			}
			if _, err := f.owned.selected.contain(); err != nil || !f.owned.selected.terminal || !f.owned.store.selected.terminal {
				t.Fatal("independent bounded cleanup inherited canceled preparation", err)
			}
			if _, err := f.owned.store.Load(context.Background()); err != nil {
				t.Fatal("fresh independent cleanup inspection failed", err)
			}
			// Containment uses the existing fake cgroup/identity/process fixture;
			// this is context separation, not live terminal cleanup acceptance.
		})
	})
	t.Run("legacy_seven_valid_genesis", func(t *testing.T) {
		owned, _, _, _ := jailerRecoveryRuntimeFixture(t)
		if owned.store.selected.minimal != nil || owned.selected.config.Version != jailerRecoveryConfigVersion {
			t.Fatal("legacy seven-role prerequisite")
		}
		if _, err := owned.store.CreateGenesis(context.Background(), owned.genesis); err != nil {
			t.Fatal("legacy valid genesis rejected", err)
		}
		if _, err := owned.store.Load(context.Background()); err != nil {
			t.Fatal("legacy record readback", err)
		}
	})
}
