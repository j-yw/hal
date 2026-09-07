package localresolver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestL8MinimalUntransferredCurrentnessRejectsChangedOriginal(t *testing.T) {
	for _, change := range []string{"vmlinux", "rootfs.ext4", "provenance.json", "parent_rootfs", "parent_metadata", "root_directory", "parent_directory", "in_place", "symlink"} {
		t.Run(change, func(t *testing.T) {
			request := minimalDistributionFixture(t)
			verified, err := VerifyL8MinimalDistributionBundle(request)
			if err != nil {
				t.Fatal(err)
			}
			defer verified.Close()
			if err := verified.ConfirmCurrent(context.Background()); err != nil {
				t.Fatal("new currentness prerequisite", err)
			}
			state, parent := verified.state, verified.state.parentLease
			files := minimalLaunchRetainedFiles(verified)
			if change == "parent_directory" {
				root := request.ParentL7.rootDir
				if err := os.Rename(root, filepath.Join(t.TempDir(), "retained-parent")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				minimalLaunchMutate(t, request, change)
			}
			if err := verified.ConfirmCurrent(context.Background()); err == nil {
				t.Fatal("changed original remained current")
			}
			if verified.state != state || state.parentLease != parent || state.closed || state.transferred {
				t.Fatal("failed currentness replaced or transferred its owner")
			}
			minimalCurrentnessRequireSameFiles(t, verified, files)
			if lease, err := verified.TakeLaunchLease(context.Background()); err == nil {
				_ = lease.Close()
				t.Fatal("rejected currentness reacquired a replacement for launch")
			}
			if err := verified.Close(); err != nil {
				t.Fatal("owned close", err)
			}
			for _, file := range files {
				if _, err := file.Stat(); err == nil {
					t.Fatal("original retained descriptor survived close")
				}
			}
		})
	}
}

func minimalCurrentnessRequireSameFiles(t *testing.T, verified VerifiedL8MinimalDistribution, originals []*os.File) {
	t.Helper()
	current := minimalLaunchRetainedFiles(verified)
	if len(current) != len(originals) {
		t.Fatal("retained file inventory changed")
	}
	seen := make(map[*os.File]bool, len(current))
	for _, file := range current {
		seen[file] = true
	}
	for _, file := range originals {
		if !seen[file] {
			t.Fatal("original retained file handle replaced")
		}
		if _, err := file.Stat(); err != nil {
			t.Fatal("currentness closed original handle", err)
		}
	}
}

// Holding the actual parent mutex makes the shared checker wait after the
// distribution mutex is acquired. TryLock observes that real boundary without
// changing production callbacks, deadlines, or filesystem operations.
func TestL8MinimalUntransferredCurrentnessSerializesLifetime(t *testing.T) {
	for _, action := range []string{"cancel", "deadline", "close", "transfer"} {
		t.Run(action, func(t *testing.T) {
			verified := minimalCurrentnessVerifiedFixture(t)
			if verified.ConfirmCurrent(context.Background()) != nil {
				t.Fatal("new currentness prerequisite")
			}
			files := minimalLaunchRetainedFiles(verified)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if action == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
				defer cancel()
			}
			parent := verified.state.parentLease
			parent.mu.Lock()
			var unlock sync.Once
			release := func() { unlock.Do(parent.mu.Unlock) }
			done := make(chan error, 1)
			go func() { done <- verified.ConfirmCurrent(ctx) }()
			joined := false
			defer func() {
				release()
				if !joined {
					_ = minimalCurrentnessJoin(t, done)
				}
			}()
			limit := time.NewTimer(2 * time.Second)
			defer limit.Stop()
			for {
				if !verified.state.mu.TryLock() {
					break
				}
				verified.state.mu.Unlock()
				select {
				case err := <-done:
					joined = true
					t.Fatal("Current did not wait at retained parent", err)
				case <-limit.C:
					t.Fatal("actual parent-lock boundary not reached")
				case <-time.After(time.Millisecond):
				}
			}
			var actionDone chan error
			var lease *VerifiedL8MinimalLaunchLease
			switch action {
			case "cancel":
				cancel()
			case "deadline":
				select {
				case <-ctx.Done():
				case <-time.After(2 * time.Second):
					t.Fatal("real fixed deadline did not expire")
				}
			case "close", "transfer":
				actionDone = make(chan error, 1)
				go func() {
					if action == "close" {
						actionDone <- verified.Close()
						return
					}
					var err error
					lease, err = verified.TakeLaunchLease(context.Background())
					actionDone <- err
				}()
			}
			release()
			err := minimalCurrentnessJoin(t, done)
			joined = true
			if actionDone != nil {
				if actionErr := minimalCurrentnessJoin(t, actionDone); actionErr != nil {
					t.Fatal("serialized owner action", actionErr)
				}
				if lease != nil {
					defer lease.Close()
				}
			}
			switch action {
			case "cancel", "deadline":
				if !errors.Is(err, ctx.Err()) || err == nil {
					t.Fatal("wait lost original context error", err, ctx.Err())
				}
				if verified.ConfirmCurrent(context.Background()) != nil {
					t.Fatal("caller cancellation revoked asset ownership")
				}
				minimalCurrentnessRequireSameFiles(t, verified, files)
			case "close":
				if err != nil || verified.ConfirmCurrent(context.Background()) == nil {
					t.Fatal("Close was not serialized after Current", err)
				}
				for _, file := range files {
					if _, err := file.Stat(); err == nil {
						t.Fatal("Close left original descriptor")
					}
				}
			case "transfer":
				if err != nil || lease == nil || lease.ConfirmCurrent(context.Background()) != nil {
					t.Fatal("transfer did not preserve original currentness", err)
				}
				if verified.ConfirmCurrent(context.Background()) == nil {
					t.Fatal("distribution gained lease alias authority")
				}
				minimalCurrentnessRequireSameFiles(t, verified, files)
			}
		})
	}
}

func minimalCurrentnessJoin(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("currentness fixture operation did not join")
		return nil
	}
}

// This observer delegates every Context method to an immutable real parent.
// It only arranges real cancellation at an actual Err observation boundary;
// it never fabricates Err/Deadline/Done or changes a production dependency.
type minimalCurrentnessCancelObserver struct {
	context.Context
	cancel                context.CancelFunc
	mode                  string
	readCalls, finalCalls int
	reached               bool
}

func (ctx *minimalCurrentnessCancelObserver) Err() error {
	pc, _, _, _ := runtime.Caller(1)
	fn := runtime.FuncForPC(pc)
	if fn != nil {
		name := fn.Name()
		if strings.HasSuffix(name, ".(*minimalLaunchReader).Read") {
			ctx.readCalls++
			// The second Read's Err check follows an actual successful first
			// read from a retained file, not merely method entry.
			if ctx.mode == "after_read" && ctx.readCalls == 2 {
				ctx.reached = true
				ctx.cancel()
			}
		}
		if strings.HasSuffix(name, ".(*minimalDistributionState).confirmLaunchCurrent") {
			ctx.finalCalls++
			if ctx.mode == "final_readback" && ctx.finalCalls == 2 && ctx.readCalls > 1 {
				ctx.reached = true
				ctx.cancel()
			}
		}
	}
	return ctx.Context.Err()
}

func TestL8MinimalUntransferredCurrentnessCancelsAfterActualRead(t *testing.T) {
	for _, mode := range []string{"after_read", "final_readback"} {
		t.Run(mode, func(t *testing.T) {
			verified := minimalCurrentnessVerifiedFixture(t)
			if verified.ConfirmCurrent(context.Background()) != nil {
				t.Fatal("new currentness prerequisite")
			}
			files := minimalLaunchRetainedFiles(verified)
			// All twelve measured fixture files are nonempty and fit in one
			// bounded Read. A successful traversal therefore observes exactly
			// one data Read and one EOF Read per file, plus both outer checks.
			regularFiles := 0
			for _, file := range files {
				info, err := file.Stat()
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().IsRegular() {
					if info.Size() <= 0 || info.Size() > 32<<10 {
						t.Fatal("read-observation fixture is not one nonempty chunk")
					}
					regularFiles++
				}
			}
			control := &minimalCurrentnessCancelObserver{Context: context.Background()}
			if err := verified.ConfirmCurrent(control); err != nil || regularFiles != 12 || control.readCalls != 2*regularFiles || control.finalCalls != 2 {
				t.Fatal("complete retained-byte read control failed", err, regularFiles, control.readCalls, control.finalCalls)
			}
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &minimalCurrentnessCancelObserver{Context: parent, cancel: cancel, mode: mode}
			err := verified.ConfirmCurrent(ctx)
			if !ctx.reached || ctx.readCalls < 2 || !errors.Is(parent.Err(), context.Canceled) {
				t.Fatal("actual cancellation boundary was not reached")
			}
			if mode == "after_read" && ctx.readCalls != 2 || mode == "final_readback" && ctx.readCalls != control.readCalls {
				t.Fatal("cancellation did not follow the expected completed reads", ctx.readCalls, control.readCalls)
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatal("late cancellation admitted currentness", err)
			}
			if verified.state.transferred || verified.ConfirmCurrent(context.Background()) != nil {
				t.Fatal("canceled caller consumed original authority")
			}
			minimalCurrentnessRequireSameFiles(t, verified, files)
		})
	}
}
