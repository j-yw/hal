//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func waitMinimalJailerWaiters(t *testing.T, count int) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	buffer := make([]byte, 1<<20)
	for {
		waiting := 0
		n := runtime.Stack(buffer, true)
		for _, stack := range strings.Split(string(buffer[:n]), "\n\n") {
			if strings.Contains(stack, "[select]") && strings.Contains(stack, "firecrackerhost.(*minimalJailerFinalization).run") &&
				!strings.Contains(stack, "firecrackerhost.(*minimalJailerFinalization).execute") {
				waiting++
			}
		}
		if waiting == count {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("same-attempt waiters did not reach their bounded waiting point")
		}
	}
}

func TestMinimalJailerFinalizationConcurrentWaitersKeepExactAttempt(t *testing.T) {
	for _, mode := range []string{"success", "cancel", "close", "panic"} {
		t.Run(mode, func(t *testing.T) {
			f, client, completion := minimalJailerFinalizedFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			client.ops.connectMinimal = func(ctx context.Context, directory *os.File, record firecrackerRuntimeOwnerRecordV1) (*os.File, error) {
				calls.Add(1)
				if !client.mu.TryLock() {
					return nil, errors.New("fixture: client mutex held by connector")
				}
				client.mu.Unlock()
				if !completion.state.mu.TryLock() {
					return nil, errors.New("fixture: completion mutex held by connector")
				}
				completion.state.mu.Unlock()
				close(entered)
				select {
				case <-ctx.Done():
					return nil, errors.New("secret-fixture-error-canary")
				case <-release:
				}
				if mode == "panic" {
					panic("secret-fixture-panic-canary")
				}
				return f.ops.connectMinimal(ctx, directory, record)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			activeResult := make(chan error, 1)
			go func() { activeResult <- completion.commit(ctx) }()
			activeJoined := false
			defer func() {
				cancel()
				if !activeJoined {
					_ = joinMinimalJailerResult(t, activeResult)
				}
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("selected connector did not enter outside both mutexes")
			}
			completion.state.mu.Lock()
			attempt := completion.state.active
			completion.state.mu.Unlock()
			waitCtx, cancelWait := context.WithCancel(context.Background())
			defer cancelWait()
			canceledWaiter, waiter1, waiter2 := make(chan error, 1), make(chan error, 1), make(chan error, 1)
			go func() { canceledWaiter <- completion.commit(waitCtx) }()
			go func() { waiter1 <- completion.commit(context.Background()) }()
			go func() { waiter2 <- completion.commit(context.Background()) }()
			canceledJoined, remainingJoined := false, false
			defer func() {
				cancelWait()
				cancel()
				if !canceledJoined {
					_ = joinMinimalJailerResult(t, canceledWaiter)
				}
				if !remainingJoined {
					_ = joinMinimalJailerResult(t, waiter1)
					_ = joinMinimalJailerResult(t, waiter2)
				}
			}()
			waitMinimalJailerWaiters(t, 3)
			cancelWait()
			waitErr := joinMinimalJailerResult(t, canceledWaiter)
			canceledJoined = true
			if waitErr == nil || waitErr.Error() != errL8RuntimeOwnerInvalid.Error() {
				t.Fatal("canceled waiter acquired result or leaked detail", waitErr)
			}
			if ctx.Err() != nil || calls.Load() != 1 || client.stopAndCommit(context.Background()) == nil {
				t.Fatal("waiter cancellation revoked active caller, duplicated connect or allowed legacy overlap")
			}
			completion.state.mu.Lock()
			unchanged := completion.state.active == attempt
			completion.state.mu.Unlock()
			if !unchanged {
				t.Fatal("canceled waiter replaced admitted attempt")
			}
			var closeResult chan error
			switch mode {
			case "success", "panic":
				close(release)
			case "cancel":
				cancel()
			case "close":
				closeResult = make(chan error, 1)
				go func() { closeResult <- client.close() }()
			}
			actual := joinMinimalJailerResult(t, activeResult)
			activeJoined = true
			first, second := joinMinimalJailerResult(t, waiter1), joinMinimalJailerResult(t, waiter2)
			remainingJoined = true
			if (actual == nil) != (mode == "success") || first != actual || second != actual || calls.Load() != 1 {
				t.Fatal("waiters did not share the exact admitted attempt outcome", actual, first, second)
			}
			if actual != nil && actual.Error() != errL8RuntimeOwnerInvalid.Error() {
				t.Fatal("callback error or panic leaked")
			}
			if closeResult != nil && joinMinimalJailerResult(t, closeResult) != nil {
				t.Fatal("concurrent close did not join the admitted connector")
			}
			f.waitConnection()
			if completion.state.active != nil || attempt.stream != nil || completion.state.acknowledged != (mode == "success") {
				t.Fatal("joined attempt retained I/O or invented ACK")
			}
			if mode == "panic" && !completion.state.quarantined {
				t.Fatal("callback panic did not retain uncertainty")
			}
		})
	}
}

func TestMinimalJailerFinalizationCannotMigrateAfterConcurrentLegacyAdmission(t *testing.T) {
	for _, fails := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy_success", true: "legacy_failure"}[fails], func(t *testing.T) {
			f := newJailerRecoveryWireFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			contain := f.owner.opts.ContainChild
			f.owner.opts.ContainChild = func() (l8RuntimeOwnerAbsenceObservation, error) {
				close(entered)
				<-release
				if fails {
					return l8RuntimeOwnerAbsenceObservation{}, errL8RuntimeOwnerInvalid
				}
				return contain()
			}
			client := f.fresh(t)
			legacy := make(chan error, 1)
			go func() { legacy <- client.stopAndCommit(context.Background()) }()
			released, legacyJoined := false, false
			defer func() {
				if !released {
					close(release)
				}
				if !legacyJoined {
					_ = joinMinimalJailerResult(t, legacy)
				}
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("actual legacy Stop did not reach its existing mutex-held I/O")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			selected := make(chan error, 1)
			go func() {
				completion, err := client.finalizeMinimalCleanup(ctx)
				if completion != nil {
					selected <- errors.New("selected route was minted after legacy admission")
					return
				}
				selected <- err
			}()
			selectedJoined := false
			defer func() {
				if !released {
					close(release)
					released = true
				}
				if !selectedJoined {
					_ = joinMinimalJailerResult(t, selected)
				}
			}()
			deadline := time.Now().Add(3 * time.Second)
			buffer := make([]byte, 1<<20)
			for {
				n := runtime.Stack(buffer, true)
				waiting := false
				for _, stack := range strings.Split(string(buffer[:n]), "\n\n") {
					waiting = waiting || strings.Contains(stack, "firecrackerhost.(*jailerRecoveryClient).finalizeMinimalCleanup") && strings.Contains(stack, "sync.(*Mutex).Lock")
				}
				if waiting {
					break
				}
				if !time.Now().Before(deadline) {
					t.Fatal("selected entry did not reach the actual legacy lock wait")
				}
				time.Sleep(time.Millisecond)
			}
			cancel() // Cannot interrupt an already-admitted legacy operation.
			close(release)
			released = true
			legacyErr := joinMinimalJailerResult(t, legacy)
			legacyJoined = true
			selectedErr := joinMinimalJailerResult(t, selected)
			selectedJoined = true
			f.waitConnection()
			if (legacyErr != nil) != fails || selectedErr != errL8RuntimeOwnerInvalid || client.minimal != nil || !client.legacyAdmitted {
				t.Fatal("concurrent selected entry changed or migrated the admitted legacy route", legacyErr, selectedErr)
			}
		})
	}
}
