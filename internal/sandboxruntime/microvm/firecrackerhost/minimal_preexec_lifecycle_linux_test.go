//go:build linux

package firecrackerhost

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

func minimalPreexecReceive[T any](t *testing.T, channel <-chan T) T {
	t.Helper()
	select {
	case result := <-channel:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("owned operation did not join")
	}
	var zero T
	return zero
}

func TestMinimalPreexecFinalizeWaitsForActualSetupReturn(t *testing.T) {
	for _, hostClose := range []bool{false, true} {
		t.Run(map[bool]string{false: "finalize", true: "host close and finalize"}[hostClose], func(t *testing.T) {
			f := newMinimalPreexecAssemblyFixture(t)
			entered, release := make(chan *os.File, 1), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			duplicate := f.ops.duplicate
			f.ops.duplicate = func(file *os.File) (*os.File, error) {
				actual, err := duplicate(file)
				if err != nil {
					return actual, err
				}
				if f.duplicateCalls.Load() == 1 {
					// Actual source Current must be callable outside source.mu.
					if f.base.handoff.selected.Current(f.base.preparation) != nil {
						return actual, errMinimalPreexecTestFault
					}
					entered <- actual
					<-release
				}
				return actual, nil
			}
			setup := make(chan error, 1)
			setupJoined := make(chan struct{})
			go func() { defer close(setupJoined); setup <- f.base.owner.prepareMinimalInputsWithOps(f.host, f.ops) }()
			defer func() { unblock(); minimalPreexecReceive(t, setupJoined) }()
			actual := minimalPreexecReceive(t, entered)
			var hostDone chan error
			if hostClose {
				hostDone = make(chan error, 1)
				hostJoined := make(chan struct{})
				go func() { defer close(hostJoined); hostDone <- f.host.close() }()
				defer func() { unblock(); minimalPreexecReceive(t, hostJoined) }()
				minimalPreexecReceive(t, f.host.context.Done())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			receipt, err := f.base.owner.Finalize(ctx)
			deadline, _ := ctx.Deadline()
			if time.Now().Before(deadline) {
				t.Fatal("Finalize returned before its actual setup wait reached caller deadline")
			}
			cancel()
			minimalPreexecAssertUnavailable(t, err)
			if receipt != (sandboxruntime.MinimalLaunchCleanupReceipt{}) {
				t.Fatal("deadline produced receipt")
			}
			owner := f.base.owner
			owner.source.mu.Lock()
			a := owner.attempt
			closed, assetsClosed := owner.closed, owner.assetsClosed
			owner.source.mu.Unlock()
			if a == nil || !closed || assetsClosed || !a.retired.Load() {
				t.Fatal("Finalize discarded owner or closed before setup joined")
			}
			for _, file := range []*os.File{actual, owner.files[0], f.host.stateRoot} {
				if _, err := file.Stat(); err != nil {
					t.Fatal("in-flight borrowed/returned FD closed", err)
				}
			}
			if hostDone != nil {
				select {
				case <-hostDone:
					t.Fatal("host close did not wait for admitted borrow")
				default:
				}
			}
			unblock()
			minimalPreexecAssertUnavailable(t, minimalPreexecReceive(t, setup))
			if hostDone != nil {
				if err := minimalPreexecReceive(t, hostDone); err != nil {
					t.Fatal(err)
				}
			}
			if owner.attempt != a || a.hostFiles[0] != actual || a.prepared || f.duplicateCalls.Load() != 1 || f.networkCalls.Load() != 0 {
				t.Fatal("late returned FD not captured or canceled setup continued")
			}
			minimalPreexecFinalizeFixture(t, f)
		})
	}
}

type minimalPreexecBlockingProxy struct {
	*minimalL7ConfigTestProxy
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	stops   atomic.Int32
	fail    atomic.Bool
}

func (p *minimalPreexecBlockingProxy) Stop(ctx context.Context, plan networkenforcement.Plan, generation l7network.ProxyGeneration) error {
	p.stops.Add(1)
	if p.fail.Load() {
		return errMinimalPreexecTestFault
	}
	if p.entered != nil {
		p.once.Do(func() { close(p.entered) })
		select {
		case <-p.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return p.minimalL7ConfigTestProxy.Stop(ctx, plan, generation)
}

func TestMinimalPreexecConcurrentFinalizeAdmissionIsCancellable(t *testing.T) {
	f := newMinimalPreexecAssemblyFixture(t)
	p := &minimalPreexecBlockingProxy{minimalL7ConfigTestProxy: &minimalL7ConfigTestProxy{endpoint: "127.0.0.1:43123", loss: make(chan struct{})}, entered: make(chan struct{}), release: make(chan struct{})}
	f.configureNetwork = func(options *l7network.Options) { options.Proxy = p }
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(p.release) }) }
	defer unblock()
	if err := f.base.owner.prepareMinimalInputsWithOps(f.host, f.ops); err != nil {
		t.Fatal("real preparation", err)
	}
	winner := make(chan error, 1)
	winnerJoined := make(chan struct{})
	go func() {
		defer close(winnerJoined)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := f.base.owner.Finalize(ctx)
		winner <- err
	}()
	defer func() { unblock(); minimalPreexecReceive(t, winnerJoined) }()
	minimalPreexecReceive(t, p.entered)
	current := make(chan error, 1)
	currentJoined := make(chan struct{})
	go func() { defer close(currentJoined); current <- f.base.handoff.selected.Current(f.base.preparation) }()
	defer func() { unblock(); minimalPreexecReceive(t, currentJoined) }()
	if minimalPreexecReceive(t, current) == nil {
		t.Fatal("closing owner remained current")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	receipt, err := f.base.owner.Finalize(ctx)
	deadline, _ := ctx.Deadline()
	if time.Now().Before(deadline) {
		t.Fatal("losing Finalize did not wait through caller cancellation")
	}
	cancel()
	minimalPreexecAssertUnavailable(t, err)
	if receipt != (sandboxruntime.MinimalLaunchCleanupReceipt{}) || p.stops.Load() != 1 {
		t.Fatal("loser started duplicate cleanup")
	}
	select {
	case <-winner:
		t.Fatal("admitted synchronous callback was abandoned")
	default:
	}
	unblock()
	minimalPreexecAssertUnavailable(t, minimalPreexecReceive(t, winner))
	minimalPreexecFinalizeFixture(t, f)
	if p.stops.Load() != 1 {
		t.Fatal("completed cleanup reentered proxy Stop")
	}
}

func TestMinimalPreexecRetainsActualPartialSessionRollback(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepared rollback", true: "failed prepare rollback"}[partial], func(t *testing.T) {
			f := newMinimalPreexecAssemblyFixture(t)
			endpoint := "127.0.0.1:43123"
			if partial {
				endpoint = "invalid"
			}
			p := &minimalPreexecBlockingProxy{minimalL7ConfigTestProxy: &minimalL7ConfigTestProxy{endpoint: endpoint, loss: make(chan struct{})}}
			p.fail.Store(true)
			f.configureNetwork = func(options *l7network.Options) { options.Proxy = p }
			err := f.base.owner.prepareMinimalInputsWithOps(f.host, f.ops)
			if partial {
				minimalPreexecAssertUnavailable(t, err)
			} else if err != nil {
				t.Fatal("actual preparation", err)
			}
			a := f.base.owner.attempt
			if a == nil || a.session == nil || !a.prepareReturned || a.successfulPrepare == partial {
				t.Fatal("did not retain actual appropriate Session")
			}
			if partial && (a.lossDone != nil || p.stops.Load() != 1 || f.seedCalls.Load() != 0) {
				t.Fatal("failed Prepare claimed an armed loss watcher")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			receipt, err := f.base.owner.Finalize(ctx)
			cancel()
			minimalPreexecAssertUnavailable(t, err)
			if receipt != (sandboxruntime.MinimalLaunchCleanupReceipt{}) || a.rollbackComplete || !a.filesClosed || a.session == nil {
				t.Fatal("failed rollback uncertainty discarded")
			}
			want := int32(1)
			if partial {
				want = 2
			}
			if p.stops.Load() != want {
				t.Fatal("actual rollback retry path not reached", p.stops.Load())
			}
			p.fail.Store(false)
			minimalPreexecFinalizeFixture(t, f)
			if p.stops.Load() != want+1 || f.base.owner.attempt != a || a.session.Metadata().Status != l7network.StatusStopped {
				t.Fatal("retry did not clean the same retained Session")
			}
		})
	}
}

func TestMinimalPreexecHostClosePreservesJobOwnedDuplicates(t *testing.T) {
	f := newMinimalPreexecAssemblyFixture(t)
	if err := f.base.owner.prepareMinimalInputsWithOps(f.host, f.ops); err != nil {
		t.Fatal(err)
	}
	a := f.base.owner.attempt
	if err := f.host.close(); err != nil {
		t.Fatal(err)
	}
	for _, file := range a.hostFiles {
		if _, err := file.Stat(); err != nil {
			t.Fatal("host closed job-owned duplicate", err)
		}
	}
	if _, _, err := f.host.beginBorrow(); err == nil {
		t.Fatal("closed host admitted borrow")
	}
	minimalPreexecReceive(t, a.ctx.Done())
	minimalPreexecFinalizeFixture(t, f)
}

func TestMinimalPreexecOriginalPreparationExpiryDoesNotRebase(t *testing.T) {
	f := newMinimalPreexecAssemblyFixture(t)
	// Wait for the original real reservation, not a replacement context.
	<-f.base.preparation.Done()
	if f.base.reservation.OwnedContext().Err() != nil {
		t.Fatal("fixture lost distinct original ownership lifetime")
	}
	minimalPreexecAssertUnavailable(t, f.base.owner.prepareMinimalInputsWithOps(f.host, f.ops))
	if f.base.owner.attempt != nil || f.duplicateCalls.Load() != 0 || f.base.owner.preparationDeadline != f.base.p {
		t.Fatal("expired original P was rebased")
	}
	minimalPreexecFinalizeFixture(t, f)
}

func TestMinimalPreexecCancellationAfterActualAdmissionMutexWait(t *testing.T) {
	f := newMinimalPreexecAssemblyFixture(t)
	f.base.owner.source.mu.Lock()
	var unlock sync.Once
	done := make(chan struct{})
	var result error
	go func() { defer close(done); result = f.base.owner.prepareMinimalInputsWithOps(f.host, f.ops) }()
	defer func() { unlock.Do(f.base.owner.source.mu.Unlock); minimalPreexecReceive(t, done) }()
	waitMinimalTemplateMutex(t, "firecrackerhost.(*minimalTemplateAssetOwner).prepareMinimalInputsWithOps")
	f.base.reservation.Revoke()
	unlock.Do(f.base.owner.source.mu.Unlock)
	minimalPreexecReceive(t, done)
	minimalPreexecAssertUnavailable(t, result)
	if f.base.owner.attempt != nil || f.duplicateCalls.Load() != 0 || f.networkCalls.Load() != 0 {
		t.Fatal("post-wait cancellation allocated an attempt")
	}
	minimalPreexecFinalizeFixture(t, f)
}

func TestMinimalPreexecSameHostPreparesIndependentOriginalOwners(t *testing.T) {
	one := newMinimalPreexecAssemblyFixture(t)
	two := newMinimalPreexecAssemblyFixture(t, newMinimalPreexecAssemblyClaim(t, one.base.handoff))
	// Distinct deterministic entropy streams, still through the actual bounded
	// entropy primitive. This is not a claim about live entropy/provisioning.
	read := two.ops.entropy
	two.ops.entropy = func(buffer []byte) (int, error) {
		n, err := read(buffer)
		for i := range buffer {
			buffer[i] ^= 0x40
		}
		return n, err
	}
	results := make(chan error, 2)
	var joined sync.WaitGroup
	joined.Add(2)
	for _, f := range []*minimalPreexecAssemblyFixture{one, two} {
		go func() { defer joined.Done(); results <- f.base.owner.prepareMinimalInputsWithOps(one.host, f.ops) }()
	}
	joined.Wait()
	for i := 0; i < 2; i++ {
		if err := minimalPreexecReceive(t, results); err != nil {
			t.Fatal("same host original job preparation", err)
		}
	}
	a, b := one.base.owner.attempt, two.base.owner.attempt
	if a == nil || b == nil || a == b || a.owner == b.owner || a.host != one.host || b.host != one.host ||
		a.owner.source.provider != b.owner.source.provider || a.owner.lease == b.owner.lease || a.session == b.session || a.coordinator == b.coordinator ||
		a.directoryPin == b.directoryPin || a.networkIdentity.PlanID == b.networkIdentity.PlanID || a.owner.identity.RuntimeGeneration == b.owner.identity.RuntimeGeneration {
		t.Fatal("independent original jobs shared an owner, lease, preparation or directory")
	}
	minimalPreexecFinalizeFixture(t, one)
	if !b.current() || b.owner.lease.ConfirmCurrent(b.ctx) != nil {
		t.Fatal("one job cleanup retired another job")
	}
	for _, file := range append(b.hostFiles[:], b.namespace[:]...) {
		if _, err := file.Stat(); err != nil {
			t.Fatal("other job FD closed", err)
		}
	}
	minimalPreexecFinalizeFixture(t, two)
}

func TestMinimalPreexecLastCallbackCannotPublishAfterLossOrCancel(t *testing.T) {
	for _, cause := range []string{"original cancellation", "actual Session loss"} {
		t.Run(cause, func(t *testing.T) {
			f := newMinimalPreexecAssemblyFixture(t)
			var proxy *minimalL7ConfigTestProxy
			f.configureNetwork = func(options *l7network.Options) { proxy = options.Proxy.(*minimalL7ConfigTestProxy) }
			seal := f.ops.seal
			var returned *os.File
			f.ops.seal = func(ctx context.Context, payload []byte) (*os.File, error) {
				actual, err := seal(ctx, payload)
				if err != nil {
					return actual, err
				}
				if f.sealCalls.Load() == 2 {
					returned = actual
					if cause == "original cancellation" {
						f.base.reservation.Revoke()
					} else {
						proxy.stop.Do(func() { close(proxy.loss) })
						minimalPreexecReceive(t, f.base.owner.attempt.ctx.Done())
					}
				}
				return actual, nil
			}
			minimalPreexecAssertUnavailable(t, f.base.owner.prepareMinimalInputsWithOps(f.host, f.ops))
			a := f.base.owner.attempt
			if a == nil || a.prepared || a.configFile != returned || f.sealCalls.Load() != 2 || returned == nil ||
				cause == "actual Session loss" && !a.lost.Load() {
				t.Fatal("did not reach late loss/cancel with original allocated config retained")
			}
			minimalPreexecFinalizeFixture(t, f)
		})
	}
}
