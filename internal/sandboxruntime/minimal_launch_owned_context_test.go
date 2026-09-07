package sandboxruntime

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMinimalReservationOwnedContextConcurrentRevocation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newMinimalReservationLifetimeFixture(t, parent, 750*time.Millisecond)
	f.start(t)
	owned, preparation := f.reservation.OwnedContext(), f.reservation.Context()
	waitMinimalReservationContext(t, preparation)
	if owned.Err() != nil {
		t.Fatal("fixture did not retain ownership after P")
	}
	const workers = 12
	begin, done := make(chan struct{}), make(chan struct{})
	failures := make(chan string, workers)
	var joined sync.WaitGroup
	for index := range workers {
		joined.Add(1)
		go func() {
			defer joined.Done()
			<-begin
			for range 64 {
				if f.reservation.OwnedContext() != owned || f.reservation.Context() != preparation {
					failures <- "concurrent access replaced original context"
					return
				}
				switch index % 3 {
				case 0:
					f.reservation.Revoke()
				case 1:
					f.authorizer.Close()
				case 2:
					cancel()
				}
			}
		}()
	}
	go func() { joined.Wait(); close(done) }()
	close(begin)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent revoke/access tasks did not join")
	}
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
	waitMinimalReservationContext(t, owned)
	if owned.Err() != context.Canceled || preparation.Err() != context.DeadlineExceeded || f.provider.starts != 1 {
		t.Fatal("concurrent revocation changed preparation history or launch count")
	}
}

// This observer is test-owned. It proves Revoke does not join a consumer's
// blocked cancellation callback; it does not claim joining the internal
// cancel-only authorizer callback, whose asynchronous semantics are unchanged.
func TestMinimalReservationOwnedContextRevokeDoesNotJoinConsumer(t *testing.T) {
	f := newMinimalReservationLifetimeFixture(t, context.Background(), time.Minute)
	f.start(t)
	entered, release, callbackDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	stop := context.AfterFunc(f.reservation.OwnedContext(), func() {
		defer close(callbackDone)
		close(entered)
		<-release
	})
	revokeDone := make(chan struct{})
	t.Cleanup(func() {
		close(release)
		if !stop() {
			select {
			case <-callbackDone:
			case <-time.After(5 * time.Second):
				t.Error("test-owned cancellation observer did not join")
			}
		}
		select {
		case <-revokeDone:
		case <-time.After(5 * time.Second):
			t.Error("Revoke did not join after observer release")
		}
	})
	go func() { f.reservation.Revoke(); close(revokeDone) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("owned cancellation observer never entered")
	}
	select {
	case <-revokeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Revoke waited for a consumer under its caller's lock")
	}
	if f.reservation.OwnedContext().Err() != context.Canceled || f.reservation.Context().Err() != context.Canceled {
		t.Fatal("nonjoining Revoke failed to cancel both contexts")
	}
}
