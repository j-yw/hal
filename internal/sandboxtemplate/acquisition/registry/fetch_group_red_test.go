package registry

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestL9FetchGroupWaiterCancellationIsIndependent(t *testing.T) {
	var fetches atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	group := &fetchGroup{}
	fetch := func(ctx context.Context) ([]byte, error) {
		if fetches.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
			return []byte("verified"), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, _, err := group.do(leaderCtx, "sha256:fixture", fetch)
		leaderDone <- err
	}()
	<-started
	liveDone := make(chan error, 1)
	go func() {
		data, releaseFetch, err := group.do(context.Background(), "sha256:fixture", fetch)
		if releaseFetch != nil {
			defer releaseFetch()
		}
		if err == nil && string(data) != "verified" {
			err = errors.New("waiter received different bytes")
		}
		liveDone <- err
	}()
	waitForFetchOwners(t, group, "sha256:fixture", 2)
	cancelLeader()
	select {
	case err := <-leaderDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("leader error = %v, want canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled leader did not return promptly")
	}
	close(release)
	if err := <-liveDone; err != nil {
		t.Fatalf("live waiter error = %v", err)
	}
	if fetches.Load() != 1 {
		t.Fatalf("fetches = %d, want one shared fetch", fetches.Load())
	}
}

func waitForFetchOwners(t *testing.T, group *fetchGroup, key string, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		group.mu.Lock()
		call := group.calls[key]
		owners := 0
		if call != nil {
			owners = call.owners
		}
		group.mu.Unlock()
		if owners == want {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("fetch owners did not reach %d", want)
}

func TestL9FetchGroupCancelsSharedFetchAfterAllOwnersCancel(t *testing.T) {
	var fetches atomic.Int32
	fetchCanceled := make(chan struct{})
	group := &fetchGroup{}
	fetch := func(ctx context.Context) ([]byte, error) {
		fetches.Add(1)
		<-ctx.Done()
		close(fetchCanceled)
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, err := group.do(ctx, "sha256:fixture", fetch)
		done <- err
	}()
	cancel()
	select {
	case <-fetchCanceled:
	case <-time.After(time.Second):
		t.Fatal("shared fetch remained orphaned after all owners canceled")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("owner error = %v, want canceled", err)
	}
	if fetches.Load() != 1 {
		t.Fatalf("fetches = %d, want one", fetches.Load())
	}
}

func TestL9FetchGroupStaleReleaseCannotCancelNewGeneration(t *testing.T) {
	group := &fetchGroup{}
	key := "sha256:fixture"
	_, firstRelease, err := group.do(context.Background(), key, func(context.Context) ([]byte, error) {
		return []byte("old-generation"), nil
	})
	if err != nil {
		t.Fatalf("old generation error = %v", err)
	}
	_, staleRelease, err := group.do(context.Background(), key, func(context.Context) ([]byte, error) {
		return nil, errors.New("old generation unexpectedly refetched")
	})
	if err != nil {
		t.Fatalf("old generation waiter error = %v", err)
	}

	// Two callers that completed against the old generation have distinct
	// deferred releases. The first retires the old call; the second must not be
	// able to retire a replacement call with the same key.
	firstRelease()

	started := make(chan struct{})
	release := make(chan struct{})
	canceled := make(chan struct{})
	newDone := make(chan error, 1)
	go func() {
		data, releaseFetch, err := group.do(context.Background(), key, func(ctx context.Context) ([]byte, error) {
			close(started)
			select {
			case <-release:
				return []byte("new-generation"), nil
			case <-ctx.Done():
				close(canceled)
				return nil, ctx.Err()
			}
		})
		if releaseFetch != nil {
			defer releaseFetch()
		}
		if err == nil && string(data) != "new-generation" {
			err = errors.New("new generation returned different bytes")
		}
		newDone <- err
	}()
	<-started
	staleRelease()
	group.mu.Lock()
	newCall := group.calls[key]
	group.mu.Unlock()
	if newCall == nil {
		t.Fatal("stale release removed the new fetch generation")
	}
	select {
	case <-canceled:
		t.Fatal("stale release canceled the new fetch generation")
	default:
	}
	close(release)
	if err := <-newDone; err != nil {
		t.Fatalf("new generation error = %v", err)
	}
}
