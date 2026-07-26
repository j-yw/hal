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
		_, err := group.do(leaderCtx, "sha256:fixture", fetch)
		leaderDone <- err
	}()
	<-started
	liveDone := make(chan error, 1)
	go func() {
		data, err := group.do(context.Background(), "sha256:fixture", fetch)
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
	group.forget("sha256:fixture")
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
		_, err := group.do(ctx, "sha256:fixture", fetch)
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
