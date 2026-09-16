package registry

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestRegistryFetchCanceledGenerationCannotRetireLiveReplacement(t *testing.T) {
	oldStarted, oldCleaning, oldFinished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	newStarted, newFinished := make(chan struct{}), make(chan struct{})
	oldGate, newGate := make(chan struct{}), make(chan struct{})
	releaseOld := sync.OnceFunc(func() { close(oldGate) })
	releaseNew := sync.OnceFunc(func() { close(newGate) })
	defer releaseOld()
	defer releaseNew()
	var calls atomic.Int32
	resolver, request, layer := newFetchOwnershipResolver(t, func(r *http.Request, layer []byte) (*http.Response, error) {
		switch calls.Add(1) {
		case 1:
			defer close(oldFinished)
			close(oldStarted)
			<-r.Context().Done()
			close(oldCleaning)
			<-oldGate
			return nil, r.Context().Err()
		case 2:
			defer close(newFinished)
			close(newStarted)
			select {
			case <-newGate:
				return fetchOwnershipResponse(MediaTypeTemplateYAML, layer), nil
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		default:
			return nil, errors.New("live replacement was unexpectedly refetched")
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Cleanup(func() {
		awaitFetchSignal(t, oldFinished, "old callback join")
		awaitFetchSignal(t, newFinished, "replacement callback join")
	})
	oldDone := startFetchOwnershipResolve(t, resolver, ctx, request)
	awaitFetchSignal(t, oldStarted, "old callback start")
	cancel()
	awaitFetchSignal(t, oldCleaning, "old callback cancellation")
	newDone := startFetchOwnershipResolve(t, resolver, context.Background(), request)
	awaitFetchSignal(t, newStarted, "replacement callback start")
	releaseOld()
	// Joining the old canceled owner must not join a new generation with the
	// same key, nor may old failure retirement remove that live replacement.
	if result := awaitFetchResult(t, oldDone); !errors.Is(result.err, context.Canceled) {
		t.Fatalf("old Resolve error = %v", result.err)
	}
	otherDone := startFetchOwnershipResolve(t, resolver, context.Background(), request)
	key := request.Reference.Ref[strings.LastIndexByte(request.Reference.Ref, '@')+1:]
	waitForFetchOwners(t, &resolver.fetches, key, 2)
	if calls.Load() != 2 {
		t.Fatalf("layer calls = %d, want one old and one shared replacement", calls.Load())
	}
	releaseNew()
	for _, done := range []<-chan fetchOwnershipResult{newDone, otherDone} {
		result := awaitFetchResult(t, done)
		if result.err != nil || !bytes.Equal(result.result.TemplateBytes, layer) {
			t.Fatalf("replacement owner result = %v, want verified bytes", result.err)
		}
	}
}
