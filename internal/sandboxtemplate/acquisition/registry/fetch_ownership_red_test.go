package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
)

func TestRegistryFetchLastOwnerJoinsCleanup(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "canceled"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			started, cleaning, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			release := make(chan struct{})
			releaseCleanup := sync.OnceFunc(func() { close(release) })
			defer releaseCleanup()
			resolver, request, _ := newFetchOwnershipResolver(t, func(r *http.Request, _ []byte) (*http.Response, error) {
				defer close(finished)
				close(started)
				<-r.Context().Done()
				close(cleaning)
				<-release
				return nil, r.Context().Err()
			})
			ctx, cancel := context.WithCancel(context.Background())
			wantErr, wantCode := context.Canceled, ErrorCodeRequestCanceled
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 150*time.Millisecond)
				wantErr, wantCode = context.DeadlineExceeded, ErrorCodeRequestTimeout
			}
			defer cancel()
			t.Cleanup(func() { awaitFetchSignal(t, finished, "layer callback join") })
			done := startFetchOwnershipResolve(t, resolver, ctx, request)
			awaitFetchSignal(t, started, "layer callback start")
			if !deadline {
				cancel()
			}
			awaitFetchSignal(t, cleaning, "layer callback cancellation")
			var result fetchOwnershipResult
			returned := false
			select {
			case result = <-done:
				returned = true
				t.Error("Resolve returned while the last-owned layer callback was still cleaning up")
			case <-time.After(100 * time.Millisecond):
			}
			releaseCleanup()
			awaitFetchSignal(t, finished, "layer callback cleanup completion")
			if !returned {
				result = awaitFetchResult(t, done)
			}
			var safe *Error
			if !errors.Is(result.err, wantErr) || !errors.As(result.err, &safe) || safe.Code != wantCode || result.result.TemplateBytes != nil {
				t.Fatalf("Resolve result = %#v, %v; want no bytes and %s", result.result, result.err, wantCode)
			}
		})
	}
}

func TestRegistryFetchCleanupDoesNotBlockReplacementGeneration(t *testing.T) {
	started, cleaning, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	releaseOld := make(chan struct{})
	finishOld := sync.OnceFunc(func() { close(releaseOld) })
	defer finishOld()
	var calls atomic.Int32
	resolver, request, layer := newFetchOwnershipResolver(t, func(r *http.Request, layer []byte) (*http.Response, error) {
		if calls.Add(1) != 1 {
			return fetchOwnershipResponse(MediaTypeTemplateYAML, layer), nil
		}
		defer close(finished)
		close(started)
		<-r.Context().Done()
		close(cleaning)
		<-releaseOld
		return nil, r.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Cleanup(func() { awaitFetchSignal(t, finished, "old generation callback join") })
	oldDone := startFetchOwnershipResolve(t, resolver, ctx, request)
	awaitFetchSignal(t, started, "old generation start")
	cancel()
	awaitFetchSignal(t, cleaning, "old generation cleanup")
	// This must complete while the old callback's cleanup is held: joining
	// under the group lock or waiting on all generations would deadlock here.
	newDone := startFetchOwnershipResolve(t, resolver, context.Background(), request)
	result := awaitFetchResult(t, newDone)
	if result.err != nil || !bytes.Equal(result.result.TemplateBytes, layer) || calls.Load() != 2 {
		t.Fatalf("replacement result = %v, calls = %d; want fresh verified bytes", result.err, calls.Load())
	}
	finishOld()
	awaitFetchSignal(t, finished, "old generation completion")
	if result := awaitFetchResult(t, oldDone); !errors.Is(result.err, context.Canceled) {
		t.Fatalf("old Resolve error = %v", result.err)
	}
	// Finishing the old call must not poison later acquisition of the same key.
	result = awaitFetchResult(t, startFetchOwnershipResolve(t, resolver, context.Background(), request))
	if result.err != nil || !bytes.Equal(result.result.TemplateBytes, layer) || calls.Load() != 3 {
		t.Fatalf("later result = %v, calls = %d", result.err, calls.Load())
	}
}

func TestRegistryFetchLayerPanicIsContained(t *testing.T) {
	const childKey = "HAL_TEST_REGISTRY_FETCH_PANIC"
	const canary = "synthetic-private-layer-panic"
	if mode := os.Getenv(childKey); mode != "" {
		var calls, cleaned atomic.Int32
		started, release := make(chan struct{}), make(chan struct{})
		releasePanic := sync.OnceFunc(func() { close(release) })
		defer releasePanic()
		resolver, request, layer := newFetchOwnershipResolver(t, func(_ *http.Request, layer []byte) (*http.Response, error) {
			if calls.Add(1) != 1 {
				return fetchOwnershipResponse(MediaTypeTemplateYAML, layer), nil
			}
			close(started)
			<-release
			if mode == "do" {
				defer cleaned.Add(1)
				panic(canary)
			}
			response := fetchOwnershipResponse(MediaTypeTemplateYAML, layer)
			response.Body = &fetchOwnershipPanicBody{Reader: bytes.NewReader(layer), mode: mode, cleaned: &cleaned}
			return response, nil
		})
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		first := startFetchOwnershipResolve(t, resolver, ctx, request)
		awaitFetchSignal(t, started, "panicking callback start")
		second := startFetchOwnershipResolve(t, resolver, ctx, request)
		key := request.Reference.Ref[strings.LastIndexByte(request.Reference.Ref, '@')+1:]
		waitForFetchOwners(t, &resolver.fetches, key, 2)
		releasePanic()
		for _, done := range []<-chan fetchOwnershipResult{first, second} {
			result := awaitFetchResult(t, done)
			var safe *Error
			if !errors.As(result.err, &safe) || safe.Code != ErrorCodeRegistryUnavailable || safe.Err != nil || result.err.Error() != string(ErrorCodeRegistryUnavailable) || result.result.TemplateBytes != nil || cleaned.Load() != 1 {
				t.Fatalf("panic boundary = %v, bytes = %d, cleanup = %d", result.err, len(result.result.TemplateBytes), cleaned.Load())
			}
		}
		result, err := resolver.ResolveOCIArtifact(ctx, request)
		if err != nil || !bytes.Equal(result.TemplateBytes, layer) || calls.Load() != 2 {
			t.Fatalf("retry after panic = %v, calls = %d", err, calls.Load())
		}
		return
	}
	for _, mode := range []string{"do", "read", "close"} {
		t.Run(mode, func(t *testing.T) {
			// A broken background panic boundary must fail an assertion, not
			// kill the parent test process and prevent the remaining controls.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRegistryFetchLayerPanicIsContained$", "-test.count=1", "-test.timeout=5s")
			child.Env = append(os.Environ(), childKey+"="+mode)
			output, err := child.CombinedOutput()
			if err != nil {
				t.Errorf("layer %s panic escaped returned registry error (child failure: %v)", mode, err)
			}
			if bytes.Contains(output, []byte(canary)) {
				t.Error("layer panic payload escaped through child process output")
			}
		})
	}
}

type fetchOwnershipPanicBody struct {
	*bytes.Reader
	mode    string
	cleaned *atomic.Int32
}

func (b *fetchOwnershipPanicBody) Read(p []byte) (int, error) {
	if b.mode == "read" {
		panic("synthetic-private-layer-panic")
	}
	return b.Reader.Read(p)
}

func (b *fetchOwnershipPanicBody) Close() error {
	b.cleaned.Add(1)
	if b.mode == "close" {
		panic("synthetic-private-layer-panic")
	}
	return nil
}

type fetchOwnershipDoer func(*http.Request) (*http.Response, error)

func (f fetchOwnershipDoer) Do(r *http.Request) (*http.Response, error) { return f(r) }

func newFetchOwnershipResolver(t *testing.T, layerDo func(*http.Request, []byte) (*http.Response, error)) (*Resolver, acquisition.OCIArtifactResolveRequest, []byte) {
	t.Helper()
	layer := []byte("apiVersion: sandbox-template.hal.dev/v1\nkind: SandboxTemplate\n")
	manifestBytes, err := json.Marshal(manifest{
		SchemaVersion: 2, MediaType: MediaTypeOCIManifest, ArtifactType: MediaTypeTemplateArtifact,
		Config: descriptor{MediaType: MediaTypeOCIEmptyConfig, Digest: digestString([]byte("{}")), Size: 2},
		Layers: []descriptor{{MediaType: MediaTypeTemplateYAML, Digest: digestString(layer), Size: int64(len(layer))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewResolver(Options{
		AllowedRegistryOrigins: []string{"https://registry.example"},
		Client: fetchOwnershipDoer(func(r *http.Request) (*http.Response, error) {
			if strings.Contains(r.URL.Path, "/manifests/") {
				return fetchOwnershipResponse(MediaTypeOCIManifest, manifestBytes), nil
			}
			if strings.Contains(r.URL.Path, "/blobs/") {
				return layerDo(r, layer)
			}
			return nil, errors.New("unexpected fixture request")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := acquisition.OCIArtifactResolveRequest{Reference: sandboxtemplate.ImmutableRef{
		Kind: sandboxtemplate.ReferenceKindOCIArtifact, Ref: "registry.example/hal/template@" + digestString(manifestBytes),
	}}
	return resolver, request, layer
}

func fetchOwnershipResponse(mediaType string, data []byte) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{mediaType}}, Body: io.NopCloser(bytes.NewReader(data))}
}

type fetchOwnershipResult struct {
	result acquisition.OCIArtifactResolveResult
	err    error
}

func startFetchOwnershipResolve(t *testing.T, resolver *Resolver, ctx context.Context, request acquisition.OCIArtifactResolveRequest) <-chan fetchOwnershipResult {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	done, joined := make(chan fetchOwnershipResult, 1), make(chan struct{})
	go func() {
		defer close(joined)
		result, err := resolver.ResolveOCIArtifact(ctx, request)
		done <- fetchOwnershipResult{result: result, err: err}
	}()
	t.Cleanup(func() {
		cancel()
		awaitFetchSignal(t, joined, "Resolve goroutine join")
	})
	return done
}

func awaitFetchSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func awaitFetchResult(t *testing.T, done <-chan fetchOwnershipResult) fetchOwnershipResult {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Resolve result")
		return fetchOwnershipResult{}
	}
}
