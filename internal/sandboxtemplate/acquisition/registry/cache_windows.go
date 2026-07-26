//go:build windows

package registry

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
)

type Cache interface {
	Load(context.Context, CacheLookup) ([]byte, bool, error)
	Store(context.Context, CacheEntry) error
}

type CacheLookup struct {
	ManifestDigest string
	LayerDigest    string
	MediaType      string
	SizeBytes      int64
}

type CacheEntry struct {
	ManifestDigest string
	LayerDigest    string
	MediaType      string
	LayerBytes     []byte
}

// FileCache fails closed on Windows because L9 does not yet own an equivalent
// no-follow, descriptor-relative, owner/DACL-verified cache implementation.
type FileCache struct {
	root          string
	invalid       bool
	mu            sync.Mutex
	beforePublish func()
}

func NewFileCache(root string) *FileCache {
	cleaned := filepath.Clean(root)
	return &FileCache{
		root:    cleaned,
		invalid: strings.TrimSpace(root) == "" || !filepath.IsAbs(cleaned),
	}
}

func (c *FileCache) Load(ctx context.Context, _ CacheLookup) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, requestContextError(err)
	}
	return nil, false, coded(ErrorCodeCacheInvalid, nil)
}

func (c *FileCache) Store(ctx context.Context, _ CacheEntry) error {
	if err := ctx.Err(); err != nil {
		return requestContextError(err)
	}
	return coded(ErrorCodeCachePublishFailed, nil)
}

type fetchGroup struct {
	mu    sync.Mutex
	calls map[string]*fetchCall
}

type fetchCall struct {
	done   chan struct{}
	cancel context.CancelFunc
	owners int
	data   []byte
	err    error
}

func (g *fetchGroup) do(ctx context.Context, key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = make(map[string]*fetchCall)
	}
	call := g.calls[key]
	if call == nil {
		fetchCtx, cancel := context.WithCancel(context.Background())
		call = &fetchCall{done: make(chan struct{}), cancel: cancel}
		g.calls[key] = call
		go g.run(key, call, fetchCtx, fn)
	}
	call.owners++
	g.mu.Unlock()

	select {
	case <-call.done:
		g.releaseOwner(key, call, false)
		return append([]byte(nil), call.data...), call.err
	case <-ctx.Done():
		g.releaseOwner(key, call, true)
		return nil, ctx.Err()
	}
}

func (g *fetchGroup) run(key string, call *fetchCall, ctx context.Context, fn func(context.Context) ([]byte, error)) {
	call.data, call.err = fn(ctx)
	close(call.done)
	if call.err != nil {
		g.mu.Lock()
		if g.calls[key] == call {
			delete(g.calls, key)
		}
		g.mu.Unlock()
	}
}

func (g *fetchGroup) releaseOwner(key string, call *fetchCall, canceled bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if call.owners > 0 {
		call.owners--
	}
	if canceled && call.owners == 0 {
		call.cancel()
		if g.calls[key] == call {
			delete(g.calls, key)
		}
	}
}

func (g *fetchGroup) forget(key string) {
	g.mu.Lock()
	if call := g.calls[key]; call != nil {
		call.cancel()
		delete(g.calls, key)
	}
	g.mu.Unlock()
}
