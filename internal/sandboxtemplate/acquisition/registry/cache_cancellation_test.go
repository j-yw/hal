package registry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestL9FileCacheCancellationBeforeRenamePublishesNoFinalEntry(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	layer := []byte("apiVersion: sandbox-template.hal.dev/v1\nkind: SandboxTemplate\n")
	manifestDigest := "sha256:" + strings.Repeat("a", 64)
	ctx, cancel := context.WithCancel(context.Background())
	cache := NewFileCache(root)
	cache.beforePublish = cancel

	err := cache.Store(ctx, CacheEntry{
		ManifestDigest: manifestDigest,
		LayerDigest:    digestString(layer),
		MediaType:      MediaTypeTemplateYAML,
		LayerBytes:     layer,
	})
	var registryErr *Error
	if !errors.As(err, &registryErr) || registryErr.Code != ErrorCodeRequestCanceled {
		t.Fatalf("Store() error = %v, want request_canceled", err)
	}
	finalPath := filepath.Join(root, strings.TrimPrefix(manifestDigest, "sha256:"))
	if _, statErr := os.Lstat(finalPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("canceled cache publication left final entry: %v", statErr)
	}
	entries, readErr := os.ReadDir(root)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("canceled cache publication left temporary entries: %#v", entries)
	}
}

func TestL9FileCacheCancellationAfterRenamePublishesNoFinalEntry(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	layer := []byte("apiVersion: sandbox-template.hal.dev/v1\nkind: SandboxTemplate\n")
	manifestDigest := "sha256:" + strings.Repeat("b", 64)
	ctx := &cancelOnThirdErrContext{Context: context.Background()}
	cache := NewFileCache(root)

	err := cache.Store(ctx, CacheEntry{
		ManifestDigest: manifestDigest,
		LayerDigest:    digestString(layer),
		MediaType:      MediaTypeTemplateYAML,
		LayerBytes:     layer,
	})
	var registryErr *Error
	if !errors.As(err, &registryErr) || registryErr.Code != ErrorCodeRequestCanceled {
		t.Fatalf("Store() error = %v, want request_canceled", err)
	}
	finalPath := filepath.Join(root, strings.TrimPrefix(manifestDigest, "sha256:"))
	if _, statErr := os.Lstat(finalPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("canceled cache publication left final entry: %v", statErr)
	}
	entries, readErr := os.ReadDir(root)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("canceled cache publication left entries: %#v", entries)
	}
}

type cancelOnThirdErrContext struct {
	context.Context
	calls atomic.Int32
}

func (c *cancelOnThirdErrContext) Err() error {
	if c.calls.Add(1) >= 3 {
		return context.Canceled
	}
	return nil
}
