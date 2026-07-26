package registry_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition/registry"
)

func TestL9FileCacheRoundTripUsesOnlyVerifiedManifestIdentity(t *testing.T) {
	fixture := newRegistryFixture(t)
	root := t.TempDir()
	cache := registry.NewFileCache(root)
	entry := registry.CacheEntry{
		ManifestDigest: fixture.manifestDigest,
		LayerDigest:    fixture.layerDigest,
		MediaType:      registry.MediaTypeTemplateYAML,
		LayerBytes:     fixture.template,
	}
	if err := cache.Store(context.Background(), entry); err != nil {
		t.Fatalf("Store() error = %v (cause %v)", err, errors.Unwrap(err))
	}
	got, hit, err := cache.Load(context.Background(), registry.CacheLookup{
		ManifestDigest: fixture.manifestDigest,
		LayerDigest:    fixture.layerDigest,
		MediaType:      registry.MediaTypeTemplateYAML,
		SizeBytes:      int64(len(fixture.template)),
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !hit || !bytes.Equal(got, fixture.template) {
		t.Fatalf("Load() = hit %v bytes %q", hit, got)
	}
	paths, err := filepath.Glob(filepath.Join(root, "*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		base := filepath.Base(path)
		if strings.Contains(base, "registry") || strings.Contains(base, "template") || strings.Contains(base, "latest") {
			t.Fatalf("cache name contains reference-derived data: %q", base)
		}
	}
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Mode().Perm() != 0o700 {
				t.Errorf("directory %s mode = %o, want 700", filepath.Base(path), info.Mode().Perm())
			}
			return nil
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("file %s mode = %o, want 600", filepath.Base(path), info.Mode().Perm())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestL9FileCacheRejectsSymlinksWrongModesAndCorruption(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Fatal("L9 cache safety acceptance requires Unix ownership and mode semantics")
	}
	fixture := newRegistryFixture(t)
	tests := []struct {
		name    string
		prepare func(t *testing.T, root string, cache *registry.FileCache)
	}{
		{
			name: "symlink root",
			prepare: func(t *testing.T, root string, _ *registry.FileCache) {
				target := t.TempDir()
				if err := os.Remove(root); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, root); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "permissive root",
			prepare: func(t *testing.T, root string, _ *registry.FileCache) {
				if err := os.Chmod(root, 0o777); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink entry",
			prepare: func(t *testing.T, root string, _ *registry.FileCache) {
				if err := os.Symlink(t.TempDir(), filepath.Join(root, strings.TrimPrefix(fixture.manifestDigest, "sha256:"))); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "incomplete entry",
			prepare: func(t *testing.T, root string, _ *registry.FileCache) {
				path := filepath.Join(root, strings.TrimPrefix(fixture.manifestDigest, "sha256:"))
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "cache")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			cache := registry.NewFileCache(root)
			tt.prepare(t, root, cache)
			_, _, err := cache.Load(context.Background(), registry.CacheLookup{
				ManifestDigest: fixture.manifestDigest,
				LayerDigest:    fixture.layerDigest,
				MediaType:      registry.MediaTypeTemplateYAML,
				SizeBytes:      int64(len(fixture.template)),
			})
			requireRegistryErrorCode(t, err, registry.ErrorCodeCacheInvalid)
		})
	}
}

func TestL9FileCacheDetectsChangeDuringReadOrReturnsOnlyVerifiedBytes(t *testing.T) {
	fixture := newRegistryFixture(t)
	cache := registry.NewFileCache(t.TempDir())
	entry := registry.CacheEntry{
		ManifestDigest: fixture.manifestDigest,
		LayerDigest:    fixture.layerDigest,
		MediaType:      registry.MediaTypeTemplateYAML,
		LayerBytes:     fixture.template,
	}
	if err := cache.Store(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = cache.Store(context.Background(), entry)
			}
		}
	}()
	for i := 0; i < 100; i++ {
		got, hit, err := cache.Load(context.Background(), registry.CacheLookup{
			ManifestDigest: fixture.manifestDigest,
			LayerDigest:    fixture.layerDigest,
			MediaType:      registry.MediaTypeTemplateYAML,
			SizeBytes:      int64(len(fixture.template)),
		})
		if err != nil {
			if !strings.Contains(err.Error(), string(registry.ErrorCodeCacheInvalid)) {
				t.Fatalf("Load() error = %v", err)
			}
			continue
		}
		if hit && !bytes.Equal(got, fixture.template) {
			t.Fatal("cache returned changed or partially published bytes")
		}
	}
	close(stop)
	writer.Wait()
}

func TestL9FileCacheRejectsCorruptionAndEntryFileSymlinksAfterSuccess(t *testing.T) {
	fixture := newRegistryFixture(t)
	for _, mode := range []string{"corrupt", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			cache := registry.NewFileCache(root)
			entry := registry.CacheEntry{
				ManifestDigest: fixture.manifestDigest,
				LayerDigest:    fixture.layerDigest,
				MediaType:      registry.MediaTypeTemplateYAML,
				LayerBytes:     fixture.template,
			}
			if err := cache.Store(context.Background(), entry); err != nil {
				t.Fatal(err)
			}
			layerPath := largestRegularFile(t, root)
			if mode == "corrupt" {
				if err := os.WriteFile(layerPath, []byte("corrupt cache bytes"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				target := filepath.Join(t.TempDir(), "attacker-data")
				if err := os.WriteFile(target, fixture.template, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(layerPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, layerPath); err != nil {
					t.Fatal(err)
				}
			}
			_, _, err := cache.Load(context.Background(), registry.CacheLookup{
				ManifestDigest: fixture.manifestDigest,
				LayerDigest:    fixture.layerDigest,
				MediaType:      registry.MediaTypeTemplateYAML,
				SizeBytes:      int64(len(fixture.template)),
			})
			requireRegistryErrorCode(t, err, registry.ErrorCodeCacheInvalid)
		})
	}
}

func TestL9FileCachePublicationCoalescesConcurrentWriters(t *testing.T) {
	fixture := newRegistryFixture(t)
	cache := registry.NewFileCache(t.TempDir())
	entry := registry.CacheEntry{
		ManifestDigest: fixture.manifestDigest,
		LayerDigest:    fixture.layerDigest,
		MediaType:      registry.MediaTypeTemplateYAML,
		LayerBytes:     fixture.template,
	}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- cache.Store(context.Background(), entry)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Store() error = %v", err)
		}
	}
	got, hit, err := cache.Load(context.Background(), registry.CacheLookup{
		ManifestDigest: fixture.manifestDigest,
		LayerDigest:    fixture.layerDigest,
		MediaType:      registry.MediaTypeTemplateYAML,
		SizeBytes:      int64(len(fixture.template)),
	})
	if err != nil || !hit || !bytes.Equal(got, fixture.template) {
		t.Fatalf("Load() after concurrent publication = %q, %v, %v", got, hit, err)
	}
}

func TestL9FileCacheImplementationUsesLstatFsyncAndSameDirectoryRename(t *testing.T) {
	content, err := os.ReadFile("cache.go")
	if err != nil {
		t.Fatalf("ReadFile(cache.go): %v", err)
	}
	source := string(content)
	for _, required := range []string{"os.Lstat", ".Sync()", "os.Rename", "MkdirTemp", "0o700", "0o600", "Stat_t", "Uid"} {
		if !strings.Contains(source, required) {
			t.Errorf("cache.go missing crash/containment primitive %q", required)
		}
	}
}

func largestRegularFile(t *testing.T, root string) string {
	t.Helper()
	var selected string
	var selectedSize int64 = -1
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() && info.Size() > selectedSize {
			selected = path
			selectedSize = info.Size()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if selected == "" {
		t.Fatal("cache contains no regular entry file")
	}
	return selected
}
