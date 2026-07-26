package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
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

type FileCache struct {
	root string
	mu   sync.Mutex
}

func NewFileCache(root string) *FileCache {
	cache := &FileCache{root: filepath.Clean(root)}
	if info, err := os.Lstat(cache.root); err == nil &&
		info.Mode()&os.ModeSymlink == 0 &&
		info.IsDir() &&
		fileOwnedByCurrentUser(info) {
		_ = os.Chmod(cache.root, 0o700)
	}
	return cache
}

type cacheMetadata struct {
	ManifestDigest string `json:"manifestDigest"`
	LayerDigest    string `json:"layerDigest"`
	MediaType      string `json:"mediaType"`
	SizeBytes      int64  `json:"sizeBytes"`
}

func (c *FileCache) Load(ctx context.Context, lookup CacheLookup) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, requestContextError(err)
	}
	if c == nil || !validCacheLookup(lookup) {
		return nil, false, coded(ErrorCodeCacheInvalid, nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureRoot(false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, coded(ErrorCodeCacheInvalid, err)
	}
	entryDir := c.entryDir(lookup.ManifestDigest)
	entryInfo, err := os.Lstat(entryDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || validateOwnedMode(entryInfo, true, 0o700) != nil {
		return nil, false, coded(ErrorCodeCacheInvalid, err)
	}
	metadataBytes, err := readCacheFile(filepath.Join(entryDir, "metadata.json"), 16<<10)
	if err != nil {
		return nil, false, coded(ErrorCodeCacheInvalid, err)
	}
	var metadata cacheMetadata
	decoder := json.NewDecoder(bytes.NewReader(metadataBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil || ensureJSONEOF(decoder) != nil {
		return nil, false, coded(ErrorCodeCacheInvalid, err)
	}
	if metadata.ManifestDigest != lookup.ManifestDigest ||
		metadata.LayerDigest != lookup.LayerDigest ||
		metadata.MediaType != lookup.MediaType ||
		metadata.SizeBytes != lookup.SizeBytes {
		return nil, false, coded(ErrorCodeCacheInvalid, nil)
	}
	layerPath := filepath.Join(entryDir, "layer")
	layerBytes, err := readCacheFile(layerPath, int(lookup.SizeBytes)+1)
	if err != nil ||
		int64(len(layerBytes)) != lookup.SizeBytes ||
		digestString(layerBytes) != lookup.LayerDigest {
		return nil, false, coded(ErrorCodeCacheInvalid, err)
	}
	return layerBytes, true, nil
}

func (c *FileCache) Store(ctx context.Context, entry CacheEntry) error {
	if err := ctx.Err(); err != nil {
		return requestContextError(err)
	}
	if c == nil || !validCacheEntry(entry) {
		return coded(ErrorCodeCachePublishFailed, nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureRoot(true); err != nil {
		return coded(ErrorCodeCachePublishFailed, err)
	}
	finalDir := c.entryDir(entry.ManifestDigest)
	if info, err := os.Lstat(finalDir); err == nil {
		if validateOwnedMode(info, true, 0o700) != nil {
			return coded(ErrorCodeCacheInvalid, nil)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return coded(ErrorCodeCachePublishFailed, err)
	}

	tempDir, err := os.MkdirTemp(c.root, ".tmp-")
	if err != nil {
		return coded(ErrorCodeCachePublishFailed, err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tempDir)
		}
	}()
	if err := os.Chmod(tempDir, 0o700); err != nil {
		return coded(ErrorCodeCachePublishFailed, err)
	}
	metadataBytes, err := json.Marshal(cacheMetadata{
		ManifestDigest: entry.ManifestDigest,
		LayerDigest:    entry.LayerDigest,
		MediaType:      entry.MediaType,
		SizeBytes:      int64(len(entry.LayerBytes)),
	})
	if err != nil {
		return coded(ErrorCodeCachePublishFailed, err)
	}
	if err := writeSyncedFile(filepath.Join(tempDir, "metadata.json"), metadataBytes); err != nil {
		return coded(ErrorCodeCachePublishFailed, err)
	}
	if err := writeSyncedFile(filepath.Join(tempDir, "layer"), entry.LayerBytes); err != nil {
		return coded(ErrorCodeCachePublishFailed, err)
	}
	if err := syncDirectory(tempDir); err != nil {
		return coded(ErrorCodeCachePublishFailed, err)
	}
	if err := os.Rename(tempDir, finalDir); err != nil {
		if _, statErr := os.Lstat(finalDir); statErr == nil {
			return nil
		}
		return coded(ErrorCodeCachePublishFailed, err)
	}
	cleanup = false
	if err := syncDirectory(c.root); err != nil {
		return coded(ErrorCodeCachePublishFailed, err)
	}
	return nil
}

func (c *FileCache) ensureRoot(create bool) error {
	info, err := os.Lstat(c.root)
	if errors.Is(err, os.ErrNotExist) && create {
		if err := os.MkdirAll(c.root, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(c.root, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(c.root)
	}
	if err != nil {
		return err
	}
	if create && info.Mode()&os.ModeSymlink == 0 && info.IsDir() && fileOwnedByCurrentUser(info) && info.Mode().Perm() != 0o700 {
		if err := os.Chmod(c.root, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(c.root)
		if err != nil {
			return err
		}
	}
	return validateOwnedMode(info, true, 0o700)
}

func (c *FileCache) entryDir(manifestDigest string) string {
	return filepath.Join(c.root, strings.TrimPrefix(manifestDigest, "sha256:"))
}

func validCacheLookup(lookup CacheLookup) bool {
	return validDigest(lookup.ManifestDigest) &&
		validDigest(lookup.LayerDigest) &&
		(lookup.MediaType == MediaTypeTemplateYAML || lookup.MediaType == MediaTypeTemplateJSON) &&
		lookup.SizeBytes >= 0 &&
		lookup.SizeBytes <= DefaultMaxLayerBytes
}

func validCacheEntry(entry CacheEntry) bool {
	return validCacheLookup(CacheLookup{
		ManifestDigest: entry.ManifestDigest,
		LayerDigest:    entry.LayerDigest,
		MediaType:      entry.MediaType,
		SizeBytes:      int64(len(entry.LayerBytes)),
	}) && digestString(entry.LayerBytes) == entry.LayerDigest
}

func validateOwnedMode(info os.FileInfo, directory bool, mode os.FileMode) error {
	if info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || info.Mode().Perm() != mode {
		return errors.New("cache entry metadata is invalid")
	}
	if !fileOwnedByCurrentUser(info) {
		return errors.New("cache entry owner is invalid")
	}
	return nil
}

func fileOwnedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

func readCacheFile(path string, limit int) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || validateOwnedMode(before, false, 0o600) != nil {
		return nil, errors.New("cache file is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(data) > limit {
		return nil, errors.New("cache file is oversized")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("cache file changed during read")
	}
	return data, nil
}

func writeSyncedFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}

type fetchGroup struct {
	mu    sync.Mutex
	calls map[string]*fetchCall
}

type fetchCall struct {
	done chan struct{}
	data []byte
	err  error
}

func (g *fetchGroup) do(key string, fn func() ([]byte, error)) ([]byte, error) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = make(map[string]*fetchCall)
	}
	if call := g.calls[key]; call != nil {
		g.mu.Unlock()
		<-call.done
		return append([]byte(nil), call.data...), call.err
	}
	call := &fetchCall{done: make(chan struct{})}
	g.calls[key] = call
	g.mu.Unlock()

	call.data, call.err = fn()
	close(call.done)
	if call.err != nil {
		g.forget(key)
	}
	return append([]byte(nil), call.data...), call.err
}

func (g *fetchGroup) forget(key string) {
	g.mu.Lock()
	delete(g.calls, key)
	g.mu.Unlock()
}
