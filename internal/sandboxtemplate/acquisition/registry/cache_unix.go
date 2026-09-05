//go:build !windows

package registry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
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
	if c == nil || c.invalid || !validCacheLookup(lookup) {
		return nil, false, coded(ErrorCodeCacheInvalid, nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loadLocked(ctx, lookup)
}

func (c *FileCache) loadLocked(ctx context.Context, lookup CacheLookup) ([]byte, bool, error) {
	root, err := openCacheRoot(c.root, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, coded(ErrorCodeCacheInvalid, err)
	}
	defer root.Close()
	return loadCacheEntry(root, lookup)
}

func loadCacheEntry(root *os.File, lookup CacheLookup) ([]byte, bool, error) {
	entry, err := openDirectoryAt(root, cacheEntryName(lookup.ManifestDigest))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, coded(ErrorCodeCacheInvalid, err)
	}
	defer entry.Close()
	if err := validateOpenFile(entry, true, 0o700); err != nil {
		return nil, false, coded(ErrorCodeCacheInvalid, err)
	}
	metadataBytes, err := readCacheFileAt(entry, "metadata.json", 16<<10)
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
	layerBytes, err := readCacheFileAt(entry, "layer", int(lookup.SizeBytes)+1)
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
	if c == nil || c.invalid || !validCacheEntry(entry) {
		return coded(ErrorCodeCachePublishFailed, nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	root, err := openCacheRoot(c.root, true)
	if err != nil {
		return coded(ErrorCodeCachePublishFailed, err)
	}
	defer root.Close()
	lookup := CacheLookup{
		ManifestDigest: entry.ManifestDigest,
		LayerDigest:    entry.LayerDigest,
		MediaType:      entry.MediaType,
		SizeBytes:      int64(len(entry.LayerBytes)),
	}
	if existing, openErr := openDirectoryAt(root, cacheEntryName(entry.ManifestDigest)); openErr == nil {
		_ = existing.Close()
		_, hit, loadErr := loadCacheEntry(root, lookup)
		if loadErr != nil {
			return loadErr
		}
		if !hit {
			return coded(ErrorCodeCacheInvalid, nil)
		}
		return nil
	} else if !errors.Is(openErr, os.ErrNotExist) {
		return coded(ErrorCodeCachePublishFailed, openErr)
	}

	tempName, tempDir, err := createCacheTempDirectory(root)
	if err != nil {
		return coded(ErrorCodeCachePublishFailed, err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Unlinkat(int(tempDir.Fd()), "metadata.json", 0)
			_ = unix.Unlinkat(int(tempDir.Fd()), "layer", 0)
		}
		_ = tempDir.Close()
		if cleanup {
			_ = unix.Unlinkat(int(root.Fd()), tempName, unix.AT_REMOVEDIR)
		}
	}()
	metadataBytes, err := json.Marshal(cacheMetadata{
		ManifestDigest: entry.ManifestDigest,
		LayerDigest:    entry.LayerDigest,
		MediaType:      entry.MediaType,
		SizeBytes:      int64(len(entry.LayerBytes)),
	})
	if err != nil {
		return coded(ErrorCodeCachePublishFailed, err)
	}
	if err := writeSyncedFileAt(tempDir, "metadata.json", metadataBytes); err != nil {
		return coded(ErrorCodeCachePublishFailed, err)
	}
	if err := writeSyncedFileAt(tempDir, "layer", entry.LayerBytes); err != nil {
		return coded(ErrorCodeCachePublishFailed, err)
	}
	if err := tempDir.Sync(); err != nil {
		return coded(ErrorCodeCachePublishFailed, err)
	}
	if c.beforePublish != nil {
		c.beforePublish()
	}
	if err := ctx.Err(); err != nil {
		return requestContextError(err)
	}
	finalName := cacheEntryName(entry.ManifestDigest)
	if err := unix.Renameat(int(root.Fd()), tempName, int(root.Fd()), finalName); err != nil {
		if errors.Is(err, unix.EEXIST) || errors.Is(err, unix.ENOTEMPTY) {
			_, hit, loadErr := loadCacheEntry(root, lookup)
			if loadErr != nil {
				return loadErr
			}
			if hit {
				return nil
			}
			return coded(ErrorCodeCacheInvalid, nil)
		}
		return coded(ErrorCodeCachePublishFailed, err)
	}
	cleanup = false
	if err := ctx.Err(); err != nil {
		return rollbackCachePublication(root, tempDir, finalName, err)
	}
	if err := root.Sync(); err != nil {
		return rollbackCachePublication(root, tempDir, finalName, err)
	}
	if err := ctx.Err(); err != nil {
		return rollbackCachePublication(root, tempDir, finalName, err)
	}
	return nil
}

func rollbackCachePublication(root, entry *os.File, finalName string, cause error) error {
	var rollbackErr error
	for _, name := range []string{"metadata.json", "layer"} {
		if err := unix.Unlinkat(int(entry.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			rollbackErr = errors.Join(rollbackErr, err)
		}
	}
	if err := unix.Unlinkat(int(root.Fd()), finalName, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		rollbackErr = errors.Join(rollbackErr, err)
	}
	if err := root.Sync(); err != nil {
		rollbackErr = errors.Join(rollbackErr, err)
	}
	if rollbackErr != nil {
		return coded(ErrorCodeCachePublishFailed, errors.Join(cause, rollbackErr))
	}
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return requestContextError(cause)
	}
	return coded(ErrorCodeCachePublishFailed, cause)
}

func cacheEntryName(manifestDigest string) string {
	return strings.TrimPrefix(manifestDigest, "sha256:")
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
	if info.Mode()&os.ModeSymlink != 0 ||
		(directory && !info.IsDir()) ||
		(!directory && !info.Mode().IsRegular()) ||
		info.Mode().Perm() != mode {
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

func validateOpenFile(file *os.File, directory bool, mode os.FileMode) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	return validateOwnedMode(info, directory, mode)
}

func readCacheFileAt(directory *os.File, name string, limit int) ([]byte, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("cache file is invalid")
	}
	if err := validateOpenFile(file, false, 0o600); err != nil {
		_ = file.Close()
		return nil, errors.New("cache file is invalid")
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
	return data, nil
}

func writeSyncedFileAt(directory *os.File, name string, data []byte) error {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("cache file creation failed")
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
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

func openCacheRoot(path string, create bool) (*os.File, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), "/")
	if current == nil {
		_ = unix.Close(fd)
		return nil, errors.New("cache root open failed")
	}
	components := strings.Split(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			_ = current.Close()
			return nil, errors.New("cache root is invalid")
		}
		next, openErr := openDirectoryAt(current, component)
		if errors.Is(openErr, os.ErrNotExist) && create {
			if mkdirErr := unix.Mkdirat(int(current.Fd()), component, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = current.Close()
				return nil, mkdirErr
			}
			next, openErr = openDirectoryAt(current, component)
		}
		_ = current.Close()
		if openErr != nil {
			return nil, openErr
		}
		current = next
	}
	if err := validateOpenFile(current, true, 0o700); err != nil {
		_ = current.Close()
		return nil, err
	}
	return current, nil
}

func openDirectoryAt(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("cache directory open failed")
	}
	return file, nil
}

func createCacheTempDirectory(root *os.File) (string, *os.File, error) {
	for attempt := 0; attempt < 32; attempt++ {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return "", nil, err
		}
		name := ".tmp-" + hex.EncodeToString(random)
		if err := unix.Mkdirat(int(root.Fd()), name, 0o700); err != nil {
			if errors.Is(err, unix.EEXIST) {
				continue
			}
			return "", nil, err
		}
		directory, err := openDirectoryAt(root, name)
		if err != nil {
			_ = unix.Unlinkat(int(root.Fd()), name, unix.AT_REMOVEDIR)
			return "", nil, err
		}
		if err := validateOpenFile(directory, true, 0o700); err != nil {
			_ = directory.Close()
			_ = unix.Unlinkat(int(root.Fd()), name, unix.AT_REMOVEDIR)
			return "", nil, err
		}
		return name, directory, nil
	}
	return "", nil, errors.New("cache temporary directory unavailable")
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

func (g *fetchGroup) do(ctx context.Context, key string, fn func(context.Context) ([]byte, error)) ([]byte, func(), error) {
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
		if call.err != nil {
			return append([]byte(nil), call.data...), nil, call.err
		}
		return append([]byte(nil), call.data...), sync.OnceFunc(func() {
			g.forget(key, call)
		}), nil
	case <-ctx.Done():
		g.releaseOwner(key, call, true)
		return nil, nil, ctx.Err()
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

func (g *fetchGroup) forget(key string, expected *fetchCall) {
	g.mu.Lock()
	if call := g.calls[key]; call != nil && call == expected {
		call.cancel()
		delete(g.calls, key)
	}
	g.mu.Unlock()
}
