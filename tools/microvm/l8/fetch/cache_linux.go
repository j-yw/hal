//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
)

func openCacheDir(name string) (*os.File, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return nil, errCache
	}
	canonical, err := filepath.EvalSymlinks(name)
	if err != nil || canonical != name {
		return nil, errCache
	}
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errCache
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Getuid()) || st.Mode&07777 != 0700 {
		f.Close()
		return nil, errCache
	}
	return f, nil
}

func openCacheEntry(dir *os.File, pin lockedFile) (*os.File, error) {
	if !validPin(pin) {
		return nil, errCache
	}
	fd, err := unix.Openat(int(dir.Fd()), pin.Name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errCache
	}
	f := os.NewFile(uintptr(fd), pin.Name)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Getuid()) || st.Mode&0022 != 0 || st.Size != pin.Size {
		f.Close()
		return nil, errCache
	}
	return f, nil
}

func copyPinnedEntry(ctx context.Context, source io.Reader, destination io.Writer, pin lockedFile) error {
	if !validPin(pin) || ctx.Err() != nil {
		return errCache
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(destination, hash), io.LimitReader(contextReader{ctx, source}, pin.Size+1))
	if err != nil || n != pin.Size || hex.EncodeToString(hash.Sum(nil)) != pin.SHA256 || ctx.Err() != nil {
		return errCache
	}
	return nil
}

func sortedPins(locks map[string]lockedFile) []lockedFile {
	result := make([]lockedFile, 0, len(locks))
	for _, pin := range locks {
		result = append(result, pin)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

type ownedCacheEntry struct {
	name          string
	device, inode uint64
}

func createCacheEntry(dir *os.File, pin lockedFile) (*os.File, ownedCacheEntry, error) {
	var owned ownedCacheEntry
	if !validPin(pin) {
		return nil, owned, errCache
	}
	fd, err := unix.Openat(int(dir.Fd()), pin.Name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, owned, errCache
	}
	f := os.NewFile(uintptr(fd), pin.Name)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		f.Close()
		return nil, owned, errCache
	}
	return f, ownedCacheEntry{name: pin.Name, device: st.Dev, inode: st.Ino}, nil
}

func (owned ownedCacheEntry) remove(dir *os.File) {
	var st unix.Stat_t
	if owned.name != "" && unix.Fstatat(int(dir.Fd()), owned.name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Dev == owned.device && st.Ino == owned.inode && st.Mode&unix.S_IFMT == unix.S_IFREG {
		_ = unix.Unlinkat(int(dir.Fd()), owned.name, 0)
	}
}

func verifyCache(ctx context.Context, name string, locks map[string]lockedFile) error {
	dir, err := openCacheDir(name)
	if err != nil {
		return err
	}
	defer dir.Close()
	return verifyCacheDir(ctx, dir, locks)
}

func verifyCacheDir(ctx context.Context, dir *os.File, locks map[string]lockedFile) error {
	if len(locks) == 0 || len(locks) > maxSources || ctx.Err() != nil {
		return errCache
	}
	// Btrfs may retain the extent visible when a directory was opened, before
	// this stage's entries were created. A fresh enumeration handle also avoids
	// reusing an exhausted cursor. Resolve only through the retained authority,
	// never the mutable stage pathname. Read names only; all entry metadata and
	// bytes are checked through openCacheEntry's retained-FD-relative NOFOLLOW.
	fd, err := unix.Openat(int(dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errCache
	}
	enumeration := os.NewFile(uintptr(fd), dir.Name())
	defer enumeration.Close()
	entries, err := enumeration.Readdirnames(len(locks) + 1)
	if (err != nil && err != io.EOF) || len(entries) != len(locks) {
		return errCache
	}
	for _, name := range entries {
		pin, ok := locks[name]
		if !ok || pin.Name != name {
			return errCache
		}
	}
	for _, pin := range sortedPins(locks) {
		f, err := openCacheEntry(dir, pin)
		if err != nil {
			return err
		}
		err = copyPinnedEntry(ctx, f, io.Discard, pin)
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return errCache
		}
	}
	return nil
}

func combineLocks(a, b map[string]lockedFile) (map[string]lockedFile, error) {
	if len(a) == 0 || len(b) < 4 || len(a)+len(b) > maxSources {
		return nil, errCache
	}
	all := make(map[string]lockedFile, len(a)+len(b))
	var total int64
	for _, set := range []map[string]lockedFile{a, b} {
		for name, pin := range set {
			if name != pin.Name || !validPin(pin) {
				return nil, errCache
			}
			if _, exists := all[name]; exists {
				return nil, errCache
			}
			total += pin.Size
			if total > 1<<30 {
				return nil, errCache
			}
			all[name] = pin
		}
	}
	return all, nil
}

// L5 sources are acquired separately by the existing signer/tag-verifying
// fetcher. This helper measures every copied byte and never fabricates that
// upstream signature verification from a successful cache hash check.
func acquireCache(ctx context.Context, output, l5dir string, l5locks, l8locks map[string]lockedFile, client *http.Client) error {
	all, err := combineLocks(l5locks, l8locks)
	if err != nil || ctx.Err() != nil {
		return errCache
	}
	parent, err := openCacheDir(filepath.Dir(output))
	if err != nil {
		return err
	}
	defer parent.Close()
	if !filenamePattern.MatchString(filepath.Base(output)) {
		return errCache
	}
	if _, err := os.Lstat(output); err == nil {
		return verifyCache(ctx, output, all)
	} else if !os.IsNotExist(err) {
		return errCache
	}
	l5, err := openCacheDir(l5dir)
	if err != nil {
		return err
	}
	defer l5.Close()
	if err := verifyCacheDir(ctx, l5, l5locks); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Dir(output), ".hal-l8-cache-")
	if err != nil {
		return errCache
	}
	stageFD, err := openCacheDir(stage)
	if err != nil {
		os.Remove(stage)
		return err
	}
	defer stageFD.Close()
	var ownedEntries []ownedCacheEntry
	published := false
	defer func() {
		if !published {
			for _, entry := range ownedEntries {
				entry.remove(stageFD)
			}
			if sameDirectory(stageFD, stage) {
				_ = unix.Unlinkat(int(parent.Fd()), filepath.Base(stage), unix.AT_REMOVEDIR)
			}
		}
	}()
	for _, pin := range sortedPins(l5locks) {
		input, err := openCacheEntry(l5, pin)
		if err != nil {
			return err
		}
		output, owned, err := createCacheEntry(stageFD, pin)
		if err != nil {
			input.Close()
			return errCache
		}
		ownedEntries = append(ownedEntries, owned)
		copyErr := copyPinnedEntry(ctx, input, output, pin)
		syncErr := output.Sync()
		inErr := input.Close()
		outErr := output.Close()
		if copyErr != nil || syncErr != nil || inErr != nil || outErr != nil {
			return errCache
		}
	}
	for _, spec := range []downloadSpec{{File: l8locks[nodeFile], URL: nodeURL}, {File: l8locks[piFile], URL: piURL}} {
		owned, err := downloadPinnedAt(ctx, client, stageFD, spec)
		if err != nil {
			return err
		}
		ownedEntries = append(ownedEntries, owned)
	}
	pi, err := openCacheEntry(stageFD, l8locks[piFile])
	if err != nil {
		return err
	}
	// Snapshot the small pinned Pi package before decoding it independently.
	if l8locks[piFile].Size > maxArchiveBytes {
		pi.Close()
		return errCache
	}
	var packageBytes bytes.Buffer
	err = copyPinnedEntry(ctx, pi, &packageBytes, l8locks[piFile])
	closeErr := pi.Close()
	if err != nil || closeErr != nil {
		return errCache
	}
	wrap, err := extractShrinkwrap(ctx, bytes.NewReader(packageBytes.Bytes()), l8locks[shrinkwrapFile])
	if err != nil {
		return err
	}
	dependencies, err := planNPMDownloads(wrap, l8locks)
	if err != nil {
		return err
	}
	file, owned, err := createCacheEntry(stageFD, l8locks[shrinkwrapFile])
	if err != nil {
		return errCache
	}
	ownedEntries = append(ownedEntries, owned)
	err = copyPinnedEntry(ctx, bytes.NewReader(wrap), file, l8locks[shrinkwrapFile])
	syncErr := file.Sync()
	closeErr = file.Close()
	if err != nil || syncErr != nil || closeErr != nil {
		return errCache
	}
	for _, spec := range dependencies {
		owned, err := downloadPinnedAt(ctx, client, stageFD, spec)
		if err != nil {
			return err
		}
		ownedEntries = append(ownedEntries, owned)
	}
	if err := verifyCacheDir(ctx, stageFD, all); err != nil {
		return err
	}
	if stageFD.Sync() != nil || ctx.Err() != nil || !sameDirectory(stageFD, stage) || !sameDirectory(parent, filepath.Dir(output)) {
		return errCache
	}
	if unix.Renameat2(int(parent.Fd()), filepath.Base(stage), int(parent.Fd()), filepath.Base(output), unix.RENAME_NOREPLACE) != nil {
		return errCache
	}
	published = true
	if parent.Sync() != nil {
		return errCache
	}
	return nil
}

func sameDirectory(file *os.File, name string) bool {
	var retained, named unix.Stat_t
	return unix.Fstat(int(file.Fd()), &retained) == nil && unix.Lstat(name, &named) == nil && retained.Dev == named.Dev && retained.Ino == named.Ino && named.Mode&unix.S_IFMT == unix.S_IFDIR
}
