//go:build linux

package firecrackerhost

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type linuxJailerStagingFilesystem struct {
	mu         sync.Mutex
	authority  jailerStagingAuthority
	commonPath string
	commonFD   int
	commonID   linuxJailerStagingIdentity
	statEntry  func(int, string) (unix.Stat_t, error)
	used       bool
}

type linuxJailerStagingRoot struct {
	mu              sync.Mutex
	authority       jailerStagingAuthority
	commonPath      string
	commonFD        int
	runtimeFD       int
	rootFD          int
	commonID        linuxJailerStagingIdentity
	runtimeID       linuxJailerStagingIdentity
	rootID          linuxJailerStagingIdentity
	entries         map[string]linuxJailerStagingEntry
	finalized       bool
	cleanupStarted  bool
	rootUnlinked    bool
	runtimeUnlinked bool
	creationOnly    bool
	removed         bool
	closed          bool
}

type linuxJailerStagingFile struct {
	mu       sync.Mutex
	root     *linuxJailerStagingRoot
	relative string
	name     string
	parentFD int
	fd       int
	id       linuxJailerStagingIdentity
	uid      uint32
	gid      uint32
	mode     uint32
	closed   bool
}

type linuxJailerStagingIdentity struct {
	device uint64
	inode  uint64
}

type linuxJailerStagingEntry struct {
	id        linuxJailerStagingIdentity
	directory bool
	uid       uint32
	gid       uint32
	mode      uint32
}

// newLinuxJailerStagingFilesystem binds the exact, preexisting common
// <chroot>/<firecracker-basename> directory without following any path
// component symlink. It creates no broad parent directories and is single-use.
func newLinuxJailerStagingFilesystem(authority jailerStagingAuthority) (jailerStagingFilesystem, error) {
	validated, err := validateJailerStagingAuthority(authority)
	if err != nil {
		return nil, err
	}
	commonPath := filepath.Join(validated.ChrootBaseDir, filepath.Base(validated.CanonicalFirecrackerPath))
	commonFD, err := openLinuxJailerAbsoluteDirectory(commonPath)
	if err != nil {
		return nil, newJailerStagingError(errJailerStagingFailed, "filesystem")
	}
	stat, err := linuxJailerFstat(commonFD)
	if err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o777 != 0o700 || stat.Uid != uint32(os.Geteuid()) {
		_ = unix.Close(commonFD)
		return nil, newJailerStagingError(errJailerStagingFailed, "filesystem")
	}
	return &linuxJailerStagingFilesystem{
		authority: validated, commonPath: commonPath, commonFD: commonFD,
		commonID: linuxJailerIdentity(stat), statEntry: linuxJailerFstatat,
	}, nil
}

func (filesystem *linuxJailerStagingFilesystem) createExclusiveRoot(request jailerStagingRootRequest) (jailerStagingRoot, error) {
	filesystem.mu.Lock()
	defer filesystem.mu.Unlock()
	if filesystem.used || filesystem.commonFD < 0 || filesystem.statEntry == nil || request.HostRoot != filesystem.authority.JailRootHostPath ||
		request.Mode != filesystem.authority.DirectoryMode || request.UID != filesystem.authority.UID || request.GID != filesystem.authority.GID {
		return nil, newJailerStagingError(errJailerStagingInvalid, "root")
	}
	filesystem.used = true
	if err := verifyLinuxJailerAbsoluteDirectory(filesystem.commonPath, filesystem.commonID); err != nil {
		return nil, newJailerStagingError(errJailerStagingFailed, "root")
	}

	runtimeName := filesystem.authority.RuntimeID
	if err := unix.Mkdirat(filesystem.commonFD, runtimeName, 0o700); err != nil {
		return nil, newJailerStagingError(errJailerStagingFailed, "root")
	}
	root := &linuxJailerStagingRoot{
		authority: filesystem.authority, commonPath: filesystem.commonPath,
		commonFD: filesystem.commonFD, runtimeFD: -1, rootFD: -1,
		commonID: filesystem.commonID,
		entries:  make(map[string]linuxJailerStagingEntry), cleanupStarted: true, rootUnlinked: true, creationOnly: true,
	}
	filesystem.commonFD = -1

	runtimeLinked, err := filesystem.statEntry(root.commonFD, runtimeName)
	if err != nil || runtimeLinked.Mode&unix.S_IFMT != unix.S_IFDIR {
		return finishLinuxJailerCreationFailure(root)
	}
	root.runtimeID = linuxJailerIdentity(runtimeLinked)
	runtimeFD, err := openLinuxJailerDirectoryAt(root.commonFD, runtimeName)
	if err != nil {
		return finishLinuxJailerCreationFailure(root)
	}
	root.runtimeFD = runtimeFD
	runtimeStat, err := linuxJailerFstat(runtimeFD)
	if err != nil || runtimeStat.Mode&unix.S_IFMT != unix.S_IFDIR || !linuxJailerSameIdentity(runtimeStat, root.runtimeID) {
		_ = unix.Close(runtimeFD)
		root.runtimeFD = -1
		return finishLinuxJailerCreationFailure(root)
	}
	if unix.Fchmod(runtimeFD, 0o700) != nil {
		return finishLinuxJailerCreationFailure(root)
	}
	if err := unix.Mkdirat(runtimeFD, "root", 0o700); err != nil {
		return finishLinuxJailerCreationFailure(root)
	}
	root.rootUnlinked = false
	rootLinked, err := filesystem.statEntry(runtimeFD, "root")
	if err != nil {
		return finishLinuxJailerCreationFailure(root)
	}
	if rootLinked.Mode&unix.S_IFMT != unix.S_IFDIR {
		root.rootUnlinked = true
		return finishLinuxJailerCreationFailure(root)
	}
	root.rootID = linuxJailerIdentity(rootLinked)
	rootFD, err := openLinuxJailerDirectoryAt(runtimeFD, "root")
	if err != nil {
		return finishLinuxJailerCreationFailure(root)
	}
	root.rootFD = rootFD
	rootStat, err := linuxJailerFstat(rootFD)
	if err != nil || rootStat.Mode&unix.S_IFMT != unix.S_IFDIR || !linuxJailerSameIdentity(rootStat, root.rootID) {
		_ = unix.Close(rootFD)
		root.rootFD = -1
		return finishLinuxJailerCreationFailure(root)
	}
	if unix.Fchmod(rootFD, 0o700) != nil || unix.Fsync(rootFD) != nil || unix.Fsync(runtimeFD) != nil || unix.Fsync(root.commonFD) != nil {
		return finishLinuxJailerCreationFailure(root)
	}
	root.creationOnly = false
	root.cleanupStarted = false
	return root, nil
}

func finishLinuxJailerCreationFailure(root *linuxJailerStagingRoot) (jailerStagingRoot, error) {
	if cleanupErr := root.removeOwned(); cleanupErr != nil {
		return root, joinLinuxJailerCreationError(cleanupErr)
	}
	// Exact directory rollback is terminal even if closing its now-unlinked
	// descriptors reports an error; there is no generation left to retry.
	closeErr := root.close()
	return nil, joinLinuxJailerCreationError(closeErr)
}

func (filesystem *linuxJailerStagingFilesystem) close() error {
	filesystem.mu.Lock()
	defer filesystem.mu.Unlock()
	if filesystem.commonFD < 0 {
		return nil
	}
	fd := filesystem.commonFD
	filesystem.commonFD = -1
	if err := unix.Close(fd); err != nil {
		return newJailerStagingError(errJailerStagingCleanupIncomplete, "root_close")
	}
	return nil
}

func (root *linuxJailerStagingRoot) createDirectory(relative string, mode os.FileMode, uid, gid uint32) error {
	root.mu.Lock()
	defer root.mu.Unlock()
	if root.closed || root.removed || mode != root.authority.DirectoryMode || uid != root.authority.UID || gid != root.authority.GID ||
		!validLinuxJailerRelativePath(relative) {
		return newJailerStagingError(errJailerStagingInvalid, "directory")
	}
	if _, exists := root.entries[relative]; exists {
		return newJailerStagingError(errJailerStagingFailed, "directory")
	}
	parentFD, name, err := root.openVerifiedRelativeParent(relative)
	if err != nil {
		return newJailerStagingError(errJailerStagingFailed, "directory")
	}
	defer unix.Close(parentFD)
	if err := unix.Mkdirat(parentFD, name, uint32(mode.Perm())); err != nil {
		return newJailerStagingError(errJailerStagingFailed, "directory")
	}
	linked, err := linuxJailerFstatat(parentFD, name)
	if err != nil || linked.Mode&unix.S_IFMT != unix.S_IFDIR {
		return newJailerStagingError(errJailerStagingCleanupIncomplete, "directory")
	}
	id := linuxJailerIdentity(linked)
	directoryFD, err := openLinuxJailerDirectoryAt(parentFD, name)
	if err != nil {
		_ = removeLinuxJailerEmptyEntry(parentFD, name, id)
		return newJailerStagingError(errJailerStagingFailed, "directory")
	}
	if secureLinuxJailerOpenedDirectory(directoryFD, parentFD, id, mode, uid, gid) != nil {
		_ = unix.Close(directoryFD)
		_ = removeLinuxJailerEmptyEntry(parentFD, name, id)
		return newJailerStagingError(errJailerStagingFailed, "directory")
	}
	_ = unix.Close(directoryFD)
	root.entries[relative] = linuxJailerStagingEntry{id: id, directory: true, uid: uid, gid: gid, mode: uint32(mode.Perm())}
	return nil
}

func secureLinuxJailerOpenedDirectory(directoryFD, parentFD int, expected linuxJailerStagingIdentity, mode os.FileMode, uid, gid uint32) error {
	stat, err := linuxJailerFstat(directoryFD)
	if err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || !linuxJailerSameIdentity(stat, expected) {
		return errJailerStagingFailed
	}
	if err := unix.Fchown(directoryFD, int(uid), int(gid)); err != nil {
		return errJailerStagingFailed
	}
	if err := unix.Fchmod(directoryFD, uint32(mode.Perm())); err != nil {
		return errJailerStagingFailed
	}
	if err := unix.Fsync(directoryFD); err != nil {
		return errJailerStagingFailed
	}
	if err := unix.Fsync(parentFD); err != nil {
		return errJailerStagingFailed
	}
	return nil
}

func (root *linuxJailerStagingRoot) createFileExclusive(relative string) (jailerStagingFile, error) {
	root.mu.Lock()
	defer root.mu.Unlock()
	if root.closed || root.removed || !validLinuxJailerRelativePath(relative) {
		return nil, newJailerStagingError(errJailerStagingInvalid, "file")
	}
	if _, exists := root.entries[relative]; exists {
		return nil, newJailerStagingError(errJailerStagingFailed, "file")
	}
	parentFD, name, err := root.openVerifiedRelativeParent(relative)
	if err != nil {
		return nil, newJailerStagingError(errJailerStagingFailed, "file")
	}
	fd, err := unix.Openat(parentFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		_ = unix.Close(parentFD)
		return nil, newJailerStagingError(errJailerStagingFailed, "file")
	}
	stat, statErr := linuxJailerFstat(fd)
	if statErr != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		id := linuxJailerIdentity(stat)
		_ = unix.Close(fd)
		_ = removeLinuxJailerFileEntry(parentFD, name, id)
		_ = unix.Close(parentFD)
		return nil, newJailerStagingError(errJailerStagingFailed, "file")
	}
	id := linuxJailerIdentity(stat)
	entry := linuxJailerStagingEntry{id: id, uid: stat.Uid, gid: stat.Gid, mode: 0o600}
	if secureLinuxJailerOpenedFile(fd, parentFD, name, entry) != nil {
		_ = unix.Close(fd)
		_ = removeLinuxJailerFileEntry(parentFD, name, id)
		_ = unix.Close(parentFD)
		return nil, newJailerStagingError(errJailerStagingFailed, "file")
	}
	root.entries[relative] = entry
	return &linuxJailerStagingFile{
		root: root, relative: relative, name: name, parentFD: parentFD, fd: fd, id: id,
		uid: entry.uid, gid: entry.gid, mode: entry.mode,
	}, nil
}

func secureLinuxJailerOpenedFile(fd, parentFD int, _ string, expected linuxJailerStagingEntry) error {
	if unix.Fchmod(fd, expected.mode) != nil || unix.Fsync(parentFD) != nil {
		return errJailerStagingFailed
	}
	return nil
}

// verifyOwned re-resolves the authority and every staged entry. The future
// outer coordinator must serialize this check with process start; this method
// alone cannot prevent a same-UID host process from mutating the tree after it
// returns.
func (root *linuxJailerStagingRoot) verifyOwned() error {
	root.mu.Lock()
	defer root.mu.Unlock()
	if root.closed || root.removed {
		return newJailerStagingError(errJailerStagingFailed, "root_verify")
	}
	if err := root.verifyLocked(false); err != nil {
		return newJailerStagingError(errJailerStagingFailed, "root_verify")
	}
	if !root.finalized {
		if unix.Fchown(root.rootFD, int(root.authority.UID), int(root.authority.GID)) != nil ||
			unix.Fchmod(root.rootFD, uint32(root.authority.DirectoryMode.Perm())) != nil || unix.Fsync(root.rootFD) != nil ||
			unix.Fchown(root.runtimeFD, int(root.authority.UID), int(root.authority.GID)) != nil ||
			unix.Fchmod(root.runtimeFD, uint32(root.authority.DirectoryMode.Perm())) != nil || unix.Fsync(root.runtimeFD) != nil ||
			unix.Fsync(root.commonFD) != nil {
			return newJailerStagingError(errJailerStagingFailed, "root_verify")
		}
	}
	if err := root.verifyLocked(true); err != nil {
		return newJailerStagingError(errJailerStagingFailed, "root_verify")
	}
	root.finalized = true
	return nil
}

func (root *linuxJailerStagingRoot) verifyLocked(requireFinalMetadata bool) error {
	if err := verifyLinuxJailerAbsoluteDirectory(root.commonPath, root.commonID); err != nil {
		return err
	}
	commonStat, err := linuxJailerFstat(root.commonFD)
	if err != nil || commonStat.Mode&unix.S_IFMT != unix.S_IFDIR || commonStat.Mode&0o777 != 0o700 ||
		commonStat.Uid != uint32(os.Geteuid()) || !linuxJailerSameIdentity(commonStat, root.commonID) {
		return errJailerStagingFailed
	}
	runtimeStat, err := linuxJailerFstatat(root.commonFD, root.authority.RuntimeID)
	if err != nil || runtimeStat.Mode&unix.S_IFMT != unix.S_IFDIR || !linuxJailerSameIdentity(runtimeStat, root.runtimeID) {
		return errJailerStagingFailed
	}
	openedRuntimeStat, err := linuxJailerFstat(root.runtimeFD)
	if err != nil || !linuxJailerSameIdentity(openedRuntimeStat, root.runtimeID) {
		return errJailerStagingFailed
	}
	rootStat, err := linuxJailerFstatat(root.runtimeFD, "root")
	if err != nil || rootStat.Mode&unix.S_IFMT != unix.S_IFDIR || !linuxJailerSameIdentity(rootStat, root.rootID) {
		return errJailerStagingFailed
	}
	openedRootStat, err := linuxJailerFstat(root.rootFD)
	if err != nil || !linuxJailerSameIdentity(openedRootStat, root.rootID) {
		return errJailerStagingFailed
	}
	if requireFinalMetadata && (!linuxJailerMetadataMatches(runtimeStat, root.authority.UID, root.authority.GID, 0o700) ||
		!linuxJailerMetadataMatches(rootStat, root.authority.UID, root.authority.GID, 0o700)) {
		return errJailerStagingFailed
	}
	paths := make([]string, 0, len(root.entries))
	for relative := range root.entries {
		paths = append(paths, relative)
	}
	sort.Strings(paths)
	for _, relative := range paths {
		entry := root.entries[relative]
		stat, err := statLinuxJailerRelative(root.rootFD, relative)
		if err != nil || !linuxJailerSameIdentity(stat, entry.id) || !linuxJailerMetadataMatches(stat, entry.uid, entry.gid, entry.mode) ||
			entry.directory != (stat.Mode&unix.S_IFMT == unix.S_IFDIR) || (!entry.directory && (stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1)) {
			return errJailerStagingFailed
		}
	}
	return nil
}

// removeOwned requires outer lifecycle proof that the Jailer/Firecracker
// process is terminal. Linux has no unlink-by-inode operation: every unlinkat
// is dirfd-bound and immediately preceded by an identity recheck, but the
// dedicated runtime UID must also be quiescent to close the final check/unlink
// race. A failed removal retains all authority needed for an exact retry.
func (root *linuxJailerStagingRoot) removeOwned() error {
	root.mu.Lock()
	defer root.mu.Unlock()
	if root.closed {
		return newJailerStagingError(errJailerStagingCleanupIncomplete, "root")
	}
	if root.removed {
		return nil
	}
	if root.creationOnly {
		if err := root.removeCreationOnlyLocked(); err != nil {
			return newJailerStagingError(errJailerStagingCleanupIncomplete, "root")
		}
		return nil
	}
	verify := root.verifyLocked
	if root.cleanupStarted {
		verify = root.verifyCleanupLocked
	}
	if err := verify(root.finalized); err != nil {
		return newJailerStagingError(errJailerStagingCleanupIncomplete, "root")
	}
	root.cleanupStarted = true
	if !root.rootUnlinked {
		if err := removeLinuxJailerDirectoryContents(root.rootFD, "", root.entries, root.finalized); err != nil || unix.Fsync(root.rootFD) != nil {
			return newJailerStagingError(errJailerStagingCleanupIncomplete, "root")
		}
		rootStat, err := linuxJailerFstatat(root.runtimeFD, "root")
		if err != nil || !linuxJailerSameIdentity(rootStat, root.rootID) || unix.Unlinkat(root.runtimeFD, "root", unix.AT_REMOVEDIR) != nil {
			return newJailerStagingError(errJailerStagingCleanupIncomplete, "root")
		}
		root.rootUnlinked = true
	}
	if !root.runtimeUnlinked {
		if removeLinuxJailerDirectoryContents(root.runtimeFD, "", nil, root.finalized) != nil || unix.Fsync(root.runtimeFD) != nil {
			return newJailerStagingError(errJailerStagingCleanupIncomplete, "root")
		}
		runtimeStat, err := linuxJailerFstatat(root.commonFD, root.authority.RuntimeID)
		if err != nil || !linuxJailerSameIdentity(runtimeStat, root.runtimeID) ||
			unix.Unlinkat(root.commonFD, root.authority.RuntimeID, unix.AT_REMOVEDIR) != nil {
			return newJailerStagingError(errJailerStagingCleanupIncomplete, "root")
		}
		root.runtimeUnlinked = true
	}
	if unix.Fsync(root.commonFD) != nil {
		return newJailerStagingError(errJailerStagingCleanupIncomplete, "root")
	}
	root.removed = true
	return nil
}

// removeCreationOnlyLocked rolls back only the exact empty directories whose
// identities were correlated before creation failed. It never scans or
// recursively removes descendants: unexpected contents keep the in-memory
// quarantine nonterminal for an exact retry.
func (root *linuxJailerStagingRoot) removeCreationOnlyLocked() error {
	if err := verifyLinuxJailerAbsoluteDirectory(root.commonPath, root.commonID); err != nil {
		return errJailerStagingCleanupIncomplete
	}
	commonStat, err := linuxJailerFstat(root.commonFD)
	if err != nil || commonStat.Mode&unix.S_IFMT != unix.S_IFDIR || commonStat.Mode&0o777 != 0o700 ||
		commonStat.Uid != uint32(os.Geteuid()) || !linuxJailerSameIdentity(commonStat, root.commonID) {
		return errJailerStagingCleanupIncomplete
	}
	if root.runtimeUnlinked {
		if unix.Fsync(root.commonFD) != nil {
			return errJailerStagingCleanupIncomplete
		}
		root.removed = true
		return nil
	}
	if root.runtimeID == (linuxJailerStagingIdentity{}) {
		return errJailerStagingCleanupIncomplete
	}
	runtimeFD, err := pinLinuxJailerCreationDirectory(root.commonFD, root.authority.RuntimeID, root.runtimeID, root.runtimeFD)
	if err != nil {
		return errJailerStagingCleanupIncomplete
	}
	root.runtimeFD = runtimeFD
	if !root.rootUnlinked {
		if root.rootID == (linuxJailerStagingIdentity{}) {
			return errJailerStagingCleanupIncomplete
		}
		rootFD, err := pinLinuxJailerCreationDirectory(root.runtimeFD, "root", root.rootID, root.rootFD)
		if err != nil {
			return errJailerStagingCleanupIncomplete
		}
		root.rootFD = rootFD
		if unix.Fsync(root.rootFD) != nil || removeLinuxJailerEmptyEntry(root.runtimeFD, "root", root.rootID) != nil {
			return errJailerStagingCleanupIncomplete
		}
		root.rootUnlinked = true
	}
	if unix.Fsync(root.runtimeFD) != nil || removeLinuxJailerEmptyEntry(root.commonFD, root.authority.RuntimeID, root.runtimeID) != nil {
		return errJailerStagingCleanupIncomplete
	}
	root.runtimeUnlinked = true
	if unix.Fsync(root.commonFD) != nil {
		return errJailerStagingCleanupIncomplete
	}
	root.removed = true
	return nil
}

func pinLinuxJailerCreationDirectory(parentFD int, name string, expected linuxJailerStagingIdentity, retainedFD int) (int, error) {
	if expected == (linuxJailerStagingIdentity{}) {
		return -1, errJailerStagingCleanupIncomplete
	}
	linked, err := linuxJailerFstatat(parentFD, name)
	if err != nil || linked.Mode&unix.S_IFMT != unix.S_IFDIR || !linuxJailerSameIdentity(linked, expected) {
		return -1, errJailerStagingCleanupIncomplete
	}
	if retainedFD >= 0 {
		opened, err := linuxJailerFstat(retainedFD)
		if err != nil || opened.Mode&unix.S_IFMT != unix.S_IFDIR || !linuxJailerSameIdentity(opened, expected) {
			return -1, errJailerStagingCleanupIncomplete
		}
		return retainedFD, nil
	}
	openedFD, err := openLinuxJailerDirectoryAt(parentFD, name)
	if err != nil {
		return -1, errJailerStagingCleanupIncomplete
	}
	opened, statErr := linuxJailerFstat(openedFD)
	if statErr != nil || opened.Mode&unix.S_IFMT != unix.S_IFDIR || !linuxJailerSameIdentity(opened, expected) {
		_ = unix.Close(openedFD)
		return -1, errJailerStagingCleanupIncomplete
	}
	return openedFD, nil
}

func (root *linuxJailerStagingRoot) verifyCleanupLocked(requireFinalMetadata bool) error {
	if err := verifyLinuxJailerAbsoluteDirectory(root.commonPath, root.commonID); err != nil {
		return err
	}
	commonStat, err := linuxJailerFstat(root.commonFD)
	if err != nil || commonStat.Mode&unix.S_IFMT != unix.S_IFDIR || commonStat.Mode&0o777 != 0o700 ||
		commonStat.Uid != uint32(os.Geteuid()) || !linuxJailerSameIdentity(commonStat, root.commonID) {
		return errJailerStagingFailed
	}
	if root.runtimeUnlinked {
		return nil
	}
	runtimeStat, err := linuxJailerFstatat(root.commonFD, root.authority.RuntimeID)
	if err != nil || !linuxJailerSameIdentity(runtimeStat, root.runtimeID) {
		return errJailerStagingFailed
	}
	openedRuntimeStat, err := linuxJailerFstat(root.runtimeFD)
	if err != nil || !linuxJailerSameIdentity(openedRuntimeStat, root.runtimeID) {
		return errJailerStagingFailed
	}
	if requireFinalMetadata && !linuxJailerMetadataMatches(runtimeStat, root.authority.UID, root.authority.GID, 0o700) {
		return errJailerStagingFailed
	}
	if root.rootUnlinked {
		return nil
	}
	return root.verifyLocked(requireFinalMetadata)
}

func (root *linuxJailerStagingRoot) close() error {
	root.mu.Lock()
	defer root.mu.Unlock()
	if root.closed {
		return nil
	}
	root.closed = true
	var closeErr error
	for _, fd := range []int{root.rootFD, root.runtimeFD, root.commonFD} {
		if fd >= 0 {
			closeErr = errors.Join(closeErr, unix.Close(fd))
		}
	}
	root.rootFD, root.runtimeFD, root.commonFD = -1, -1, -1
	if closeErr != nil {
		return newJailerStagingError(errJailerStagingCleanupIncomplete, "root_close")
	}
	return nil
}

func (file *linuxJailerStagingFile) Read(output []byte) (int, error) {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.closed {
		return 0, newJailerStagingError(errJailerStagingFailed, "file")
	}
	n, err := unix.Read(file.fd, output)
	if err == nil && n == 0 {
		return 0, io.EOF
	}
	if err != nil {
		return n, newJailerStagingError(errJailerStagingFailed, "file")
	}
	return n, nil
}

func (file *linuxJailerStagingFile) Write(input []byte) (int, error) {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.closed || !file.validForMutationLocked() {
		return 0, newJailerStagingError(errJailerStagingFailed, "file")
	}
	n, err := unix.Write(file.fd, input)
	if err != nil {
		return n, newJailerStagingError(errJailerStagingFailed, "file")
	}
	return n, nil
}

func (file *linuxJailerStagingFile) Seek(offset int64, whence int) (int64, error) {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.closed {
		return 0, newJailerStagingError(errJailerStagingFailed, "file")
	}
	position, err := unix.Seek(file.fd, offset, whence)
	if err != nil {
		return 0, newJailerStagingError(errJailerStagingFailed, "file")
	}
	return position, nil
}

func (file *linuxJailerStagingFile) sync() error {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.closed || unix.Fsync(file.fd) != nil {
		return newJailerStagingError(errJailerStagingFailed, "sync")
	}
	return nil
}

func (file *linuxJailerStagingFile) setOwnership(uid, gid uint32) error {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.closed || uid != file.root.authority.UID || gid != file.root.authority.GID || !file.validForMutationLocked() ||
		unix.Fchown(file.fd, int(uid), int(gid)) != nil {
		return newJailerStagingError(errJailerStagingFailed, "ownership")
	}
	file.uid, file.gid = uid, gid
	file.root.updateEntryMetadata(file.relative, file.uid, file.gid, file.mode)
	return nil
}

func (file *linuxJailerStagingFile) setMode(mode os.FileMode) error {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.closed || !validJailerStagingFileMode(mode) || !file.validForMutationLocked() || unix.Fchmod(file.fd, uint32(mode.Perm())) != nil {
		return newJailerStagingError(errJailerStagingFailed, "mode")
	}
	file.mode = uint32(mode.Perm())
	file.root.updateEntryMetadata(file.relative, file.uid, file.gid, file.mode)
	return nil
}

func (file *linuxJailerStagingFile) validForMutationLocked() bool {
	linked, err := linuxJailerFstatat(file.parentFD, file.name)
	if err != nil || !linuxJailerFileStateMatches(linked, file.id, file.uid, file.gid, file.mode) {
		return false
	}
	opened, err := linuxJailerFstat(file.fd)
	return err == nil && linuxJailerFileStateMatches(opened, file.id, file.uid, file.gid, file.mode)
}

func (file *linuxJailerStagingFile) verifyIdentity() error {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.closed {
		return newJailerStagingError(errJailerStagingFailed, "file_verify")
	}
	opened, err := linuxJailerFstat(file.fd)
	if err != nil || opened.Mode&unix.S_IFMT != unix.S_IFREG || opened.Nlink != 1 || !linuxJailerSameIdentity(opened, file.id) ||
		!linuxJailerMetadataMatches(opened, file.uid, file.gid, file.mode) {
		return newJailerStagingError(errJailerStagingFailed, "file_verify")
	}
	linked, err := linuxJailerFstatat(file.parentFD, file.name)
	if err != nil || !linuxJailerSameIdentity(linked, file.id) {
		return newJailerStagingError(errJailerStagingFailed, "file_verify")
	}
	return nil
}

func (file *linuxJailerStagingFile) close() error {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.closed {
		return nil
	}
	file.closed = true
	err := errors.Join(unix.Close(file.fd), unix.Close(file.parentFD))
	file.fd, file.parentFD = -1, -1
	if err != nil {
		return newJailerStagingError(errJailerStagingCleanupIncomplete, "file_close")
	}
	return nil
}

func (root *linuxJailerStagingRoot) updateEntryMetadata(relative string, uid, gid, mode uint32) {
	root.mu.Lock()
	defer root.mu.Unlock()
	entry, exists := root.entries[relative]
	if !exists {
		return
	}
	entry.uid, entry.gid, entry.mode = uid, gid, mode
	root.entries[relative] = entry
}

func openLinuxJailerAbsoluteDirectory(value string) (int, error) {
	if !filepathIsCleanAbsolute(value) || cleanupFilesystemRoot(value) {
		return -1, errJailerStagingInvalid
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(value, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			_ = unix.Close(fd)
			return -1, errJailerStagingInvalid
		}
		next, openErr := openLinuxJailerDirectoryAt(fd, component)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, openErr
		}
		fd = next
	}
	return fd, nil
}

func verifyLinuxJailerAbsoluteDirectory(value string, expected linuxJailerStagingIdentity) error {
	fd, err := openLinuxJailerAbsoluteDirectory(value)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	stat, err := linuxJailerFstat(fd)
	if err != nil || !linuxJailerSameIdentity(stat, expected) {
		return errJailerStagingFailed
	}
	return nil
}

func openLinuxJailerDirectoryAt(parentFD int, name string) (int, error) {
	return unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

func validLinuxJailerRelativePath(value string) bool {
	if value == "" || filepath.IsAbs(value) || filepath.Clean(value) != value || strings.Contains(value, `\`) || hasOSExecProcessControl(value) {
		return false
	}
	for _, component := range strings.Split(value, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func openLinuxJailerRelativeParent(rootFD int, relative string) (int, string, error) {
	if !validLinuxJailerRelativePath(relative) {
		return -1, "", errJailerStagingInvalid
	}
	components := strings.Split(relative, string(filepath.Separator))
	parentFD, err := unix.FcntlInt(uintptr(rootFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, "", err
	}
	for _, component := range components[:len(components)-1] {
		next, openErr := openLinuxJailerDirectoryAt(parentFD, component)
		_ = unix.Close(parentFD)
		if openErr != nil {
			return -1, "", openErr
		}
		parentFD = next
	}
	return parentFD, components[len(components)-1], nil
}

func (root *linuxJailerStagingRoot) openVerifiedRelativeParent(relative string) (int, string, error) {
	if !validLinuxJailerRelativePath(relative) {
		return -1, "", errJailerStagingInvalid
	}
	components := strings.Split(relative, string(filepath.Separator))
	parentFD, err := unix.FcntlInt(uintptr(root.rootFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, "", err
	}
	for index, component := range components[:len(components)-1] {
		relativeParent := filepath.Join(components[:index+1]...)
		expected, exists := root.entries[relativeParent]
		if !exists || !expected.directory {
			_ = unix.Close(parentFD)
			return -1, "", errJailerStagingFailed
		}
		linked, statErr := linuxJailerFstatat(parentFD, component)
		if statErr != nil || !linuxJailerDirectoryStateMatches(linked, expected) {
			_ = unix.Close(parentFD)
			return -1, "", errJailerStagingFailed
		}
		next, openErr := openLinuxJailerDirectoryAt(parentFD, component)
		_ = unix.Close(parentFD)
		if openErr != nil {
			return -1, "", openErr
		}
		opened, statErr := linuxJailerFstat(next)
		if statErr != nil || !linuxJailerDirectoryStateMatches(opened, expected) {
			_ = unix.Close(next)
			return -1, "", errJailerStagingFailed
		}
		parentFD = next
	}
	return parentFD, components[len(components)-1], nil
}

func linuxJailerDirectoryStateMatches(stat unix.Stat_t, expected linuxJailerStagingEntry) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFDIR && linuxJailerSameIdentity(stat, expected.id) &&
		linuxJailerMetadataMatches(stat, expected.uid, expected.gid, expected.mode)
}

func linuxJailerFileStateMatches(stat unix.Stat_t, expected linuxJailerStagingIdentity, uid, gid, mode uint32) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink == 1 && linuxJailerSameIdentity(stat, expected) &&
		linuxJailerMetadataMatches(stat, uid, gid, mode) && stat.Mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) == 0
}

func statLinuxJailerRelative(rootFD int, relative string) (unix.Stat_t, error) {
	parentFD, name, err := openLinuxJailerRelativeParent(rootFD, relative)
	if err != nil {
		return unix.Stat_t{}, err
	}
	defer unix.Close(parentFD)
	return linuxJailerFstatat(parentFD, name)
}

func linuxJailerFstat(fd int) (unix.Stat_t, error) {
	var stat unix.Stat_t
	err := unix.Fstat(fd, &stat)
	return stat, err
}

func linuxJailerFstatat(parentFD int, name string) (unix.Stat_t, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	return stat, err
}

func linuxJailerIdentity(stat unix.Stat_t) linuxJailerStagingIdentity {
	return linuxJailerStagingIdentity{device: uint64(stat.Dev), inode: stat.Ino}
}

func linuxJailerSameIdentity(stat unix.Stat_t, expected linuxJailerStagingIdentity) bool {
	return expected != (linuxJailerStagingIdentity{}) && uint64(stat.Dev) == expected.device && stat.Ino == expected.inode
}

func linuxJailerMetadataMatches(stat unix.Stat_t, uid, gid, mode uint32) bool {
	return stat.Uid == uid && stat.Gid == gid && stat.Mode&0o777 == mode
}

func removeLinuxJailerEmptyEntry(parentFD int, name string, expected linuxJailerStagingIdentity) error {
	if expected == (linuxJailerStagingIdentity{}) {
		return errJailerStagingCleanupIncomplete
	}
	stat, err := linuxJailerFstatat(parentFD, name)
	if err != nil {
		return err
	}
	if !linuxJailerSameIdentity(stat, expected) {
		return errJailerStagingCleanupIncomplete
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errJailerStagingCleanupIncomplete
	}
	return unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
}

func removeLinuxJailerFileEntry(parentFD int, name string, expected linuxJailerStagingIdentity) error {
	if expected == (linuxJailerStagingIdentity{}) {
		return errJailerStagingCleanupIncomplete
	}
	stat, err := linuxJailerFstatat(parentFD, name)
	if err != nil {
		return err
	}
	if !linuxJailerSameIdentity(stat, expected) {
		return errJailerStagingCleanupIncomplete
	}
	if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
		return errJailerStagingCleanupIncomplete
	}
	return unix.Unlinkat(parentFD, name, 0)
}

// removeLinuxJailerDirectoryContents admits entries outside the staging ledger
// only after the complete generation has passed final ownership verification.
// That distinction lets terminal post-Jailer cleanup remove runtime output
// without adopting an entry whose staging-time identity check never completed.
func removeLinuxJailerDirectoryContents(directoryFD int, prefix string, expected map[string]linuxJailerStagingEntry, allowUnrecorded bool) error {
	readFD, err := openLinuxJailerDirectoryAt(directoryFD, ".")
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(readFD), "jailer-owned-directory")
	if file == nil {
		_ = unix.Close(readFD)
		return errJailerStagingCleanupIncomplete
	}
	names, err := file.Readdirnames(-1)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "" || name == "." || name == ".." || strings.Contains(name, string(filepath.Separator)) || hasOSExecProcessControl(name) {
			return errJailerStagingCleanupIncomplete
		}
		before, err := linuxJailerFstatat(directoryFD, name)
		if err != nil {
			return err
		}
		id := linuxJailerIdentity(before)
		relative := name
		if prefix != "" {
			relative = filepath.Join(prefix, name)
		}
		entry, exists := expected[relative]
		if !exists && !allowUnrecorded {
			return errJailerStagingCleanupIncomplete
		}
		if exists {
			if !linuxJailerSameIdentity(before, entry.id) || entry.directory != (before.Mode&unix.S_IFMT == unix.S_IFDIR) {
				return errJailerStagingCleanupIncomplete
			}
		}
		if before.Mode&unix.S_IFMT == unix.S_IFDIR {
			childFD, err := openLinuxJailerDirectoryAt(directoryFD, name)
			if err != nil {
				return err
			}
			opened, statErr := linuxJailerFstat(childFD)
			if statErr != nil || !linuxJailerSameIdentity(opened, id) {
				_ = unix.Close(childFD)
				return errJailerStagingCleanupIncomplete
			}
			removeErr := removeLinuxJailerDirectoryContents(childFD, relative, expected, allowUnrecorded)
			closeErr := unix.Close(childFD)
			if removeErr != nil || closeErr != nil {
				return errors.Join(removeErr, closeErr)
			}
			after, err := linuxJailerFstatat(directoryFD, name)
			if err != nil || !linuxJailerSameIdentity(after, id) || unix.Unlinkat(directoryFD, name, unix.AT_REMOVEDIR) != nil {
				return errJailerStagingCleanupIncomplete
			}
			delete(expected, relative)
			continue
		}
		after, err := linuxJailerFstatat(directoryFD, name)
		if err != nil || !linuxJailerSameIdentity(after, id) || unix.Unlinkat(directoryFD, name, 0) != nil {
			return errJailerStagingCleanupIncomplete
		}
		delete(expected, relative)
	}
	return unix.Fsync(directoryFD)
}

func joinLinuxJailerCreationError(cleanupErr error) error {
	primary := newJailerStagingError(errJailerStagingFailed, "root")
	if cleanupErr != nil {
		return errors.Join(primary, newJailerStagingError(errJailerStagingCleanupIncomplete, "root"))
	}
	return primary
}
