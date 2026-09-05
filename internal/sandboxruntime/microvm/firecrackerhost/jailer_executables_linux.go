//go:build linux

package firecrackerhost

import (
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

const strictJailerExecutableSeals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL

func pinStrictJailerExecutables(inspection strictJailerHostInspectionResult) (*strictJailerExecutablePair, error) {
	return pinStrictJailerExecutablesWithFilesystem(inspection, osStrictJailerHostInspectionFilesystem{})
}

func pinStrictJailerExecutablesWithFilesystem(inspection strictJailerHostInspectionResult, filesystem strictJailerHostInspectionFilesystem) (*strictJailerExecutablePair, error) {
	if filesystem == nil {
		return nil, errStrictJailerExecutablesInvalid
	}
	pair := &strictJailerExecutablePair{}
	paths := [2]string{inspection.canonicalJailerPath, inspection.canonicalFirecrackerPath}
	infos := [2]os.FileInfo{inspection.jailerInfo, inspection.firecrackerInfo}
	digests := [2][sha256.Size]byte{inspection.jailerSHA256, inspection.firecrackerSHA256}
	for index, path := range paths {
		if _, err := inspectStrictJailerTrustedDirectory(filesystem, filepath.Dir(path), "binaryPair",
			inspection.canonicalTrustedFilesystemAnchor, inspection.trustedFilesystemAnchorInfo); err != nil {
			_ = pair.close()
			return nil, errStrictJailerExecutablesInvalid
		}
		file, err := filesystem.OpenNoFollow(path)
		if err != nil {
			_ = pair.close()
			return nil, errStrictJailerExecutablesInvalid
		}
		info, statErr := file.Stat()
		if statErr != nil || !validStrictJailerHostBinaryInfo(filesystem, info) || !filesystem.SameFile(info, infos[index]) {
			_ = file.Close()
			_ = pair.close()
			return nil, errStrictJailerExecutablesInvalid
		}
		snapshot, snapshotErr := snapshotStrictJailerExecutable(file, digests[index])
		closeErr := file.Close()
		if snapshotErr != nil || closeErr != nil {
			if snapshot != nil {
				_ = snapshot.Close()
			}
			_ = pair.close()
			return nil, errStrictJailerExecutablesInvalid
		}
		pair.entries[index] = strictJailerExecutable{path: path, file: snapshot, digest: digests[index]}
	}
	return pair, nil
}

func snapshotStrictJailerExecutable(source io.Reader, expected [sha256.Size]byte) (*os.File, error) {
	if source == nil || expected == ([sha256.Size]byte{}) {
		return nil, errStrictJailerExecutablesInvalid
	}
	fd, err := unix.MemfdCreate("hal-jailer-executable", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, errStrictJailerExecutablesInvalid
	}
	file := os.NewFile(uintptr(fd), "hal-jailer-executable")
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hasher), io.LimitReader(source, maxStrictJailerExecutableBytes+1))
	if copyErr != nil || written <= 0 || written > maxStrictJailerExecutableBytes || strictJailerHostHashSum(hasher) != expected {
		_ = file.Close()
		return nil, errStrictJailerExecutablesInvalid
	}
	if err := file.Chmod(0o555); err != nil {
		_ = file.Close()
		return nil, errStrictJailerExecutablesInvalid
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, strictJailerExecutableSeals); err != nil {
		_ = file.Close()
		return nil, errStrictJailerExecutablesInvalid
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil || validateStrictJailerExecutableSnapshot(file) != nil {
		_ = file.Close()
		return nil, errStrictJailerExecutablesInvalid
	}
	return file, nil
}

func validateStrictJailerExecutableSnapshot(file *os.File) error {
	if file == nil {
		return errStrictJailerExecutablesInvalid
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxStrictJailerExecutableBytes || info.Mode().Perm() != 0o555 {
		return errStrictJailerExecutablesInvalid
	}
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&strictJailerExecutableSeals != strictJailerExecutableSeals {
		return errStrictJailerExecutablesInvalid
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		return errStrictJailerExecutablesInvalid
	}
	return nil
}

func (pair *strictJailerExecutablePair) duplicateForLaunch(command strictJailerCommand) (*strictJailerExecutableLease, error) {
	if pair == nil {
		return nil, errStrictJailerExecutablesInvalid
	}
	pair.mu.Lock()
	defer pair.mu.Unlock()
	if pair.closed || pair.entries[0].path != command.jailerPath || pair.entries[1].path != command.firecrackerPath ||
		pair.entries[0].digest == ([sha256.Size]byte{}) || pair.entries[1].digest == ([sha256.Size]byte{}) ||
		pair.entries[0].digest == pair.entries[1].digest {
		return nil, errStrictJailerExecutablesInvalid
	}
	lease := &strictJailerExecutableLease{}
	for index, entry := range pair.entries {
		if validateStrictJailerExecutableSnapshot(entry.file) != nil {
			_ = lease.close()
			return nil, errStrictJailerExecutablesInvalid
		}
		fd, err := unix.FcntlInt(entry.file.Fd(), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			_ = lease.close()
			return nil, errStrictJailerExecutablesInvalid
		}
		lease.entries[index] = entry
		lease.entries[index].file = os.NewFile(uintptr(fd), "hal-jailer-executable-launch")
	}
	return lease, nil
}

type strictJailerExecutableMountOps struct {
	unshare     func() error
	makePrivate func() error
	bind        func(strictJailerExecutable) error
	verify      func(strictJailerExecutable) error
}

// Run only on the locked launch thread. A namespace is isolated and recursively
// private before either bind; no mount can propagate back into the host. On
// any failure the thread is retired without exec, releasing its entire private
// mount namespace, including a partially installed pair. After successful
// Start, the child and retained creating thread own the namespace until exit.
func mountStrictJailerExecutables(lease *strictJailerExecutableLease, ops strictJailerExecutableMountOps) error {
	if lease == nil || ops.unshare == nil || ops.makePrivate == nil || ops.bind == nil || ops.verify == nil {
		return errStrictJailerExecutablesInvalid
	}
	if err := ops.unshare(); err != nil {
		return errStrictJailerExecutablesInvalid
	}
	if err := ops.makePrivate(); err != nil {
		return errStrictJailerExecutablesInvalid
	}
	for _, entry := range lease.entries {
		if err := ops.bind(entry); err != nil {
			return errStrictJailerExecutablesInvalid
		}
	}
	// Inspect both after both binds so overlapping or changed paths cannot make
	// the second bind invalidate a previously accepted first executable.
	for _, entry := range lease.entries {
		if err := ops.verify(entry); err != nil {
			return errStrictJailerExecutablesInvalid
		}
	}
	return nil
}

func linuxStrictJailerExecutableMountOps() strictJailerExecutableMountOps {
	return strictJailerExecutableMountOps{
		unshare:     func() error { return unix.Unshare(unix.CLONE_NEWNS) },
		makePrivate: func() error { return unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "") },
		bind:        bindStrictJailerExecutable,
		verify:      verifyMountedStrictJailerExecutable,
	}
}

func bindStrictJailerExecutable(entry strictJailerExecutable) error {
	if validateStrictJailerExecutableSnapshot(entry.file) != nil || validateStrictJailerExecutableMountPath(entry.path) != nil {
		return errStrictJailerExecutablesInvalid
	}
	source := "/proc/self/fd/" + strconv.FormatUint(uint64(entry.file.Fd()), 10)
	if err := unix.Mount(source, entry.path, "", unix.MS_BIND, ""); err != nil {
		return errStrictJailerExecutablesInvalid
	}
	if err := unix.Mount("", entry.path, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		return errStrictJailerExecutablesInvalid
	}
	return nil
}

func validateStrictJailerExecutableMountPath(path string) error {
	filesystem := osStrictJailerHostInspectionFilesystem{}
	resolved, err := filesystem.EvalSymlinks(path)
	if err != nil || resolved != path || !filepathIsCleanAbsolute(path) || cleanupFilesystemRoot(path) {
		return errStrictJailerExecutablesInvalid
	}
	leaf, err := filesystem.Lstat(path)
	if err != nil || !validStrictJailerHostBinaryInfo(filesystem, leaf) {
		return errStrictJailerExecutablesInvalid
	}
	anchor, info, err := inspectStrictJailerTrustedFilesystemAnchor(filesystem, "")
	if err != nil {
		return errStrictJailerExecutablesInvalid
	}
	if _, err := inspectStrictJailerTrustedDirectoryChain(filesystem, filepath.Dir(path), "binaryPair", anchor, info); err != nil {
		return errStrictJailerExecutablesInvalid
	}
	return nil
}

func verifyMountedStrictJailerExecutable(entry strictJailerExecutable) error {
	if validateStrictJailerExecutableMountPath(entry.path) != nil {
		return errStrictJailerExecutablesInvalid
	}
	file, err := (osStrictJailerHostInspectionFilesystem{}).OpenNoFollow(entry.path)
	if err != nil {
		return errStrictJailerExecutablesInvalid
	}
	defer file.Close()
	info, err := file.Stat()
	expected, expectedErr := entry.file.Stat()
	if err != nil || expectedErr != nil || !os.SameFile(info, expected) {
		return errStrictJailerExecutablesInvalid
	}
	return nil
}
