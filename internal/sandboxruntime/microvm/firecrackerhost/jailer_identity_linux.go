//go:build linux

package firecrackerhost

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	jailerIdentityLockName    = "identity.lock"
	jailerIdentityJournalName = "identity.json"
)

type linuxJailerIdentityNode struct {
	fd     int
	name   string
	stat   unix.Stat_t
	fsType int64
}

// Injection is private and per-open. Production always uses the root-owned
// checks below; ordinary-file tests can observe locking without claiming root
// ownership of their fixture directories.
type linuxJailerIdentityChecks struct {
	directory func(unix.Stat_t, bool) bool
	file      func(unix.Stat_t) bool
}

type linuxJailerIdentityFilesystem struct {
	chain          []linuxJailerIdentityNode
	lockNode       linuxJailerIdentityNode
	journal        linuxJailerIdentityNode
	checks         linuxJailerIdentityChecks
	locked, closed bool
}

func openLinuxJailerIdentityFilesystem(directory string) (strictJailerIdentityFilesystem, error) {
	return openLinuxJailerIdentityFilesystemWithChecks(directory, linuxJailerIdentityChecks{
		directory: func(stat unix.Stat_t, final bool) bool {
			return stat.Uid == 0 && stat.Mode&0o022 == 0 && (!final || stat.Mode&0o7777 == 0o700)
		},
		file: func(stat unix.Stat_t) bool { return stat.Uid == 0 && stat.Mode&0o7777 == 0o600 },
	})
}

func openLinuxJailerIdentityFilesystemWithChecks(directory string, checks linuxJailerIdentityChecks) (strictJailerIdentityFilesystem, error) {
	if checks.directory == nil || checks.file == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		directory == "/" || len(directory) > 4096 || strings.ContainsAny(directory, "\x00\r\n") {
		return nil, errJailerIdentity
	}
	parts := strings.Split(strings.TrimPrefix(directory, "/"), "/")
	if len(parts) > 64 {
		return nil, errJailerIdentity
	}
	fs := &linuxJailerIdentityFilesystem{checks: checks, lockNode: linuxJailerIdentityNode{fd: -1}, journal: linuxJailerIdentityNode{fd: -1}}
	success := false
	defer func() {
		if !success {
			_ = fs.close()
		}
	}()
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errJailerIdentity
	}
	root, err := readLinuxJailerIdentityNode(fd, "")
	if err != nil {
		_ = unix.Close(fd)
		return nil, errJailerIdentity
	}
	fs.chain = append(fs.chain, root)
	if !checks.directory(root.stat, false) {
		return nil, errJailerIdentity
	}
	for index, part := range parts {
		fd, err = unix.Openat(fs.chain[len(fs.chain)-1].fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, errJailerIdentity
		}
		node, err := readLinuxJailerIdentityNode(fd, part)
		if err != nil {
			_ = unix.Close(fd)
			return nil, errJailerIdentity
		}
		fs.chain = append(fs.chain, node)
		if !checks.directory(node.stat, index == len(parts)-1) {
			return nil, errJailerIdentity
		}
	}
	for _, node := range []*linuxJailerIdentityNode{&fs.lockNode, &fs.journal} {
		name := jailerIdentityLockName
		if node == &fs.journal {
			name = jailerIdentityJournalName
		}
		fd, err = unix.Openat(fs.anchor().fd, name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return nil, errJailerIdentity
		}
		*node, err = readLinuxJailerIdentityNode(fd, name)
		if err != nil {
			_ = unix.Close(fd)
			node.fd = -1
			return nil, errJailerIdentity
		}
	}
	if fs.verify() != nil {
		return nil, errJailerIdentity
	}
	success = true
	return fs, nil
}

func readLinuxJailerIdentityNode(fd int, name string) (linuxJailerIdentityNode, error) {
	var stat unix.Stat_t
	var filesystem unix.Statfs_t
	if unix.Fstat(fd, &stat) != nil || unix.Fstatfs(fd, &filesystem) != nil {
		return linuxJailerIdentityNode{}, errJailerIdentity
	}
	return linuxJailerIdentityNode{fd: fd, name: name, stat: stat, fsType: int64(filesystem.Type)}, nil
}

func sameLinuxJailerIdentityStat(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode && left.Uid == right.Uid && left.Gid == right.Gid
}

func (fs *linuxJailerIdentityFilesystem) anchor() linuxJailerIdentityNode {
	return fs.chain[len(fs.chain)-1]
}

func (fs *linuxJailerIdentityFilesystem) verifyNode(node linuxJailerIdentityNode, parentFD int) error {
	current, err := readLinuxJailerIdentityNode(node.fd, node.name)
	if err != nil || !sameLinuxJailerIdentityStat(node.stat, current.stat) || node.fsType != current.fsType {
		return errJailerIdentity
	}
	if parentFD >= 0 {
		var named unix.Stat_t
		if unix.Fstatat(parentFD, node.name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameLinuxJailerIdentityStat(node.stat, named) {
			return errJailerIdentity
		}
	}
	if current.stat.Mode&unix.S_IFMT == unix.S_IFDIR {
		if !fs.checks.directory(current.stat, node.fd == fs.anchor().fd) {
			return errJailerIdentity
		}
	} else if current.stat.Mode&unix.S_IFMT != unix.S_IFREG || current.stat.Nlink != 1 || !fs.checks.file(current.stat) ||
		current.stat.Size < 0 || current.stat.Size > jailerIdentityJournalLimit ||
		(node.name == jailerIdentityLockName && current.stat.Size != 0) {
		return errJailerIdentity
	}
	return nil
}

func (fs *linuxJailerIdentityFilesystem) verify() error {
	if fs == nil || fs.closed || len(fs.chain) == 0 || fs.lockNode.fd < 0 || fs.journal.fd < 0 {
		return errJailerIdentity
	}
	for index, node := range fs.chain {
		parentFD := -1
		if index > 0 {
			parentFD = fs.chain[index-1].fd
		}
		if fs.verifyNode(node, parentFD) != nil {
			return errJailerIdentity
		}
	}
	if fs.verifyNode(fs.lockNode, fs.anchor().fd) != nil || fs.verifyNode(fs.journal, fs.anchor().fd) != nil ||
		fs.lockNode.stat.Dev != fs.anchor().stat.Dev || fs.journal.stat.Dev != fs.anchor().stat.Dev ||
		fs.lockNode.fsType != fs.anchor().fsType || fs.journal.fsType != fs.anchor().fsType ||
		fs.lockNode.stat.Ino == fs.journal.stat.Ino {
		return errJailerIdentity
	}
	return nil
}

func (fs *linuxJailerIdentityFilesystem) lock() error {
	if fs.locked || fs.verify() != nil || unix.Flock(fs.lockNode.fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return errJailerIdentity
	}
	fs.locked = true
	return fs.verify()
}

func (fs *linuxJailerIdentityFilesystem) read() ([]byte, error) {
	if !fs.locked || fs.verify() != nil {
		return nil, errJailerIdentity
	}
	data := make([]byte, jailerIdentityJournalLimit+1)
	n, err := unix.Pread(fs.journal.fd, data, 0)
	if err != nil || n == 0 || n > jailerIdentityJournalLimit || fs.verify() != nil {
		return nil, errJailerIdentity
	}
	var stat unix.Stat_t
	if unix.Fstat(fs.journal.fd, &stat) != nil || stat.Size != int64(n) {
		return nil, errJailerIdentity
	}
	return data[:n], nil
}

func (fs *linuxJailerIdentityFilesystem) write(payload []byte) error {
	if !fs.locked || len(payload) == 0 || len(payload) > jailerIdentityJournalLimit || fs.verify() != nil {
		return errJailerIdentity
	}
	for offset := 0; offset < len(payload); {
		n, err := unix.Pwrite(fs.journal.fd, payload[offset:], int64(offset))
		if err != nil || n <= 0 {
			return errJailerIdentity
		}
		offset += n
	}
	if unix.Ftruncate(fs.journal.fd, int64(len(payload))) != nil || fs.verify() != nil {
		return errJailerIdentity
	}
	return nil
}

func (fs *linuxJailerIdentityFilesystem) sync() error {
	if !fs.locked || fs.verify() != nil || unix.Fsync(fs.journal.fd) != nil || unix.Fsync(fs.anchor().fd) != nil || fs.verify() != nil {
		return errJailerIdentity
	}
	return nil
}

func (fs *linuxJailerIdentityFilesystem) close() error {
	if fs == nil || fs.closed {
		return nil
	}
	fs.closed = true
	var result error
	closeNode := func(node *linuxJailerIdentityNode) {
		fd := node.fd
		node.fd = -1
		if fd >= 0 && unix.Close(fd) != nil {
			result = errJailerIdentity
		}
	}
	closeNode(&fs.journal)
	closeNode(&fs.lockNode)
	for index := len(fs.chain) - 1; index >= 0; index-- {
		closeNode(&fs.chain[index])
	}
	return result
}
