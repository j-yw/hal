//go:build linux

package firecrackerhost

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type linuxJailerCgroupNode struct {
	fd     int
	name   string
	stat   unix.Stat_t
	fsType int64
}

type linuxJailerCgroupFilesystem struct {
	chain        []linuxJailerCgroupNode
	child        linuxJailerCgroupNode
	childCreated bool
}

func newLinuxJailerCgroupFilesystem(anchor string) (strictJailerCgroupFilesystem, error) {
	if !filepath.IsAbs(anchor) || filepath.Clean(anchor) != anchor || anchor == "/" {
		return nil, errJailerCgroup
	}
	fs := &linuxJailerCgroupFilesystem{child: linuxJailerCgroupNode{fd: -1}}
	success := false
	defer func() {
		if !success {
			_ = fs.close()
		}
	}()
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errJailerCgroup
	}
	root, err := inspectLinuxJailerCgroupNode(fd, "")
	if err != nil {
		_ = unix.Close(fd)
		return nil, errJailerCgroup
	}
	fs.chain = append(fs.chain, root)
	for _, part := range strings.Split(strings.TrimPrefix(anchor, "/"), "/") {
		fd, err = unix.Openat(fs.chain[len(fs.chain)-1].fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, errJailerCgroup
		}
		node, err := inspectLinuxJailerCgroupNode(fd, part)
		if err != nil {
			_ = unix.Close(fd)
			return nil, errJailerCgroup
		}
		fs.chain = append(fs.chain, node)
	}
	if fs.anchor().fsType != unix.CGROUP2_SUPER_MAGIC || fs.verifyAnchor() != nil {
		return nil, errJailerCgroup
	}
	success = true
	return fs, nil
}

func inspectLinuxJailerCgroupNode(fd int, name string) (linuxJailerCgroupNode, error) {
	var stat unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &stat) != nil || unix.Fstatfs(fd, &fs) != nil || !validLinuxJailerCgroupDirectory(stat) {
		return linuxJailerCgroupNode{}, errJailerCgroup
	}
	return linuxJailerCgroupNode{fd: fd, name: name, stat: stat, fsType: int64(fs.Type)}, nil
}

func validLinuxJailerCgroupDirectory(stat unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFDIR && stat.Uid == 0 && stat.Mode&0o022 == 0
}

func (fs *linuxJailerCgroupFilesystem) anchor() linuxJailerCgroupNode {
	return fs.chain[len(fs.chain)-1]
}

func sameLinuxJailerCgroupNode(left, right linuxJailerCgroupNode) bool {
	return left.stat.Dev == right.stat.Dev && left.stat.Ino == right.stat.Ino && left.stat.Uid == right.stat.Uid &&
		left.stat.Gid == right.stat.Gid && left.stat.Mode == right.stat.Mode && left.fsType == right.fsType
}

func (fs *linuxJailerCgroupFilesystem) verifyAnchor() error {
	if fs == nil || len(fs.chain) == 0 {
		return errJailerCgroup
	}
	for index, node := range fs.chain {
		current, err := inspectLinuxJailerCgroupNode(node.fd, node.name)
		if err != nil || !sameLinuxJailerCgroupNode(current, node) {
			return errJailerCgroup
		}
		if index > 0 {
			var named unix.Stat_t
			if unix.Fstatat(fs.chain[index-1].fd, node.name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || named.Dev != node.stat.Dev || named.Ino != node.stat.Ino || named.Mode != node.stat.Mode || named.Uid != 0 {
				return errJailerCgroup
			}
		}
	}
	anchor := fs.anchor()
	if anchor.fsType != unix.CGROUP2_SUPER_MAGIC {
		return errJailerCgroup
	}
	typeValue, err := readLinuxJailerCgroupControl(anchor, "cgroup.type")
	if err != nil || typeValue != "domain\n" {
		return errJailerCgroup
	}
	controllers, err := readLinuxJailerCgroupControl(anchor, "cgroup.subtree_control")
	if err != nil {
		return errJailerCgroup
	}
	if !jailerCgroupControllersEnabled(controllers) {
		return errJailerCgroup
	}
	return nil
}

func (fs *linuxJailerCgroupFilesystem) create(name string) error {
	if fs.childCreated || !validStrictJailerRuntimeID(name) || fs.verifyAnchor() != nil {
		return errJailerCgroup
	}
	if unix.Mkdirat(fs.anchor().fd, name, 0o700) != nil {
		return errJailerCgroup
	}
	fs.childCreated = true
	fs.child.name = name
	// If identity acquisition fails, retain an unresolved creation. Never
	// remove a later path occupant merely because mkdir previously succeeded.
	var named unix.Stat_t
	if unix.Fstatat(fs.anchor().fd, name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return errJailerCgroup
	}
	fd, err := unix.Openat(fs.anchor().fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errJailerCgroup
	}
	node, err := inspectLinuxJailerCgroupNode(fd, name)
	if err != nil || node.stat.Dev != named.Dev || node.stat.Ino != named.Ino || node.stat.Dev != fs.anchor().stat.Dev || node.fsType != unix.CGROUP2_SUPER_MAGIC || node.stat.Mode&0o7777 != 0o700 {
		_ = unix.Close(fd)
		return errJailerCgroup
	}
	fs.child = node
	return fs.verify()
}

func (fs *linuxJailerCgroupFilesystem) created() bool { return fs.childCreated }

func (fs *linuxJailerCgroupFilesystem) verify() error {
	if !fs.childCreated || fs.child.fd < 0 || fs.verifyAnchor() != nil {
		return errJailerCgroup
	}
	current, err := inspectLinuxJailerCgroupNode(fs.child.fd, fs.child.name)
	var named unix.Stat_t
	if err != nil || !sameLinuxJailerCgroupNode(current, fs.child) ||
		unix.Fstatat(fs.anchor().fd, fs.child.name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || named.Dev != fs.child.stat.Dev || named.Ino != fs.child.stat.Ino || named.Mode != fs.child.stat.Mode || named.Uid != 0 {
		return errJailerCgroup
	}
	value, err := readLinuxJailerCgroupControl(fs.child, "cgroup.type")
	if err != nil || value != "domain\n" {
		return errJailerCgroup
	}
	return nil
}

func openLinuxJailerCgroupControl(node linuxJailerCgroupNode, name string, flags int) (*os.File, unix.Stat_t, error) {
	switch name {
	case "cgroup.type", "cgroup.subtree_control", "cpu.max", "memory.max", "memory.swap.max", "pids.max", "cgroup.events", "cgroup.kill":
	default:
		return nil, unix.Stat_t{}, errJailerCgroup
	}
	fd, err := unix.Openat(node.fd, name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, unix.Stat_t{}, errJailerCgroup
	}
	var stat, named unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &stat) != nil || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || stat.Dev != node.stat.Dev ||
		stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o022 != 0 ||
		unix.Fstatat(node.fd, name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || named.Dev != stat.Dev || named.Ino != stat.Ino {
		_ = unix.Close(fd)
		return nil, unix.Stat_t{}, errJailerCgroup
	}
	return os.NewFile(uintptr(fd), "jailer-cgroup-control"), stat, nil
}

func readLinuxJailerCgroupControl(node linuxJailerCgroupNode, name string) (string, error) {
	file, before, err := openLinuxJailerCgroupControl(node, name, unix.O_RDONLY)
	if err != nil {
		return "", errJailerCgroup
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, 4097))
	var after unix.Stat_t
	if err != nil || len(value) > 4096 || unix.Fstatat(node.fd, name, &after, unix.AT_SYMLINK_NOFOLLOW) != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Mode != before.Mode || after.Uid != before.Uid {
		return "", errJailerCgroup
	}
	return string(value), nil
}

func (fs *linuxJailerCgroupFilesystem) read(name string) (string, error) {
	if fs.verify() != nil {
		return "", errJailerCgroup
	}
	return readLinuxJailerCgroupControl(fs.child, name)
}

func (fs *linuxJailerCgroupFilesystem) write(name, value string) error {
	switch name {
	case "cpu.max", "memory.max", "memory.swap.max", "pids.max", "cgroup.kill":
	default:
		return errJailerCgroup
	}
	if fs.verify() != nil || len(value) > 128 {
		return errJailerCgroup
	}
	file, before, err := openLinuxJailerCgroupControl(fs.child, name, unix.O_WRONLY)
	if err != nil {
		return errJailerCgroup
	}
	defer file.Close()
	if fs.verify() != nil {
		return errJailerCgroup
	}
	n, err := file.WriteString(value)
	var after unix.Stat_t
	if err != nil || n != len(value) || unix.Fstatat(fs.child.fd, name, &after, unix.AT_SYMLINK_NOFOLLOW) != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Mode != before.Mode || after.Uid != before.Uid || fs.verify() != nil {
		return errJailerCgroup
	}
	return nil
}

func (fs *linuxJailerCgroupFilesystem) duplicate() (*os.File, error) {
	if fs.verify() != nil {
		return nil, errJailerCgroup
	}
	fd, err := unix.FcntlInt(uintptr(fs.child.fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, errJailerCgroup
	}
	return os.NewFile(uintptr(fd), "jailer-cgroup-launch"), nil
}

func (fs *linuxJailerCgroupFilesystem) remove() error {
	if fs.verify() != nil {
		return errJailerCgroup
	}
	if unix.Unlinkat(fs.anchor().fd, fs.child.name, unix.AT_REMOVEDIR) != nil {
		return errJailerCgroup
	}
	fs.childCreated = false
	return nil
}

func (fs *linuxJailerCgroupFilesystem) close() error {
	var result error
	if fs.child.fd >= 0 {
		result = errors.Join(result, unix.Close(fs.child.fd))
		fs.child.fd = -1
	}
	for index := len(fs.chain) - 1; index >= 0; index-- {
		if fs.chain[index].fd >= 0 {
			result = errors.Join(result, unix.Close(fs.chain[index].fd))
			fs.chain[index].fd = -1
		}
	}
	return result
}
