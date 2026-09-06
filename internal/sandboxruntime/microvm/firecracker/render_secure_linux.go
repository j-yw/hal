//go:build linux

package firecracker

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type secureLiveBootStateDir struct {
	fd         int
	beforeOpen func(string) error
}

func renderProductionLiveBootFiles(paths PathPlan, config []byte) error {
	state, err := openSecureLiveBootStateDir(paths.StateDir)
	if err != nil {
		return newLiveBootRenderConfigError("stateDir", "state directory ownership is invalid")
	}
	defer state.close()
	for _, file := range []struct {
		path    string
		data    []byte
		field   string
		message string
	}{
		{path: paths.ConfigPath, data: config, field: "configPath", message: "boot config write failed"},
		{path: paths.LogPath, field: "logPath", message: "log file preparation failed"},
		{path: paths.MetricsPath, field: "metricsPath", message: "metrics file preparation failed"},
	} {
		if err := state.writeFile(file.path, file.data); err != nil {
			if errors.Is(err, errUnsafeLiveBootStateEntry) {
				return newLiveBootRenderConfigError(file.field, "support file path is invalid")
			}
			return newLiveBootRenderFailure(file.field, file.message, err)
		}
	}
	return nil
}

func openSecureLiveBootStateDir(path string) (*secureLiveBootStateDir, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Mode&0o777 != 0o700 ||
		int(stat.Uid) != os.Geteuid() {
		_ = unix.Close(fd)
		return nil, errUnsafeLiveBootStateEntry
	}
	return &secureLiveBootStateDir{fd: fd}, nil
}

func (state *secureLiveBootStateDir) close() {
	if state != nil && state.fd >= 0 {
		_ = unix.Close(state.fd)
		state.fd = -1
	}
}

func (state *secureLiveBootStateDir) writeFile(path string, data []byte) error {
	if state == nil || state.fd < 0 {
		return errUnsafeLiveBootStateEntry
	}
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) || filepath.Dir(path) == path {
		return errUnsafeLiveBootStateEntry
	}
	var before unix.Stat_t
	existed := unix.Fstatat(state.fd, name, &before, unix.AT_SYMLINK_NOFOLLOW) == nil
	if existed && !safeLiveBootStateFileStat(before) {
		return errUnsafeLiveBootStateEntry
	}
	if state.beforeOpen != nil {
		if err := state.beforeOpen(name); err != nil {
			return err
		}
	}
	flags := unix.O_WRONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if !existed {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, err := unix.Openat(state.fd, name, flags, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if !existed {
		if err := unix.Fchmod(fd, 0o600); err != nil {
			return err
		}
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil ||
		!safeLiveBootStateFileStat(after) ||
		existed && (before.Dev != after.Dev || before.Ino != after.Ino) {
		return errUnsafeLiveBootStateEntry
	}
	if existed {
		if err := unix.Ftruncate(fd, 0); err != nil {
			return err
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return err
		}
	}
	if _, err := io.Copy(file, &fixedByteReader{data: data}); err != nil {
		return err
	}
	return file.Sync()
}

func safeLiveBootStateFileStat(stat unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG &&
		stat.Mode&0o777 == 0o600 &&
		int(stat.Uid) == os.Geteuid()
}

type fixedByteReader struct {
	data []byte
}

func (reader *fixedByteReader) Read(output []byte) (int, error) {
	if len(reader.data) == 0 {
		return 0, io.EOF
	}
	n := copy(output, reader.data)
	reader.data = reader.data[n:]
	return n, nil
}
