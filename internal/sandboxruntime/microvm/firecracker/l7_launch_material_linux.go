//go:build linux

package firecracker

import (
	"crypto/sha256"
	"io"
	"os"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	"golang.org/x/sys/unix"
)

const (
	l7KernelChildFD = 3
	l7RootfsChildFD = 4
)

type sealedL7LaunchMaterial struct {
	assets map[assets.AssetRole]*sealedL7Asset
	closed bool
}

type sealedL7Asset struct {
	file   *os.File
	size   int64
	digest [sha256.Size]byte
}

func newSealedL7LaunchMaterial(string) (*sealedL7LaunchMaterial, error) {
	return &sealedL7LaunchMaterial{assets: make(map[assets.AssetRole]*sealedL7Asset, 2)}, nil
}

func (material *sealedL7LaunchMaterial) WriteAsset(role assets.AssetRole, source io.Reader) (string, error) {
	if material == nil || material.closed || source == nil || material.assets[role] != nil {
		return "", errUnsafeLiveBootStateEntry
	}
	name := ""
	childFD := 0
	switch role {
	case assets.AssetRoleKernel:
		name = "hal-l7-kernel"
		childFD = l7KernelChildFD
	case assets.AssetRoleRootfs:
		name = "hal-l7-rootfs"
		childFD = l7RootfsChildFD
	default:
		return "", errUnsafeLiveBootStateEntry
	}
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), name)
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(file, hash), source)
	if err == nil {
		_, err = file.Seek(0, io.SeekStart)
	}
	if err == nil {
		_, err = unix.FcntlInt(
			file.Fd(),
			unix.F_ADD_SEALS,
			unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL,
		)
	}
	if err != nil {
		_ = file.Close()
		return "", err
	}
	entry := &sealedL7Asset{file: file, size: size}
	copy(entry.digest[:], hash.Sum(nil))
	material.assets[role] = entry
	return "/proc/self/fd/" + childFDText(childFD), nil
}

func (material *sealedL7LaunchMaterial) Validate() error {
	if material == nil || material.closed || len(material.assets) != 2 {
		return errUnsafeLiveBootStateEntry
	}
	wantSeals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	for _, role := range []assets.AssetRole{assets.AssetRoleKernel, assets.AssetRoleRootfs} {
		entry := material.assets[role]
		if entry == nil || entry.file == nil {
			return errUnsafeLiveBootStateEntry
		}
		seals, err := unix.FcntlInt(entry.file.Fd(), unix.F_GET_SEALS, 0)
		if err != nil || seals&wantSeals != wantSeals {
			return errUnsafeLiveBootStateEntry
		}
		if _, err := entry.file.Seek(0, io.SeekStart); err != nil {
			return errUnsafeLiveBootStateEntry
		}
		hash := sha256.New()
		size, err := io.Copy(hash, entry.file)
		if err != nil || size != entry.size {
			return errUnsafeLiveBootStateEntry
		}
		var digest [sha256.Size]byte
		copy(digest[:], hash.Sum(nil))
		if digest != entry.digest {
			return errUnsafeLiveBootStateEntry
		}
		if _, err := entry.file.Seek(0, io.SeekStart); err != nil {
			return errUnsafeLiveBootStateEntry
		}
	}
	return nil
}

func (material *sealedL7LaunchMaterial) inheritedFiles() ([]*os.File, error) {
	if err := material.Validate(); err != nil {
		return nil, err
	}
	return []*os.File{
		material.assets[assets.AssetRoleKernel].file,
		material.assets[assets.AssetRoleRootfs].file,
	}, nil
}

func (material *sealedL7LaunchMaterial) Close() error {
	if material == nil || material.closed {
		return nil
	}
	material.closed = true
	failed := false
	for _, role := range []assets.AssetRole{assets.AssetRoleKernel, assets.AssetRoleRootfs} {
		entry := material.assets[role]
		if entry != nil && entry.file != nil && entry.file.Close() != nil {
			failed = true
		}
	}
	if failed {
		return errUnsafeLiveBootStateEntry
	}
	return nil
}

func childFDText(fd int) string {
	switch fd {
	case l7KernelChildFD:
		return "3"
	case l7RootfsChildFD:
		return "4"
	default:
		return ""
	}
}
