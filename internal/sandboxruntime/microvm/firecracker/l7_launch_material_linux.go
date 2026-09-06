//go:build linux

package firecracker

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	"golang.org/x/sys/unix"
)

type sealedL7LaunchMaterial struct {
	mu        sync.Mutex
	assets    map[assets.AssetRole]*sealedL7Asset
	closeFile func(*os.File) error
	closed    bool
	closeErr  error
	childFD   int
	nameLayer string
}

type sealedL7Asset struct {
	file   *os.File
	size   int64
	digest [sha256.Size]byte
}

func newSealedL7LaunchMaterial(_ string, childFD int) (*sealedL7LaunchMaterial, error) {
	return newSealedLaunchMaterial(childFD, "l7")
}

func newSealedL8LaunchMaterial(_ string, childFD int) (*sealedL7LaunchMaterial, error) {
	return newSealedLaunchMaterial(childFD, "l8")
}

func newSealedLaunchMaterial(childFD int, nameLayer string) (*sealedL7LaunchMaterial, error) {
	if childFD != l7KernelChildFD && childFD != l7NamespaceKernelChildFD {
		return nil, errUnsafeLiveBootStateEntry
	}
	if nameLayer != "l7" && nameLayer != "l8" {
		return nil, errUnsafeLiveBootStateEntry
	}
	return &sealedL7LaunchMaterial{
		assets:    make(map[assets.AssetRole]*sealedL7Asset, 2),
		childFD:   childFD,
		nameLayer: nameLayer,
	}, nil
}

func (material *sealedL7LaunchMaterial) WriteAsset(role assets.AssetRole, source io.Reader) (string, error) {
	if material == nil {
		return "", errUnsafeLiveBootStateEntry
	}
	material.mu.Lock()
	defer material.mu.Unlock()
	if material.closed || source == nil || material.assets[role] != nil {
		return "", errUnsafeLiveBootStateEntry
	}
	name := ""
	nameLayer := material.nameLayer
	if nameLayer == "" {
		nameLayer = "l7"
	}
	childFD := 0
	switch role {
	case assets.AssetRoleKernel:
		name = "hal-" + nameLayer + "-kernel"
		childFD = material.childFD
	case assets.AssetRoleRootfs:
		name = "hal-" + nameLayer + "-rootfs"
		childFD = material.childFD + 1
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
		if closeErr := file.Close(); closeErr != nil {
			return "", errors.Join(err, newSanitizedL7LaunchMaterialCleanupError(closeErr))
		}
		return "", err
	}
	entry := &sealedL7Asset{file: file, size: size}
	copy(entry.digest[:], hash.Sum(nil))
	material.assets[role] = entry
	return "/proc/self/fd/" + childFDText(childFD), nil
}

func (material *sealedL7LaunchMaterial) Validate() error {
	if material == nil {
		return errUnsafeLiveBootStateEntry
	}
	material.mu.Lock()
	defer material.mu.Unlock()
	return material.validateLocked()
}

func (material *sealedL7LaunchMaterial) validateLocked() error {
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

// inheritedFiles returns start-owned descriptor duplicates while holding the
// material lock. The caller must close the returned files exactly once after
// the synchronous process-start boundary transfers them to the child.
func (material *sealedL7LaunchMaterial) inheritedFiles() ([]*os.File, error) {
	if material == nil {
		return nil, errUnsafeLiveBootStateEntry
	}
	material.mu.Lock()
	defer material.mu.Unlock()
	if err := material.validateLocked(); err != nil {
		return nil, err
	}
	owned := make([]*os.File, 0, 2)
	for _, role := range []assets.AssetRole{assets.AssetRoleKernel, assets.AssetRoleRootfs} {
		entry := material.assets[role]
		fd, err := unix.FcntlInt(entry.file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			cleanupErr := closeProcessInheritedFiles(owned)
			if cleanupErr != nil {
				return nil, errors.Join(errUnsafeLiveBootStateEntry, cleanupErr)
			}
			return nil, errUnsafeLiveBootStateEntry
		}
		owned = append(owned, os.NewFile(uintptr(fd), entry.file.Name()+"-start"))
	}
	return owned, nil
}

func (material *sealedL7LaunchMaterial) Close() error {
	if material == nil {
		return nil
	}
	material.mu.Lock()
	defer material.mu.Unlock()
	if material.closed {
		return material.closeErr
	}
	material.closed = true
	cleanupCauses := make([]error, 0, 2)
	closeFile := material.closeFile
	if closeFile == nil {
		closeFile = func(file *os.File) error { return file.Close() }
	}
	for _, role := range []assets.AssetRole{assets.AssetRoleKernel, assets.AssetRoleRootfs} {
		entry := material.assets[role]
		if entry != nil && entry.file != nil {
			if err := closeFile(entry.file); err != nil {
				cleanupCauses = append(cleanupCauses, err)
			}
		}
	}
	if len(cleanupCauses) > 0 {
		material.closeErr = newSanitizedL7LaunchMaterialCleanupError(cleanupCauses...)
	}
	return material.closeErr
}

func newSanitizedL7LaunchMaterialCleanupError(causes ...error) error {
	joined := errors.Join(causes...)
	if joined == nil {
		return nil
	}
	return sanitizedL7LaunchMaterialCleanupCause{causes: joined}
}

type sanitizedL7LaunchMaterialCleanupCause struct {
	causes error
}

func (sanitizedL7LaunchMaterialCleanupCause) Error() string {
	return errUnsafeLiveBootStateEntry.Error()
}

func (cause sanitizedL7LaunchMaterialCleanupCause) Is(target error) bool {
	return target == errUnsafeLiveBootStateEntry || errors.Is(cause.causes, target)
}

func (cause sanitizedL7LaunchMaterialCleanupCause) As(target any) bool {
	return errors.As(cause.causes, target)
}

func childFDText(fd int) string {
	switch fd {
	case l7KernelChildFD:
		return "3"
	case l7RootfsChildFD:
		return "4"
	case l7NamespaceKernelChildFD:
		return "5"
	case l7NamespaceRootfsChildFD:
		return "6"
	default:
		return ""
	}
}
