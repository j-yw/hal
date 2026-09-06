//go:build linux

package firecrackerhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"golang.org/x/sys/unix"
)

// All policy and executable pins here are constructor-injected prepared-host
// inputs, not deserialized job/worker claims. No caller can substitute an
// unverified rootfs or kernel for the opaque authenticated distribution.
type jailerRecoveryProducerRequest struct {
	distribution            localresolver.VerifiedL8MinimalDistribution
	job                     jailerRecoveryJob
	policy                  jailerRecoveryHostPolicy
	paths                   firecracker.PathPlan
	config                  []byte
	enablePCI               bool
	ownerExecutable         io.Reader
	ownerExecutableSHA256   [sha256.Size]byte
	ownerDirectory, rootKey *os.File
	namespaces              [2]*os.File
}

// No default runtime selects this private producer. It launches the existing
// owner executable and returns the same owner's reconnect client, even when
// post-start publication/cleanup is uncertain; ownership must not be discarded.
func launchJailerRecoverySupervisor(ctx context.Context, request jailerRecoveryProducerRequest) (*jailerRecoveryClient, error) {
	return withJailerRecoveryProducerInputs(ctx, request, startJailerRecoverySupervisorCommand)
}

type jailerRecoveryProducerStart func(context.Context, jailerRecoverySupervisorConfig, *os.File, *os.File, [5]*os.File, [2]*os.File) (*jailerRecoveryClient, error)

func withJailerRecoveryProducerInputs(ctx context.Context, request jailerRecoveryProducerRequest, start jailerRecoveryProducerStart) (*jailerRecoveryClient, error) {
	if ctx == nil || ctx.Err() != nil || start == nil || request.ownerExecutable == nil || request.ownerExecutableSHA256 == ([32]byte{}) || request.ownerDirectory == nil || request.rootKey == nil || len(request.config) == 0 || len(request.config) > maxStrictJailerConfigBytes {
		return nil, errL8RuntimeOwnerInvalid
	}
	lease, err := request.distribution.TakeLaunchLease(ctx)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	defer lease.Close()
	config := jailerRecoverySupervisorConfig{Version: jailerRecoveryConfigVersion, Job: request.job, Policy: request.policy, Paths: request.paths, EnablePCI: request.enablePCI, Roles: jailerRecoverySupervisorRoles()}
	var assets [3]*os.File
	defer func() {
		for _, file := range assets {
			if file != nil {
				_ = file.Close()
			}
		}
	}()
	// Mutable views expire before launch. Retain the lease, but cross the
	// process boundary only with independently measured immutable snapshots.
	err = lease.WithAssets(ctx, func(kernel, rootfs localresolver.L8MinimalLaunchAsset) error {
		for index, input := range []localresolver.L8MinimalLaunchAsset{kernel, rootfs} {
			limit := int64(128 << 20)
			kind := "kernel"
			if index == 1 {
				limit = 4 << 30
				kind = "rootfs"
			}
			file, identity, err := snapshotJailerRecoveryAsset(ctx, kind, input.Source, input.SizeBytes, input.SHA256, limit)
			if err != nil {
				return err
			}
			assets[index] = file
			if index == 0 {
				config.Kernel = identity
			} else {
				config.Rootfs = identity
			}
		}
		return nil
	})
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	assets[2], err = sealJailerRecoveryBytes(ctx, request.config)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	identity, err := validateL8RuntimeOwnerSealedRegularFD(int(assets[2].Fd()), maxStrictJailerConfigBytes)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	digest := sha256.Sum256(request.config)
	config.Config = jailerRecoveryAsset{Kind: "config", Device: identity.Device, Inode: identity.Inode, Size: identity.Size, SHA256: hex.EncodeToString(digest[:])}
	selected := &jailerRecoveryRuntime{config: config, files: assets}
	coordinatorRequest, err := selected.request()
	if err != nil || validateJailerRecoverySupervisorConfig(config) != nil || validateStrictJailerCoordinatorConfig(coordinatorRequest) != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	payload, err := json.Marshal(config)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	configFile, err := sealJailerRecoveryBytes(ctx, payload)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	defer configFile.Close()
	executable, err := snapshotStrictJailerExecutable(request.ownerExecutable, request.ownerExecutableSHA256)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	defer executable.Close()
	if ctx.Err() != nil || lease.ConfirmCurrent(ctx) != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	// The five explicit inputs below are combined with the control socket and
	// sealed supervisor config only by the concrete seven-role exec producer.
	return start(ctx, config, executable, configFile, [5]*os.File{request.ownerDirectory, assets[0], assets[1], request.rootKey, assets[2]}, request.namespaces)
}

func duplicateJailerRecoveryFile(file *os.File) (*os.File, error) {
	if file == nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 10)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	return os.NewFile(uintptr(fd), "jailer-owner-transfer"), nil
}
