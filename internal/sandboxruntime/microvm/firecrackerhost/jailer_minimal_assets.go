package firecrackerhost

import (
	"context"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
)

// startMinimal consumes verified source ownership and uses the ordinary Jailer
// coordinator. Kernel/rootfs request fields specify only jail-relative paths;
// callers cannot replace the bundle's measured inputs. All launch, executable,
// namespace and staged-root cleanup ownership remains with that coordinator.
func (coordinator *strictJailerCoordinator) startMinimal(ctx context.Context, request strictJailerCoordinatorRequest, verified localresolver.VerifiedL8MinimalDistribution) (session strictJailerSession, retErr error) {
	if coordinator == nil || !minimalJailerPathOnly(request.kernel) || !minimalJailerPathOnly(request.rootfs) {
		return session, newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "stage")
	}
	lease, err := verified.TakeLaunchLease(ctx)
	if err != nil {
		return session, newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "verify")
	}
	defer func() {
		if err := lease.Close(); err != nil {
			retErr = errors.Join(retErr, newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "stage"))
		}
	}()
	request.kernel.ID, request.kernel.Mode = "kernel", 0o400
	request.rootfs.ID, request.rootfs.Mode = "rootfs", 0o600
	return coordinator.startWithMinimalLease(ctx, request, lease)
}

func minimalJailerPathOnly(input jailerStagingResourceInput) bool {
	return input.JailPath != "" && input.ID == "" && input.Source == nil && input.SizeBytes == 0 && input.SHA256 == "" && input.Mode == 0
}

func stageStrictJailerMinimalAssets(ctx context.Context, lease *localresolver.VerifiedL8MinimalLaunchLease,
	stage func(jailerStagingFilesystem, jailerStagingRequest) (jailerStagingResult, error),
	filesystem jailerStagingFilesystem, request jailerStagingRequest,
) (result jailerStagingResult, retErr error) {
	called := false
	var stageErr error
	borrowErr := lease.WithAssets(ctx, func(kernel, rootfs localresolver.L8MinimalLaunchAsset) error {
		called = true
		request.Kernel.Source, request.Kernel.SizeBytes, request.Kernel.SHA256 = kernel.Source, kernel.SizeBytes, kernel.SHA256
		request.Rootfs.Source, request.Rootfs.SizeBytes, request.Rootfs.SHA256 = rootfs.Source, rootfs.SizeBytes, rootfs.SHA256
		result, stageErr = stage(filesystem, request)
		return stageErr
	})
	if !called {
		if err := filesystem.close(); err != nil {
			return result, newJailerStagingError(errJailerStagingCleanupIncomplete, "root_close")
		}
	}
	if stageErr != nil {
		return result, stageErr
	}
	if borrowErr != nil {
		retErr = newJailerStagingError(errJailerStagingFailed, "source")
		if result.retainsOwnedRoot() {
			retErr = errors.Join(retErr, result.releaseOwnedRoot())
		}
		return result, retErr
	}
	return result, nil
}
