package firecracker

import (
	"strconv"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
)

type firecrackerLaunchDescriptorAssetSet struct {
	Descriptor assets.LaunchDescriptor
	Kernel     assets.LaunchAsset
	Rootfs     assets.LaunchAsset
	Initrd     assets.LaunchAsset
	HasInitrd  bool
}

func firecrackerLaunchDescriptorAssets(descriptor *assets.LaunchDescriptor, operation string) (firecrackerLaunchDescriptorAssetSet, error) {
	if descriptor == nil {
		return firecrackerLaunchDescriptorAssetSet{}, nil
	}
	result := assets.ValidateAndNormalizeLaunchDescriptor(*descriptor)
	if !result.Valid {
		return firecrackerLaunchDescriptorAssetSet{}, newFirecrackerLaunchDescriptorValidationError(operation, result.Errors)
	}
	normalized := *result.Normalized
	launchAssets := firecrackerLaunchDescriptorAssetSet{Descriptor: normalized}
	for i, asset := range normalized.Assets {
		switch asset.Role {
		case assets.AssetRoleKernel:
			if err := validateFirecrackerLaunchDescriptorAsset(operation, i, asset, assets.AssetKindKernelImage); err != nil {
				return firecrackerLaunchDescriptorAssetSet{}, err
			}
			launchAssets.Kernel = asset
		case assets.AssetRoleRootfs:
			if err := validateFirecrackerLaunchDescriptorAsset(operation, i, asset, assets.AssetKindRootfsImage); err != nil {
				return firecrackerLaunchDescriptorAssetSet{}, err
			}
			launchAssets.Rootfs = asset
		case assets.AssetRoleInitrd:
			if launchAssets.HasInitrd {
				return firecrackerLaunchDescriptorAssetSet{}, newFirecrackerLaunchDescriptorError(operation, launchDescriptorAssetField(i, "role"), "Firecracker initrd asset role must be unique")
			}
			if err := validateFirecrackerLaunchDescriptorAsset(operation, i, asset, assets.AssetKindInitrdImage); err != nil {
				return firecrackerLaunchDescriptorAssetSet{}, err
			}
			launchAssets.Initrd = asset
			launchAssets.HasInitrd = true
		default:
			continue
		}
	}
	return launchAssets, nil
}

func validateFirecrackerLaunchDescriptorAsset(operation string, index int, asset assets.LaunchAsset, kind assets.AssetKind) error {
	if asset.Kind != kind {
		return newFirecrackerLaunchDescriptorError(operation, launchDescriptorAssetField(index, "kind"), "asset kind does not match Firecracker launch role")
	}
	if asset.Source.Type != assets.SourceTypeLocalFile {
		return newFirecrackerLaunchDescriptorError(operation, launchDescriptorAssetField(index, "source.type"), "Firecracker launch asset source must be local file")
	}
	if asset.Source.HostPath == nil || strings.TrimSpace(asset.Source.HostPath.Path) == "" {
		return newFirecrackerLaunchDescriptorError(operation, launchDescriptorAssetField(index, "source.hostPath.path"), "Firecracker launch asset host path is required")
	}
	if asset.Source.HostPath.Role != assets.HostPathRoleResolvedLocalAsset {
		return newFirecrackerLaunchDescriptorError(operation, launchDescriptorAssetField(index, "source.hostPath.role"), "Firecracker launch asset host path must be resolved local asset metadata")
	}
	return nil
}

func (launchAssets firecrackerLaunchDescriptorAssetSet) kernelPath() string {
	return launchDescriptorAssetHostPath(launchAssets.Kernel)
}

func (launchAssets firecrackerLaunchDescriptorAssetSet) rootfsPath() string {
	return launchDescriptorAssetHostPath(launchAssets.Rootfs)
}

func (launchAssets firecrackerLaunchDescriptorAssetSet) initrdPath() *string {
	if !launchAssets.HasInitrd {
		return nil
	}
	return optionalPath(launchDescriptorAssetHostPath(launchAssets.Initrd))
}

func launchDescriptorAssetHostPath(asset assets.LaunchAsset) string {
	if asset.Source.HostPath == nil {
		return ""
	}
	return strings.TrimSpace(asset.Source.HostPath.Path)
}

func newFirecrackerLaunchDescriptorValidationError(operation string, validationErrors []assets.ValidationError) error {
	field := "launchDescriptor"
	message := "launch asset descriptor is invalid"
	if len(validationErrors) > 0 {
		validationErr := validationErrors[0]
		if strings.TrimSpace(validationErr.Field) != "" {
			field += "." + launchDescriptorValidationField(validationErr.Field)
		}
		if validationErr.Code != "" {
			message += " (" + string(validationErr.Code) + ")"
		}
		if strings.TrimSpace(validationErr.Message) != "" {
			message += ": " + strings.TrimSpace(validationErr.Message)
		}
	}
	return newFirecrackerLaunchDescriptorError(operation, field, message)
}

func newFirecrackerLaunchDescriptorError(operation string, field string, message string) error {
	field = strings.TrimSpace(field)
	message = strings.TrimSpace(message)
	switch operation {
	case ConfigOperation:
		return newBackendConfigError(field, message)
	case PayloadRenderingOperation:
		return newPayloadRenderingError(field, message)
	case liveBootRenderOperation:
		return newLiveBootRenderConfigError(field, message)
	case OperationPlanningOperation:
		return newOperationPlanError(field, message)
	default:
		err := microvm.NewInvalidConfigError(operation, microvm.ErrInvalidConfig)
		err.Field = field
		err.Message = message
		return err
	}
}

func launchDescriptorAssetField(index int, field string) string {
	return "launchDescriptor.assets." + strconv.Itoa(index) + "." + strings.Trim(strings.TrimSpace(field), ".")
}

func launchDescriptorValidationField(field string) string {
	field = strings.TrimSpace(field)
	if field == "" {
		return ""
	}
	field = strings.NewReplacer("[", ".", "]", "").Replace(field)
	return strings.Trim(field, ".")
}
