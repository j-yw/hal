package firecracker

import (
	"context"
	"errors"
	"reflect"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
)

const l8LiveConfigOperation = "firecracker_l8_live_config"

var (
	errL8LiveConfigProviderPanic = errors.New("L8 live config provider panicked")
	errL8LiveAssetCleanupPanic   = errors.New("L8 live asset cleanup panicked")
)

// L8LiveBootConfigRequest identifies the exact runtime generation for which a
// provider must return one verified L8 live overlay.
type L8LiveBootConfigRequest struct {
	RuntimeGenerationID string `json:"runtimeGenerationId"`
}

// L8LiveBootConfigOverlay contains only the L8-owned fields added to an
// already-derived Firecracker backend config. It cannot replace ordinary
// executable, path, resource, VSOCK, or lifecycle configuration.
type L8LiveBootConfigOverlay struct {
	RuntimeGenerationID string                              `json:"runtimeGenerationId"`
	LaunchDescriptor    *assets.LaunchDescriptor            `json:"-"`
	VerifiedL8Profile   *localresolver.VerifiedL8Profile    `json:"-"`
	VerifiedL8Assets    *localresolver.VerifiedL8AssetLease `json:"-"`
	NetworkMode         microvm.NetworkMode                 `json:"networkMode"`
	NetworkInterfaces   []NetworkInterfaceConfig            `json:"-"`
	StaticNetwork       *StaticNetworkBootConfig            `json:"-"`
	AssetChildFDStart   int                                 `json:"-"`
}

// L8LiveBootConfigProvider returns one runtime-bound overlay. A provider error
// retains ownership of every returned value. A nil error provisionally
// transfers ownership of every non-nil L8 lease to Backend before validation.
type L8LiveBootConfigProvider interface {
	ProvideL8LiveBootConfig(context.Context, L8LiveBootConfigRequest) (L8LiveBootConfigOverlay, error)
}

func prepareL8LiveBootConfig(
	ctx context.Context,
	provider L8LiveBootConfigProvider,
	base BackendConfig,
) (BackendConfig, *localresolver.VerifiedL8AssetLease, error) {
	if l8LiveConfigProviderIsNil(provider) {
		return BackendConfig{}, nil, newL8LiveConfigError("provider", "L8 live config provider is unavailable", nil)
	}
	if base.VerifiedL7Profile != nil || base.VerifiedL7Assets != nil ||
		base.VerifiedL8Profile != nil || base.VerifiedL8Assets != nil {
		return BackendConfig{}, nil, newL8LiveConfigError("overlay", "L7 and L8 live config authority is mutually exclusive", nil)
	}
	runtimeID := strings.TrimSpace(base.RuntimeID)
	if safeFirecrackerMetadataToken(runtimeID) != runtimeID || !base.ProductionVsock {
		return BackendConfig{}, nil, newL8LiveConfigError("runtimeGenerationId", "L8 live runtime identity is invalid", nil)
	}

	overlay, providerErr := callL8LiveBootConfigProvider(
		provider,
		processContext(ctx),
		L8LiveBootConfigRequest{RuntimeGenerationID: runtimeID},
	)
	if providerErr != nil {
		message := "L8 live config provider failed"
		if !reflect.ValueOf(overlay).IsZero() {
			message = "L8 live config provider returned an invalid error result"
		}
		return BackendConfig{}, nil, newL8LiveConfigError("provider", message, providerErr)
	}

	lease := overlay.VerifiedL8Assets
	fail := func(field, message string, cause error) (BackendConfig, *localresolver.VerifiedL8AssetLease, error) {
		primary := newL8LiveConfigError(field, message, cause)
		if lease == nil {
			return BackendConfig{}, nil, primary
		}
		if closeErr := closeBackendOwnedL8Lease(lease); closeErr != nil {
			return BackendConfig{}, nil, errors.Join(primary, closeErr)
		}
		return BackendConfig{}, nil, primary
	}

	if overlay.RuntimeGenerationID != runtimeID {
		return fail("runtimeGenerationId", "L8 live config runtime identity mismatch", nil)
	}
	if overlay.NetworkMode != microvm.NetworkModeL7PolicyProxy ||
		overlay.AssetChildFDStart != l7NamespaceKernelChildFD ||
		overlay.LaunchDescriptor == nil || overlay.VerifiedL8Profile == nil || lease == nil ||
		len(overlay.NetworkInterfaces) != 1 || overlay.StaticNetwork == nil {
		return fail("overlay", "L8 live config overlay is incomplete", nil)
	}

	descriptor := cloneL8LaunchDescriptor(*overlay.LaunchDescriptor)
	profile := *overlay.VerifiedL8Profile
	interfaces := cloneL8NetworkInterfaces(overlay.NetworkInterfaces)
	staticNetwork := *overlay.StaticNetwork
	if err := validateL8LiveOverlaySnapshot(&descriptor, &profile, lease, interfaces, &staticNetwork); err != nil {
		return fail("overlay", "L8 live config overlay validation failed", err)
	}

	config := base
	config.LaunchDescriptor = &descriptor
	config.VerifiedL8Profile = &profile
	config.VerifiedL8Assets = lease
	config.NetworkMode = overlay.NetworkMode
	config.NetworkInterfaces = interfaces
	config.StaticNetwork = &staticNetwork
	config.AssetChildFDStart = overlay.AssetChildFDStart
	return config, lease, nil
}

func callL8LiveBootConfigProvider(
	provider L8LiveBootConfigProvider,
	ctx context.Context,
	request L8LiveBootConfigRequest,
) (overlay L8LiveBootConfigOverlay, err error) {
	defer func() {
		if recover() != nil {
			overlay = L8LiveBootConfigOverlay{}
			err = errL8LiveConfigProviderPanic
		}
	}()
	return provider.ProvideL8LiveBootConfig(ctx, request)
}

func validateL8LiveOverlaySnapshot(
	descriptor *assets.LaunchDescriptor,
	profile *localresolver.VerifiedL8Profile,
	lease *localresolver.VerifiedL8AssetLease,
	interfaces []NetworkInterfaceConfig,
	staticNetwork *StaticNetworkBootConfig,
) error {
	launchAssets, err := firecrackerLaunchDescriptorAssets(descriptor, l8LiveConfigOperation)
	if err != nil {
		return err
	}
	if descriptor == nil ||
		launchAssets.Descriptor.ID != assets.SafeID("l8-production-credentials-image") ||
		!equalSafeLabels(launchAssets.Descriptor.Labels, []assets.SafeLabel{"firecracker", "reproducible", "network-profile", "production-credentials-profile"}) ||
		launchAssets.HasInitrd ||
		launchAssets.Kernel.ID != assets.SafeID("kernel") ||
		launchAssets.Rootfs.ID != assets.SafeID("rootfs") ||
		!localresolver.VerifiedL8ProfileMatches(profile, &launchAssets.Descriptor) ||
		!localresolver.VerifiedL8ProfileMatchesLease(profile, lease) {
		return newL8LiveConfigError("launchDescriptor", "verified L8 production credential image profile is required", nil)
	}
	if err := lease.ConfirmCurrent(&launchAssets.Descriptor); err != nil {
		return newL8LiveConfigError("launchDescriptor", "current verified L8 production credential image assets are required", err)
	}
	*descriptor = cloneL8LaunchDescriptor(launchAssets.Descriptor)
	if len(interfaces) != 1 {
		return newL8LiveConfigError("networkInterfaces", "exactly one L8 network interface is required", nil)
	}
	networkInterface, err := normalizeNetworkInterface(interfaces[0])
	if err != nil {
		return err
	}
	interfaces[0] = NetworkInterfaceConfig{
		InterfaceID:    networkInterface.IfaceID,
		HostDeviceName: networkInterface.HostDevName,
		GuestMAC:       networkInterface.GuestMAC,
	}
	if staticNetwork == nil {
		return newL8LiveConfigError("staticNetwork", "static L8 guest network configuration is required", nil)
	}
	normalizedStaticNetwork, err := normalizeStaticNetwork(*staticNetwork)
	if err != nil {
		return err
	}
	*staticNetwork = normalizedStaticNetwork
	return nil
}

func closeBackendOwnedL8Lease(lease *localresolver.VerifiedL8AssetLease) (retErr error) {
	if lease == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			retErr = newL8LiveConfigError("l8Assets", "L8 live asset lease cleanup failed", errL8LiveAssetCleanupPanic)
		}
	}()
	if err := lease.Close(); err != nil {
		return newL8LiveConfigError("l8Assets", "L8 live asset lease cleanup failed", err)
	}
	return nil
}

func joinL8StartCleanup(primary, cleanupErr error) error {
	if cleanupErr == nil {
		return primary
	}
	if primary == nil {
		return cleanupErr
	}
	return errors.Join(primary, cleanupErr)
}

func newL8LiveConfigError(field, message string, cause error) *microvm.OperationError {
	if cause == nil {
		cause = microvm.ErrInvalidConfig
	}
	err := microvm.NewBackendOperationFailedError(l8LiveConfigOperation, sanitizedL8LiveConfigCause{cause: cause})
	err.Field = strings.TrimSpace(field)
	err.Message = strings.TrimSpace(message)
	return err
}

type sanitizedL8LiveConfigCause struct{ cause error }

func (sanitizedL8LiveConfigCause) Error() string { return "L8 live config failed" }

func (err sanitizedL8LiveConfigCause) Is(target error) bool {
	return target != nil && errors.Is(err.cause, target)
}

func l8LiveConfigProviderIsNil(provider L8LiveBootConfigProvider) bool {
	if provider == nil {
		return true
	}
	value := reflect.ValueOf(provider)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func cloneL8NetworkInterfaces(source []NetworkInterfaceConfig) []NetworkInterfaceConfig {
	if source == nil {
		return nil
	}
	cloned := make([]NetworkInterfaceConfig, len(source))
	copy(cloned, source)
	return cloned
}

func cloneL8LaunchDescriptor(source assets.LaunchDescriptor) assets.LaunchDescriptor {
	cloned := source
	cloned.Labels = cloneL8SafeLabels(source.Labels)
	if source.Assets == nil {
		cloned.Assets = nil
		return cloned
	}
	cloned.Assets = make([]assets.LaunchAsset, len(source.Assets))
	for index := range source.Assets {
		cloned.Assets[index] = cloneL8LaunchAsset(source.Assets[index])
	}
	return cloned
}

func cloneL8LaunchAsset(source assets.LaunchAsset) assets.LaunchAsset {
	cloned := source
	cloned.Labels = cloneL8SafeLabels(source.Labels)
	if source.Source.HostPath != nil {
		hostPath := *source.Source.HostPath
		cloned.Source.HostPath = &hostPath
	}
	if source.InitConfig != nil {
		initConfig := *source.InitConfig
		initConfig.Labels = cloneL8SafeLabels(source.InitConfig.Labels)
		cloned.InitConfig = &initConfig
	}
	if source.AgentConfig != nil {
		agentConfig := *source.AgentConfig
		agentConfig.Features = cloneL8SafeLabels(source.AgentConfig.Features)
		cloned.AgentConfig = &agentConfig
	}
	if source.Resources == nil {
		cloned.Resources = nil
	} else {
		cloned.Resources = make([]assets.ResourceMetadata, len(source.Resources))
		for index := range source.Resources {
			cloned.Resources[index] = source.Resources[index]
			cloned.Resources[index].Labels = cloneL8SafeLabels(source.Resources[index].Labels)
		}
	}
	return cloned
}

func cloneL8SafeLabels(source []assets.SafeLabel) []assets.SafeLabel {
	if source == nil {
		return nil
	}
	cloned := make([]assets.SafeLabel, len(source))
	copy(cloned, source)
	return cloned
}
