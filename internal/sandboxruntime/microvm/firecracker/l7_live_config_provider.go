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

const l7LiveConfigOperation = "firecracker_l7_live_config"

// L7LiveBootConfigRequest identifies the exact runtime generation for which a
// provider must return one live-only verified overlay.
type L7LiveBootConfigRequest struct {
	RuntimeGenerationID string `json:"runtimeGenerationId"`
}

// L7LiveBootConfigOverlay contains only fields that the explicit L7
// composition may add to an already-derived Firecracker backend config.
// Executable, path, CPU, memory, runtime identity, and lifecycle fields remain
// owned by the ordinary Backend controller.
type L7LiveBootConfigOverlay struct {
	RuntimeGenerationID string                              `json:"runtimeGenerationId"`
	LaunchDescriptor    *assets.LaunchDescriptor            `json:"-"`
	VerifiedL7Profile   *localresolver.VerifiedL7Profile    `json:"-"`
	VerifiedL7Assets    *localresolver.VerifiedL7AssetLease `json:"-"`
	NetworkMode         microvm.NetworkMode                 `json:"networkMode"`
	NetworkInterfaces   []NetworkInterfaceConfig            `json:"-"`
	StaticNetwork       *StaticNetworkBootConfig            `json:"-"`
	AssetChildFDStart   int                                 `json:"-"`
}

// L7LiveBootConfigProvider returns one runtime-bound overlay. On a non-nil
// provider error, the provider retains ownership of every value it returned.
// On success, ownership of a non-nil asset lease transfers to Backend.
type L7LiveBootConfigProvider interface {
	ProvideL7LiveBootConfig(context.Context, L7LiveBootConfigRequest) (L7LiveBootConfigOverlay, error)
}

func prepareL7LiveBootConfig(
	ctx context.Context,
	provider L7LiveBootConfigProvider,
	base BackendConfig,
) (BackendConfig, *localresolver.VerifiedL7AssetLease, error) {
	if liveConfigProviderIsNil(provider) {
		return BackendConfig{}, nil, newL7LiveConfigError("provider", "L7 live config provider is unavailable", nil)
	}
	runtimeID := strings.TrimSpace(base.RuntimeID)
	if safeFirecrackerMetadataToken(runtimeID) == "" || !base.ProductionVsock {
		return BackendConfig{}, nil, newL7LiveConfigError("runtimeGenerationId", "L7 live runtime identity is invalid", nil)
	}
	overlay, err := provider.ProvideL7LiveBootConfig(processContext(ctx), L7LiveBootConfigRequest{RuntimeGenerationID: runtimeID})
	if err != nil {
		return BackendConfig{}, nil, newL7LiveConfigError("provider", "L7 live config provider failed", err)
	}
	lease := overlay.VerifiedL7Assets
	fail := func(field, message string, cause error) (BackendConfig, *localresolver.VerifiedL7AssetLease, error) {
		primary := newL7LiveConfigError(field, message, cause)
		if lease == nil {
			return BackendConfig{}, nil, primary
		}
		if closeErr := closeBackendOwnedL7Lease(lease); closeErr != nil {
			return BackendConfig{}, nil, errors.Join(primary, closeErr)
		}
		return BackendConfig{}, nil, primary
	}
	if strings.TrimSpace(overlay.RuntimeGenerationID) != runtimeID {
		return fail("runtimeGenerationId", "L7 live config runtime identity mismatch", nil)
	}
	if overlay.NetworkMode != microvm.NetworkModeL7PolicyProxy || overlay.AssetChildFDStart != l7NamespaceKernelChildFD ||
		overlay.LaunchDescriptor == nil || overlay.VerifiedL7Profile == nil || lease == nil ||
		len(overlay.NetworkInterfaces) != 1 || overlay.StaticNetwork == nil {
		return fail("overlay", "L7 live config overlay is incomplete", nil)
	}

	config := base
	config.LaunchDescriptor = overlay.LaunchDescriptor
	config.VerifiedL7Profile = overlay.VerifiedL7Profile
	config.VerifiedL7Assets = lease
	config.NetworkMode = overlay.NetworkMode
	config.NetworkInterfaces = append([]NetworkInterfaceConfig(nil), overlay.NetworkInterfaces...)
	static := *overlay.StaticNetwork
	config.StaticNetwork = &static
	config.AssetChildFDStart = overlay.AssetChildFDStart
	if _, _, err := renderNetworkInterfaces(config); err != nil {
		return fail("overlay", "L7 live config overlay validation failed", err)
	}
	return config, lease, nil
}

func closeBackendOwnedL7Lease(lease *localresolver.VerifiedL7AssetLease) error {
	if lease == nil {
		return nil
	}
	if err := lease.Close(); err != nil {
		return newL7LiveConfigError("l7Assets", "L7 live asset lease cleanup failed", err)
	}
	return nil
}

func newL7LiveConfigError(field, message string, cause error) *microvm.OperationError {
	if cause == nil {
		cause = microvm.ErrInvalidConfig
	}
	err := microvm.NewBackendOperationFailedError(l7LiveConfigOperation, sanitizedL7LiveConfigCause{cause: cause})
	err.Field = strings.TrimSpace(field)
	err.Message = strings.TrimSpace(message)
	return err
}

type sanitizedL7LiveConfigCause struct{ cause error }

func (sanitizedL7LiveConfigCause) Error() string { return "L7 live config failed" }

func (err sanitizedL7LiveConfigCause) Is(target error) bool {
	return target != nil && errors.Is(err.cause, target)
}

func liveConfigProviderIsNil(provider L7LiveBootConfigProvider) bool {
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
