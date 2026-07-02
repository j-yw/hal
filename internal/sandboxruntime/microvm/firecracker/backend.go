package firecracker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

const (
	targetRuntimeIDPrefix = "fc-"

	targetCapabilityCreation              = "target_creation"
	targetCapabilityDeterministicIdentity = "deterministic_identity"
	targetCapabilityPathRoleMetadata      = "path_role_metadata"
	targetCapabilityProcessBoundary       = "process_boundary"
)

// BackendOptions configures the metadata-only Firecracker backend. BaseStateDir
// is used only to derive target-specific path plans; raw paths are not exposed
// on created targets.
type BackendOptions struct {
	BaseStateDir string
}

// Backend implements the microVM backend boundary for Firecracker target
// creation metadata. Lifecycle behavior remains intentionally deferred to later
// phases.
type Backend struct {
	baseStateDir string
}

// NewBackend constructs an explicitly injected Firecracker backend.
func NewBackend(options BackendOptions) *Backend {
	return &Backend{
		baseStateDir: strings.TrimSpace(options.BaseStateDir),
	}
}

func (b *Backend) Create(_ context.Context, req microvm.BackendCreateRequest) (*sandboxruntime.Target, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, microvm.NewTargetNameRequiredError(microvm.OperationCreate)
	}

	config, err := BackendConfigFromMicroVMConfig(req.Config)
	if err != nil {
		return nil, err
	}

	runtimeID := firecrackerRuntimeID(name)
	baseStateDir := ""
	if b != nil {
		baseStateDir = b.baseStateDir
	}
	paths, err := PlanPaths(PathPlanRequest{
		RuntimeID:    runtimeID,
		BaseStateDir: baseStateDir,
	})
	if err != nil {
		return nil, err
	}
	config.RuntimeID = runtimeID
	config.Paths = paths

	return &sandboxruntime.Target{
		ID:       runtimeID,
		Name:     firecrackerTargetDisplayName(name, runtimeID),
		Provider: BackendID,
		Status:   sandbox.StatusStopped,
		Runtime: sandboxruntime.RuntimeState{
			Driver:    sandboxruntime.DriverMicroVM,
			RuntimeID: runtimeID,
			Metadata: &sandboxruntime.RuntimeMetadata{
				Backend:          BackendID,
				CapabilityLabels: firecrackerTargetCapabilityLabels(),
				PathRoles:        firecrackerTargetPathRoles(config.Paths),
			},
		},
	}, nil
}

func (b *Backend) Controller(_ context.Context, req microvm.ControllerRequest) (microvm.Controller, error) {
	if strings.TrimSpace(req.Target.ID) == "" &&
		strings.TrimSpace(req.Target.Name) == "" &&
		strings.TrimSpace(req.Target.Runtime.RuntimeID) == "" {
		return nil, microvm.NewTargetRequiredError(req.Operation)
	}
	return firecrackerController{}, nil
}

type firecrackerController struct{}

func (firecrackerController) Start(_ context.Context, req microvm.ControllerLifecycleRequest) (*sandboxruntime.Target, error) {
	return nil, unsupportedFirecrackerOperation(req.Operation)
}

func (firecrackerController) Stop(_ context.Context, req microvm.ControllerLifecycleRequest) (*sandboxruntime.Target, error) {
	return nil, unsupportedFirecrackerOperation(req.Operation)
}

func (firecrackerController) Delete(_ context.Context, req microvm.ControllerLifecycleRequest) error {
	return unsupportedFirecrackerOperation(req.Operation)
}

func (firecrackerController) Inspect(_ context.Context, req microvm.ControllerInspectRequest) (*sandboxruntime.Target, error) {
	return nil, unsupportedFirecrackerOperation(req.Operation)
}

func (firecrackerController) Exec(_ context.Context, req microvm.ControllerExecRequest) (*sandboxruntime.ExecResult, error) {
	return nil, unsupportedFirecrackerOperation(req.Operation)
}

func (firecrackerController) CopyIn(_ context.Context, req microvm.ControllerCopyRequest) error {
	return unsupportedFirecrackerOperation(req.Operation)
}

func (firecrackerController) CopyOut(_ context.Context, req microvm.ControllerCopyRequest) error {
	return unsupportedFirecrackerOperation(req.Operation)
}

func unsupportedFirecrackerOperation(operation string) error {
	if strings.TrimSpace(operation) == "" {
		operation = "firecracker_backend"
	}
	return microvm.NewUnavailableCapabilityError(operation, errors.New("firecracker backend operation is not implemented in this phase"))
}

func firecrackerRuntimeID(name string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(name)))
	encoded := hex.EncodeToString(sum[:])
	return targetRuntimeIDPrefix + encoded[:24]
}

func firecrackerTargetDisplayName(name, runtimeID string) string {
	if safe := safeFirecrackerMetadataToken(name); safe != "" {
		return safe
	}
	return runtimeID
}

func safeFirecrackerMetadataToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxPathPlanRuntimeIDBytes || unsafeFirecrackerMetadataValue(value) {
		return ""
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.':
		default:
			return ""
		}
	}
	return value
}

func unsafeFirecrackerMetadataValue(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"://",
		"/",
		"\\",
		"token",
		"secret",
		"password",
		"credential",
		"authorization",
		"bearer",
		"api_key",
		"apikey",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func firecrackerTargetCapabilityLabels() []string {
	return []string{
		targetCapabilityCreation,
		targetCapabilityDeterministicIdentity,
		targetCapabilityPathRoleMetadata,
		targetCapabilityProcessBoundary,
	}
}

func firecrackerTargetPathRoles(paths PathPlan) []string {
	if paths == (PathPlan{}) {
		return []string{}
	}
	return []string{
		string(OperationPathRoleStateDir),
		string(OperationPathRoleAPISocket),
		string(OperationPathRoleConfig),
		string(OperationPathRoleLog),
		string(OperationPathRoleMetrics),
	}
}
