package rolebootstrap

// ContractVersion is the exact D4 native role-bootstrap source-contract
// version. It is not a native binary or a policy-artifact identity.
const ContractVersion = "hal.l8.role-bootstrap.v1"

// ErrorCode is the closed, redaction-safe foundation failure catalog.
type ErrorCode uint8

const (
	ErrorInvalidArgument  ErrorCode = 1
	ErrorDependency       ErrorCode = 2
	ErrorUnsupported      ErrorCode = 3
	ErrorArtifactMismatch ErrorCode = 4
	ErrorTransition       ErrorCode = 5
	ErrorSystem           ErrorCode = 6
	ErrorResult           ErrorCode = 7
)

// ContractError is a stable error with no dynamic system detail.
type ContractError struct {
	code ErrorCode
}

func (err ContractError) Error() string {
	switch err.code {
	case ErrorDependency:
		return "role bootstrap dependency unavailable"
	case ErrorUnsupported:
		return "role bootstrap unsupported platform"
	case ErrorArtifactMismatch:
		return "role bootstrap artifact mismatch"
	case ErrorTransition:
		return "role bootstrap transition rejected"
	case ErrorSystem:
		return "role bootstrap system operation failed"
	case ErrorResult:
		return "role bootstrap result rejected"
	default:
		return "role bootstrap invalid argument"
	}
}

func (err ContractError) Is(target error) bool {
	other, ok := target.(ContractError)
	return ok && err.code != 0 && err.code == other.code
}

func (err ContractError) Code() ErrorCode { return err.code }

var (
	ErrInvalidArgument     = ContractError{code: ErrorInvalidArgument}
	ErrDependency          = ContractError{code: ErrorDependency}
	ErrUnsupportedPlatform = ContractError{code: ErrorUnsupported}
	ErrArtifactMismatch    = ContractError{code: ErrorArtifactMismatch}
	ErrTransition          = ContractError{code: ErrorTransition}
	ErrSystem              = ContractError{code: ErrorSystem}
	ErrResult              = ContractError{code: ErrorResult}
)

// Role is the closed native bootstrap role catalog.
type Role uint8

const (
	RolePID1         Role = 1
	RoleController   Role = 2
	RoleAgent        Role = 3
	RoleMonitor      Role = 4
	RoleWorkloadShim Role = 5
)

// ValidateRole rejects zero and unknown bootstrap roles.
func ValidateRole(role Role) error {
	switch role {
	case RolePID1, RoleController, RoleAgent, RoleMonitor, RoleWorkloadShim:
		return nil
	default:
		return ErrInvalidArgument
	}
}

// GeneratedArtifact binds the D4 consumer to the identities that D7 must
// generate and verify. It contains no rows, rules, source, or executable body.
type GeneratedArtifact struct {
	contractVersion          string
	policySHA256             [32]byte
	nativeSourceSHA256       [32]byte
	nativeCallsiteSHA256     [32]byte
	nativeInstallTableSHA256 [32]byte
}

// NewGeneratedArtifact validates opaque D7 output identities without issuing
// or deriving any policy authority.
func NewGeneratedArtifact(policySHA256, nativeSourceSHA256, nativeCallsiteSHA256, nativeInstallTableSHA256 [32]byte) (GeneratedArtifact, error) {
	if zeroDigest(policySHA256) || zeroDigest(nativeSourceSHA256) || zeroDigest(nativeCallsiteSHA256) || zeroDigest(nativeInstallTableSHA256) {
		return GeneratedArtifact{}, ErrInvalidArgument
	}
	return GeneratedArtifact{
		contractVersion:          ContractVersion,
		policySHA256:             policySHA256,
		nativeSourceSHA256:       nativeSourceSHA256,
		nativeCallsiteSHA256:     nativeCallsiteSHA256,
		nativeInstallTableSHA256: nativeInstallTableSHA256,
	}, nil
}

func (artifact GeneratedArtifact) ContractVersion() string      { return artifact.contractVersion }
func (artifact GeneratedArtifact) PolicySHA256() [32]byte       { return artifact.policySHA256 }
func (artifact GeneratedArtifact) NativeSourceSHA256() [32]byte { return artifact.nativeSourceSHA256 }
func (artifact GeneratedArtifact) NativeCallsiteSHA256() [32]byte {
	return artifact.nativeCallsiteSHA256
}
func (artifact GeneratedArtifact) NativeInstallTableSHA256() [32]byte {
	return artifact.nativeInstallTableSHA256
}

func validGeneratedArtifact(artifact GeneratedArtifact) bool {
	return artifact.contractVersion == ContractVersion &&
		!zeroDigest(artifact.policySHA256) &&
		!zeroDigest(artifact.nativeSourceSHA256) &&
		!zeroDigest(artifact.nativeCallsiteSHA256) &&
		!zeroDigest(artifact.nativeInstallTableSHA256)
}

// InstallPlan is an immutable selection of one generated artifact, role, and
// exact phase-head binary identity.
type InstallPlan struct {
	role         Role
	artifact     GeneratedArtifact
	binarySHA256 [32]byte
}

func NewInstallPlan(role Role, artifact GeneratedArtifact, binarySHA256 [32]byte) (InstallPlan, error) {
	if ValidateRole(role) != nil || !validGeneratedArtifact(artifact) || zeroDigest(binarySHA256) {
		return InstallPlan{}, ErrInvalidArgument
	}
	return InstallPlan{role: role, artifact: artifact, binarySHA256: binarySHA256}, nil
}

func (plan InstallPlan) Role() Role                  { return plan.role }
func (plan InstallPlan) Artifact() GeneratedArtifact { return plan.artifact }
func (plan InstallPlan) BinarySHA256() [32]byte      { return plan.binarySHA256 }

func validInstallPlan(plan InstallPlan) bool {
	return ValidateRole(plan.role) == nil && validGeneratedArtifact(plan.artifact) && !zeroDigest(plan.binarySHA256)
}

// InstalledRole is a safe echo of a successfully consumed plan. It is not a
// process, filter, kernel, or cleanup proof.
type InstalledRole struct {
	role         Role
	artifact     GeneratedArtifact
	binarySHA256 [32]byte
}

// NewInstalledRole lets the injected D4 system boundary echo only the exact
// immutable plan it received.
func NewInstalledRole(plan InstallPlan) (InstalledRole, error) {
	if !validInstallPlan(plan) {
		return InstalledRole{}, ErrInvalidArgument
	}
	return InstalledRole{role: plan.role, artifact: plan.artifact, binarySHA256: plan.binarySHA256}, nil
}

func (installed InstalledRole) Role() Role                  { return installed.role }
func (installed InstalledRole) Artifact() GeneratedArtifact { return installed.artifact }
func (installed InstalledRole) BinarySHA256() [32]byte      { return installed.binarySHA256 }

func validInstalledRole(installed InstalledRole) bool {
	return ValidateRole(installed.role) == nil && validGeneratedArtifact(installed.artifact) && !zeroDigest(installed.binarySHA256)
}

// InstallOperation and CloseOperation are the only injected system-behavior
// callsites in this foundation.
type InstallOperation func(InstallPlan) (InstalledRole, error)
type CloseOperation func() error

// System is an opaque validated pair of injected operations. Private fields
// prevent a partially configured or typed-nil system dependency.
type System struct {
	install InstallOperation
	close   CloseOperation
}

func NewSystem(install InstallOperation, close CloseOperation) (System, error) {
	if install == nil || close == nil {
		return System{}, ErrDependency
	}
	return System{install: install, close: close}, nil
}

func (system System) configured() bool { return system.install != nil && system.close != nil }

// InstallerOptions contains the complete explicit dependency set.
type InstallerOptions struct {
	Artifact GeneratedArtifact
	System   System
}

// Installer consumes at most one plan and owns exactly one System close.
type Installer interface {
	Install(InstallPlan) (InstalledRole, error)
	Close() error
}

func zeroDigest(digest [32]byte) bool { return digest == ([32]byte{}) }
