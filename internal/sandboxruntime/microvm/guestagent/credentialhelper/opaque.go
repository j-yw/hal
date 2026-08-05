package credentialhelper

import "errors"

var (
	ErrUnknownExtensionCleanupCategory = errors.New("credential helper extension cleanup category is unknown")
	ErrInvalidExtensionCleanupResult   = errors.New("credential helper extension cleanup result is invalid")
	ErrUnknownSSHShutdownDirection     = errors.New("credential helper SSH shutdown direction is unknown")
	ErrExtensionSerialization          = errors.New("credential helper extension serialization is denied")
)

// ExecBindingCapability is opaque authority minted only by the helper host.
// Its private method prevents external implementations and literal values.
type ExecBindingCapability interface {
	credentialHelperExecBindingCapability()
}

type execBindingCapability struct{}

func (execBindingCapability) credentialHelperExecBindingCapability() {}

func newExecBindingCapability() ExecBindingCapability {
	return execBindingCapability{}
}

// ExtensionCleanupCategory is the closed guest/helper cleanup result catalog.
type ExtensionCleanupCategory uint8

const (
	ExtensionCleanupComplete       ExtensionCleanupCategory = 1
	ExtensionCleanupRetryRequired  ExtensionCleanupCategory = 2
	ExtensionCleanupStopVMRequired ExtensionCleanupCategory = 3
)

func ValidateExtensionCleanupCategory(value ExtensionCleanupCategory) error {
	switch value {
	case ExtensionCleanupComplete, ExtensionCleanupRetryRequired, ExtensionCleanupStopVMRequired:
		return nil
	default:
		return ErrUnknownExtensionCleanupCategory
	}
}

func (value ExtensionCleanupCategory) String() string {
	switch value {
	case ExtensionCleanupComplete:
		return "cleanup_complete"
	case ExtensionCleanupRetryRequired:
		return "retry_required"
	case ExtensionCleanupStopVMRequired:
		return "stop_vm_required"
	default:
		return "unknown"
	}
}

// ExtensionCleanupResult proves absence only for extension-owned resources.
type ExtensionCleanupResult struct {
	resourcesAbsent bool
	category        ExtensionCleanupCategory
}

func NewExtensionCleanupResult(resourcesAbsent bool, category ExtensionCleanupCategory) (ExtensionCleanupResult, error) {
	if err := ValidateExtensionCleanupCategory(category); err != nil {
		return ExtensionCleanupResult{}, err
	}
	if resourcesAbsent != (category == ExtensionCleanupComplete) {
		return ExtensionCleanupResult{}, ErrInvalidExtensionCleanupResult
	}
	return ExtensionCleanupResult{resourcesAbsent: resourcesAbsent, category: category}, nil
}

func (result ExtensionCleanupResult) ResourcesAbsent() bool {
	return result.resourcesAbsent
}

func (result ExtensionCleanupResult) Category() ExtensionCleanupCategory {
	return result.category
}

// SSHIOResult is bounded non-authority I/O metadata.
type SSHIOResult struct {
	byteCount uint64
	eof       bool
	truncated bool
}

func NewSSHIOResult(byteCount uint64, eof, truncated bool) SSHIOResult {
	return SSHIOResult{byteCount: byteCount, eof: eof, truncated: truncated}
}

func (result SSHIOResult) ByteCount() uint64 {
	return result.byteCount
}

func (result SSHIOResult) EOF() bool {
	return result.eof
}

func (result SSHIOResult) Truncated() bool {
	return result.truncated
}

// SSHShutdownDirection is the closed half-close operation catalog.
type SSHShutdownDirection uint8

const (
	SSHShutdownRead  SSHShutdownDirection = 1
	SSHShutdownWrite SSHShutdownDirection = 2
	SSHShutdownBoth  SSHShutdownDirection = 3
)

func ValidateSSHShutdownDirection(value SSHShutdownDirection) error {
	switch value {
	case SSHShutdownRead, SSHShutdownWrite, SSHShutdownBoth:
		return nil
	default:
		return ErrUnknownSSHShutdownDirection
	}
}

func (value SSHShutdownDirection) String() string {
	switch value {
	case SSHShutdownRead:
		return "read"
	case SSHShutdownWrite:
		return "write"
	case SSHShutdownBoth:
		return "both"
	default:
		return "unknown"
	}
}
