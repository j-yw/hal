package credentialhelper

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

var (
	ErrExtensionSerialization = errors.New("credential helper extension serialization is denied")
)

// ExecBindingCapability is opaque authority minted only by the helper host.
// Its private method prevents external implementations and literal values.
type ExecBindingCapability interface {
	credentialHelperExecBindingCapability()
}

type execBindingCapability struct {
	liveValue
	digest [32]byte
}

func (execBindingCapability) credentialHelperExecBindingCapability() {}

func newExecBindingCapability(
	bootNonce, identityDigest [32]byte,
	revision uint64,
	generations CoreGenerations,
	expiresUnixNano int64,
	manifestSHA256, transactionSHA256 [32]byte,
	bindingIndex uint16,
	bindingID credentialprotocol.SafeID,
	mode credentialprotocol.DeliveryMode,
) (ExecBindingCapability, error) {
	if bootNonce == ([32]byte{}) || identityDigest == ([32]byte{}) || revision == 0 ||
		!validCompleteCoreGenerations(generations) || expiresUnixNano <= 0 ||
		manifestSHA256 == ([32]byte{}) || transactionSHA256 == ([32]byte{}) ||
		bindingIndex >= credentialprotocol.MaxHelperBindings || !validSafeID(bindingID) ||
		credentialprotocol.ValidateDeliveryMode(mode) != nil {
		return nil, ErrContractInvalidArgument
	}
	hasher := sha256.New()
	writeExtensionOpaque16(hasher, "hal/l8/guest-helper/extension-exec-binding/v1")
	_, _ = hasher.Write(bootNonce[:])
	_, _ = hasher.Write(identityDigest[:])
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], revision)
	_, _ = hasher.Write(scalar[:])
	for _, generation := range [...]credentialprotocol.SafeID{
		generations.boot, generations.helper, generations.job,
		generations.monitor, generations.mount, generations.cgroup,
	} {
		writeExtensionOpaque16(hasher, string(generation))
	}
	binary.BigEndian.PutUint64(scalar[:], uint64(expiresUnixNano))
	_, _ = hasher.Write(scalar[:])
	_, _ = hasher.Write(manifestSHA256[:])
	_, _ = hasher.Write(transactionSHA256[:])
	var index [2]byte
	binary.BigEndian.PutUint16(index[:], bindingIndex)
	_, _ = hasher.Write(index[:])
	writeExtensionOpaque16(hasher, string(bindingID))
	_, _ = hasher.Write([]byte{byte(mode)})
	var digest [32]byte
	copy(digest[:], hasher.Sum(nil))
	return execBindingCapability{digest: digest}, nil
}

func writeExtensionOpaque16(hasher hash.Hash, value string) {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write([]byte(value))
}

func validExecBindingCapability(value ExecBindingCapability) bool {
	capability, ok := value.(execBindingCapability)
	return ok && capability.digest != ([32]byte{})
}

func validateExecBindingEcho(value, expected ExecBindingCapability) error {
	actualCapability, actualOK := value.(execBindingCapability)
	expectedCapability, expectedOK := expected.(execBindingCapability)
	if !actualOK || !expectedOK || actualCapability.digest == ([32]byte{}) || expectedCapability.digest == ([32]byte{}) ||
		subtle.ConstantTimeCompare(actualCapability.digest[:], expectedCapability.digest[:]) != 1 {
		return ErrContractCapability
	}
	return nil
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
		return ErrContractInvalidArgument
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
	liveValue
	resourcesAbsent bool
	category        ExtensionCleanupCategory
}

func NewExtensionCleanupResult(resourcesAbsent bool, category ExtensionCleanupCategory) (ExtensionCleanupResult, error) {
	if err := ValidateExtensionCleanupCategory(category); err != nil {
		return ExtensionCleanupResult{}, err
	}
	if resourcesAbsent != (category == ExtensionCleanupComplete) {
		return ExtensionCleanupResult{}, ErrContractResultMatrix
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
	liveValue
	byteCount uint64
	eof       bool
	truncated bool
}

func NewSSHIOResult(byteCount uint64, eof, truncated bool) (SSHIOResult, error) {
	if byteCount > credentialprotocol.SSHAgentMaxFrameBytes {
		return SSHIOResult{}, ErrContractInvalidArgument
	}
	return SSHIOResult{byteCount: byteCount, eof: eof, truncated: truncated}, nil
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
		return ErrContractInvalidArgument
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
