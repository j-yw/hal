package credentialhelper

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"runtime"
	"sync"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type requestCorrelation struct {
	requestID      [16]byte
	identityDigest [32]byte
	revision       uint64
}

// CoreGenerations is the immutable safe generation projection.
type CoreGenerations struct {
	boot    credentialprotocol.SafeID
	helper  credentialprotocol.SafeID
	job     credentialprotocol.SafeID
	monitor credentialprotocol.SafeID
	mount   credentialprotocol.SafeID
	cgroup  credentialprotocol.SafeID
}

func (CoreGenerations) String() string   { return "credentialhelper.live[redacted]" }
func (CoreGenerations) GoString() string { return "credentialhelper.live[redacted]" }
func (CoreGenerations) Format(state fmt.State, _ rune) {
	_, _ = fmt.Fprint(state, "credentialhelper.live[redacted]")
}
func (CoreGenerations) MarshalJSON() ([]byte, error)   { return nil, ErrContractInvalidArgument }
func (CoreGenerations) MarshalText() ([]byte, error)   { return nil, ErrContractInvalidArgument }
func (CoreGenerations) MarshalBinary() ([]byte, error) { return nil, ErrContractInvalidArgument }
func (*CoreGenerations) UnmarshalJSON([]byte) error    { return ErrContractInvalidArgument }
func (*CoreGenerations) UnmarshalText([]byte) error    { return ErrContractInvalidArgument }
func (*CoreGenerations) UnmarshalBinary([]byte) error  { return ErrContractInvalidArgument }

type RelativePathCapability struct {
	liveValue
	length uint16
	bytes  [credentialprotocol.MaxRelativePathBytes]byte
}

type ManifestCapability struct {
	liveValue
	count   uint16
	records [credentialprotocol.MaxHelperBindings]manifestRecord
}

type manifestRecord struct {
	bindingID         credentialprotocol.SafeID
	mode              credentialprotocol.DeliveryMode
	target            RelativePathCapability
	declaredFileBytes uint32
	fileSHA256        [32]byte
}

type ExecPlanCapability struct {
	liveValue
	state *execPlanCapabilityState
}

type execPlanCapabilityState struct {
	mu            sync.Mutex
	encodedLength uint32
	sha256        [32]byte
	canonical     [credentialprotocol.MaxHelperExecPlanBytes]byte
	destroyed     bool
}

type CorePreparationCapability struct {
	liveValue
	digest [32]byte
}

type CorePreparedCapability struct {
	liveValue
	digest [32]byte
}

type CoreExecutionCapability struct {
	liveValue
	digest [32]byte
}

type CoreCleanupCapability struct {
	liveValue
	digest [32]byte
}

func NewCoreGenerations(boot, helper, job, monitor, mount, cgroup credentialprotocol.SafeID) (CoreGenerations, error) {
	values := [6]credentialprotocol.SafeID{boot, helper, job, monitor, mount, cgroup}
	for _, value := range values {
		if value != "" && credentialprotocol.ValidateSafeID(value) != nil {
			return CoreGenerations{}, ErrContractInvalidArgument
		}
	}
	return CoreGenerations{boot: boot, helper: helper, job: job, monitor: monitor, mount: mount, cgroup: cgroup}, nil
}

func (value CoreGenerations) Boot() credentialprotocol.SafeID    { return value.boot }
func (value CoreGenerations) Helper() credentialprotocol.SafeID  { return value.helper }
func (value CoreGenerations) Job() credentialprotocol.SafeID     { return value.job }
func (value CoreGenerations) Monitor() credentialprotocol.SafeID { return value.monitor }
func (value CoreGenerations) Mount() credentialprotocol.SafeID   { return value.mount }
func (value CoreGenerations) Cgroup() credentialprotocol.SafeID  { return value.cgroup }

func NewRelativePathCapability(path string) (RelativePathCapability, error) {
	if path == "" || credentialprotocol.ValidateOptionalRelativePath(path) != nil {
		return RelativePathCapability{}, ErrContractInvalidArgument
	}
	var capability RelativePathCapability
	capability.length = uint16(len(path))
	copy(capability.bytes[:], path)
	return capability, nil
}

func (capability RelativePathCapability) Len() uint16 { return capability.length }

func (capability RelativePathCapability) CopyTo(destination []byte) (int, error) {
	if len(destination) != int(capability.length) || capability.length == 0 {
		wipeBytes(destination[:cap(destination)])
		return 0, ErrContractInvalidArgument
	}
	copy(destination, capability.bytes[:capability.length])
	return int(capability.length), nil
}

func NewManifestCapability(bindings []credentialprotocol.HelperBindingManifestRecord) (ManifestCapability, error) {
	digest, err := credentialprotocol.ComputeHelperManifestSHA256(bindings)
	if err != nil || digest == ([32]byte{}) {
		return ManifestCapability{}, ErrContractInvalidArgument
	}
	var capability ManifestCapability
	capability.count = uint16(len(bindings))
	for index, binding := range bindings {
		bindingID := credentialprotocol.SafeID(binding.BindingID)
		if credentialprotocol.ValidateSafeID(bindingID) != nil {
			return ManifestCapability{}, ErrContractInvalidArgument
		}
		var target RelativePathCapability
		if binding.Mode == credentialprotocol.DeliveryModeFileTmpfs {
			target, err = NewRelativePathCapability(binding.TargetPath)
			if err != nil {
				return ManifestCapability{}, ErrContractInvalidArgument
			}
		}
		capability.records[index] = manifestRecord{
			bindingID: bindingID, mode: binding.Mode, target: target,
			declaredFileBytes: binding.DeclaredFileBytes, fileSHA256: binding.FileSHA256,
		}
	}
	return capability, nil
}

func (capability ManifestCapability) Count() uint16 { return capability.count }

func (capability ManifestCapability) Binding(index uint16) (credentialprotocol.SafeID, credentialprotocol.DeliveryMode, RelativePathCapability, uint32, [32]byte, bool) {
	if index >= capability.count {
		return "", 0, RelativePathCapability{}, 0, [32]byte{}, false
	}
	record := capability.records[index]
	return record.bindingID, record.mode, record.target, record.declaredFileBytes, record.fileSHA256, true
}

func (capability ManifestCapability) SHA256() [32]byte {
	bindings := make([]credentialprotocol.HelperBindingManifestRecord, capability.count)
	for index := uint16(0); index < capability.count; index++ {
		record := capability.records[index]
		var target string
		if record.target.length != 0 {
			target = string(record.target.bytes[:record.target.length])
		}
		bindings[index] = credentialprotocol.HelperBindingManifestRecord{
			BindingID: string(record.bindingID), Mode: record.mode, TargetPath: target,
			DeclaredFileBytes: record.declaredFileBytes, FileSHA256: record.fileSHA256,
		}
	}
	digest, err := credentialprotocol.ComputeHelperManifestSHA256(bindings)
	if err != nil {
		return [32]byte{}
	}
	return digest
}

func NewExecPlanCapability(plan credentialprotocol.HelperExecPlan) (ExecPlanCapability, error) {
	canonical, err := credentialprotocol.EncodeHelperExecPlan(plan)
	if err != nil || len(canonical) == 0 || len(canonical) > credentialprotocol.MaxHelperExecPlanBytes {
		return ExecPlanCapability{}, ErrContractInvalidArgument
	}
	defer wipeBytes(canonical[:cap(canonical)])
	state := &execPlanCapabilityState{encodedLength: uint32(len(canonical)), sha256: sha256.Sum256(canonical)}
	copy(state.canonical[:], canonical)
	return ExecPlanCapability{state: state}, nil
}

func (capability ExecPlanCapability) EncodedLength() uint32 {
	if capability.state == nil {
		return 0
	}
	capability.state.mu.Lock()
	defer capability.state.mu.Unlock()
	if capability.state.destroyed {
		return 0
	}
	return capability.state.encodedLength
}

func (capability ExecPlanCapability) SHA256() [32]byte {
	if capability.state == nil {
		return [32]byte{}
	}
	capability.state.mu.Lock()
	defer capability.state.mu.Unlock()
	if capability.state.destroyed {
		return [32]byte{}
	}
	return capability.state.sha256
}

func (capability ExecPlanCapability) CopyCanonicalTo(sink credentialmemory.CredentialSink) error {
	if capability.state == nil {
		return ErrContractDestroyed
	}
	capability.state.mu.Lock()
	defer capability.state.mu.Unlock()
	if capability.state.destroyed {
		return ErrContractDestroyed
	}
	if isNilCoreDependency(sink) {
		return ErrContractTypedNil
	}
	length := int(capability.state.encodedLength)
	if sink.MaxCredentialBytes() < length {
		return ErrContractInvalidArgument
	}
	if err := sink.WriteCredential(capability.state.canonical[:length]); err != nil {
		return ErrContractOwnership
	}
	return nil
}

func (capability ExecPlanCapability) destroy() {
	if capability.state == nil {
		return
	}
	capability.state.mu.Lock()
	defer capability.state.mu.Unlock()
	wipeBytes(capability.state.canonical[:])
	capability.state.encodedLength = 0
	capability.state.sha256 = [32]byte{}
	capability.state.destroyed = true
}

func wipeBytes(value []byte) {
	clear(value)
	runtime.KeepAlive(value)
}

func isNilCoreDependency(value credentialmemory.CredentialSink) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func validCoreCapabilityDigest(digest [32]byte) bool { return digest != [32]byte{} }

func validPartialCoreGenerations(value CoreGenerations) bool {
	return validSafeID(value.boot) && validSafeID(value.helper) && validSafeID(value.job) &&
		value.monitor == "" && value.mount == "" && value.cgroup == ""
}

func validCompleteCoreGenerations(value CoreGenerations) bool {
	return validSafeID(value.boot) && validSafeID(value.helper) && validSafeID(value.job) &&
		validSafeID(value.monitor) && validSafeID(value.mount) && validSafeID(value.cgroup)
}

func validSafeID(value credentialprotocol.SafeID) bool {
	return credentialprotocol.ValidateSafeID(value) == nil
}

func validRequestCorrelation(value requestCorrelation) bool {
	return value.requestID != [16]byte{} && value.identityDigest != [32]byte{} && value.revision != 0
}
