package credentialhelper

import (
	"context"
	"time"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

const serviceCleanupLimit = 30 * time.Second

// ServiceOptions is the exact dependency set for the later D4 Service FSM.
type ServiceOptions struct {
	Core       Core
	Transport  Transport
	Policy     Policy
	Extensions *ExtensionRegistry
	Host       ExtensionHost
	Runtime    ServiceRuntime
}

type ServiceDisposition uint8

const (
	ServiceClosed         ServiceDisposition = 1
	ServiceStopVMRequired ServiceDisposition = 2
)

type ServiceResult struct {
	liveValue
	disposition ServiceDisposition
	closeReason credentialprotocol.CloseReason
}

func (result ServiceResult) Disposition() ServiceDisposition { return result.disposition }
func (result ServiceResult) CloseReason() credentialprotocol.CloseReason {
	return result.closeReason
}

func newServiceResult(disposition ServiceDisposition, closeReason credentialprotocol.CloseReason) (ServiceResult, error) {
	if ValidateServiceDisposition(disposition) != nil || credentialprotocol.ValidateCloseReason(closeReason) != nil {
		return ServiceResult{}, ErrContractInvalidArgument
	}
	clean := disposition == ServiceClosed && (closeReason == credentialprotocol.CloseReasonNormal || closeReason == credentialprotocol.CloseReasonShutdown)
	stop := disposition == ServiceStopVMRequired && (closeReason == credentialprotocol.CloseReasonProtocolError || closeReason == credentialprotocol.CloseReasonIdentityDrift || closeReason == credentialprotocol.CloseReasonExpired || closeReason == credentialprotocol.CloseReasonHelperLoss)
	if !clean && !stop {
		return ServiceResult{}, ErrContractResultMatrix
	}
	return ServiceResult{disposition: disposition, closeReason: closeReason}, nil
}

type ServiceRuntime interface {
	Bootstrap(context.Context) (ServiceBootstrap, error)
	BindAgent(context.Context, ServiceAgentBindingRequest, ReceivedCapability) error
	ObserveJob(context.Context, ServiceJobObservationRequest) (ServiceJobObservation, error)
	Loss() <-chan ServiceLoss
	BeginCleanup() (ServiceCleanupBudget, error)
	Close(context.Context) error
}

type ServiceCleanupBudget interface {
	Context() context.Context
	Limit() time.Duration
	DeadlineExceeded() bool
	Close() error
}

type ServiceBootstrap struct {
	liveValue
	bootNonce        [32]byte
	bootGeneration   credentialprotocol.SafeID
	helperGeneration credentialprotocol.SafeID
}

func NewServiceBootstrap(bootNonce [32]byte, bootGeneration, helperGeneration credentialprotocol.SafeID) (ServiceBootstrap, error) {
	if bootNonce == ([32]byte{}) || !validSafeID(bootGeneration) || !validSafeID(helperGeneration) {
		return ServiceBootstrap{}, ErrContractInvalidArgument
	}
	return ServiceBootstrap{bootNonce: bootNonce, bootGeneration: bootGeneration, helperGeneration: helperGeneration}, nil
}

func (bootstrap ServiceBootstrap) BootNonce() [32]byte { return bootstrap.bootNonce }
func (bootstrap ServiceBootstrap) BootGeneration() credentialprotocol.SafeID {
	return bootstrap.bootGeneration
}
func (bootstrap ServiceBootstrap) HelperGeneration() credentialprotocol.SafeID {
	return bootstrap.helperGeneration
}

type ServiceAgentBindingRequest struct {
	liveValue
	agentIdentitySHA256     [32]byte
	bootstrapSHA256         [32]byte
	processDescriptorSHA256 [32]byte
	bootGeneration          credentialprotocol.SafeID
	helperGeneration        credentialprotocol.SafeID
}

//nolint:unused // D4 Service is the sole planned caller of this private issuer.
func newServiceAgentBindingRequest(agentIdentitySHA256, bootstrapSHA256, processDescriptorSHA256 [32]byte, bootGeneration, helperGeneration credentialprotocol.SafeID) (ServiceAgentBindingRequest, error) {
	if agentIdentitySHA256 == ([32]byte{}) || bootstrapSHA256 == ([32]byte{}) || processDescriptorSHA256 == ([32]byte{}) || !validSafeID(bootGeneration) || !validSafeID(helperGeneration) {
		return ServiceAgentBindingRequest{}, ErrContractInvalidArgument
	}
	return ServiceAgentBindingRequest{agentIdentitySHA256: agentIdentitySHA256, bootstrapSHA256: bootstrapSHA256, processDescriptorSHA256: processDescriptorSHA256, bootGeneration: bootGeneration, helperGeneration: helperGeneration}, nil
}

func (request ServiceAgentBindingRequest) AgentIdentitySHA256() [32]byte {
	return request.agentIdentitySHA256
}
func (request ServiceAgentBindingRequest) BootstrapSHA256() [32]byte {
	return request.bootstrapSHA256
}
func (request ServiceAgentBindingRequest) ProcessDescriptorSHA256() [32]byte {
	return request.processDescriptorSHA256
}
func (request ServiceAgentBindingRequest) BootGeneration() credentialprotocol.SafeID {
	return request.bootGeneration
}
func (request ServiceAgentBindingRequest) HelperGeneration() credentialprotocol.SafeID {
	return request.helperGeneration
}

type ServiceOperation uint8

const (
	ServiceOperationPrepare ServiceOperation = 1
	ServiceOperationExec    ServiceOperation = 2
	ServiceOperationRenew   ServiceOperation = 3
	ServiceOperationRevoke  ServiceOperation = 4
	ServiceOperationInspect ServiceOperation = 5
)

type ServiceJobObservationRequest struct {
	liveValue
	operation        ServiceOperation
	requestID        [16]byte
	identityDigest   [32]byte
	revision         uint64
	bootGeneration   credentialprotocol.SafeID
	helperGeneration credentialprotocol.SafeID
}

//nolint:unused // D4 Service is the sole planned caller of this private issuer.
func newServiceJobObservationRequest(operation ServiceOperation, requestID [16]byte, identityDigest [32]byte, revision uint64, bootGeneration, helperGeneration credentialprotocol.SafeID) (ServiceJobObservationRequest, error) {
	if ValidateServiceOperation(operation) != nil || requestID == ([16]byte{}) || identityDigest == ([32]byte{}) || revision == 0 || !validSafeID(bootGeneration) || !validSafeID(helperGeneration) {
		return ServiceJobObservationRequest{}, ErrContractInvalidArgument
	}
	return ServiceJobObservationRequest{operation: operation, requestID: requestID, identityDigest: identityDigest, revision: revision, bootGeneration: bootGeneration, helperGeneration: helperGeneration}, nil
}

func (request ServiceJobObservationRequest) Operation() ServiceOperation { return request.operation }
func (request ServiceJobObservationRequest) RequestID() [16]byte         { return request.requestID }
func (request ServiceJobObservationRequest) IdentityDigest() [32]byte    { return request.identityDigest }
func (request ServiceJobObservationRequest) Revision() uint64            { return request.revision }
func (request ServiceJobObservationRequest) BootGeneration() credentialprotocol.SafeID {
	return request.bootGeneration
}
func (request ServiceJobObservationRequest) HelperGeneration() credentialprotocol.SafeID {
	return request.helperGeneration
}

type ServiceJobObservation struct {
	liveValue
	generations        CoreGenerations
	observedUnixNano   int64
	hardExpiryUnixNano int64
}

func NewServiceJobObservation(generations CoreGenerations, observedUnixNano, hardExpiryUnixNano int64) (ServiceJobObservation, error) {
	if !validCompleteCoreGenerations(generations) || observedUnixNano <= 0 || hardExpiryUnixNano < observedUnixNano {
		return ServiceJobObservation{}, ErrContractInvalidArgument
	}
	return ServiceJobObservation{generations: generations, observedUnixNano: observedUnixNano, hardExpiryUnixNano: hardExpiryUnixNano}, nil
}

func (observation ServiceJobObservation) Generations() CoreGenerations {
	return observation.generations
}
func (observation ServiceJobObservation) ObservedUnixNano() int64 {
	return observation.observedUnixNano
}
func (observation ServiceJobObservation) HardExpiryUnixNano() int64 {
	return observation.hardExpiryUnixNano
}

type ServiceLossCategory uint8

const (
	ServiceLossAgent   ServiceLossCategory = 1
	ServiceLossJob     ServiceLossCategory = 2
	ServiceLossMonitor ServiceLossCategory = 3
	ServiceLossMount   ServiceLossCategory = 4
	ServiceLossCgroup  ServiceLossCategory = 5
)

type ServiceLoss struct {
	liveValue
	category ServiceLossCategory
}

func NewServiceLoss(category ServiceLossCategory) (ServiceLoss, error) {
	if ValidateServiceLossCategory(category) != nil {
		return ServiceLoss{}, ErrContractInvalidArgument
	}
	return ServiceLoss{category: category}, nil
}

func (loss ServiceLoss) Category() ServiceLossCategory { return loss.category }

func ValidateServiceDisposition(value ServiceDisposition) error {
	if value != ServiceClosed && value != ServiceStopVMRequired {
		return ErrContractInvalidArgument
	}
	return nil
}

func (value ServiceDisposition) String() string {
	switch value {
	case ServiceClosed:
		return "closed"
	case ServiceStopVMRequired:
		return "stop_vm_required"
	default:
		return "unknown"
	}
}

func ValidateServiceOperation(value ServiceOperation) error {
	if value < ServiceOperationPrepare || value > ServiceOperationInspect {
		return ErrContractInvalidArgument
	}
	return nil
}

func (value ServiceOperation) String() string {
	switch value {
	case ServiceOperationPrepare:
		return "prepare"
	case ServiceOperationExec:
		return "exec"
	case ServiceOperationRenew:
		return "renew"
	case ServiceOperationRevoke:
		return "revoke"
	case ServiceOperationInspect:
		return "inspect"
	default:
		return "unknown"
	}
}

func ValidateServiceLossCategory(value ServiceLossCategory) error {
	if value < ServiceLossAgent || value > ServiceLossCgroup {
		return ErrContractInvalidArgument
	}
	return nil
}

func (value ServiceLossCategory) String() string {
	switch value {
	case ServiceLossAgent:
		return "agent"
	case ServiceLossJob:
		return "job"
	case ServiceLossMonitor:
		return "monitor"
	case ServiceLossMount:
		return "mount"
	case ServiceLossCgroup:
		return "cgroup"
	default:
		return "unknown"
	}
}

type Core interface {
	BeginPrepare(context.Context, CorePrepareRequest) (CorePreparation, error)
	BeginExec(context.Context, CoreExecRequest, credentialmemory.BorrowedView) (CoreExecution, error)
	Renew(context.Context, CoreRenewRequest) error
	Revoke(context.Context, CoreRevokeRequest) (CoreCleanupResult, error)
	Inspect(context.Context, CoreInspectRequest) (CoreInspection, error)
	Close(context.Context) error
}

type CorePreparation interface {
	StageFile(context.Context, CoreFileRequest, credentialmemory.BorrowedView) error
	Commit(context.Context, CoreCommitRequest) (CorePreparedResult, error)
	Rollback(context.Context) (CoreCleanupResult, error)
}

type CoreExecution interface {
	WriteStdin(context.Context, credentialmemory.BorrowedView, uint64, bool) error
	GrantOutput(context.Context, CoreOutputRequest) error
	Next(context.Context) (CoreExecutionEvent, error)
	Cancel(context.Context) (CoreCleanupResult, error)
}
