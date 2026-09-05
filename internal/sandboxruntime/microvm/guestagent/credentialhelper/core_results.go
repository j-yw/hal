package credentialhelper

import (
	"crypto/sha256"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type CorePreparedResult struct {
	liveValue
	generations       CoreGenerations
	expiresUnixNano   int64
	bindingCount      uint16
	manifestSHA256    [32]byte
	transactionSHA256 [32]byte
	prepared          CorePreparedCapability
}

type CoreOutputResult struct {
	liveValue
	execution CoreExecutionCapability
	kind      credentialprotocol.HelperExecStreamKind
	offset    uint64
	byteCount uint32
	sha256    [32]byte
	eof       bool
	truncated bool
}

type CoreExecExitCategory uint8

const (
	CoreExecExitExited      CoreExecExitCategory = 1
	CoreExecExitSignaled    CoreExecExitCategory = 2
	CoreExecExitSetupFailed CoreExecExitCategory = 3
)

type CoreExecResult struct {
	liveValue
	execution             CoreExecutionCapability
	exitCategory          CoreExecExitCategory
	exitCode              int32
	stdinBytes            uint64
	stdinSHA256           [32]byte
	stdinTranscriptSHA256 [32]byte
	stdoutBytes           uint64
	stdoutSHA256          [32]byte
	stdoutTruncated       bool
	stderrBytes           uint64
	stderrSHA256          [32]byte
	stderrTruncated       bool
	execTransactionSHA256 [32]byte
}

type CoreCleanupCategory uint8

const (
	CoreCleanupComplete       CoreCleanupCategory = 1
	CoreCleanupRetryRequired  CoreCleanupCategory = 2
	CoreCleanupStopVMRequired CoreCleanupCategory = 3
)

type CoreCleanupResult struct {
	liveValue
	cleanup         CoreCleanupCapability
	category        CoreCleanupCategory
	authorityAbsent bool
	resourcesAbsent bool
}

type CoreInspectionState uint8

const (
	CoreInspectionPreparing CoreInspectionState = 1
	CoreInspectionPrepared  CoreInspectionState = 2
	CoreInspectionExecuting CoreInspectionState = 3
	CoreInspectionRevoking  CoreInspectionState = 4
	CoreInspectionAbsent    CoreInspectionState = 5
)

type CoreInspection struct {
	liveValue
	prepared         CorePreparedCapability
	state            CoreInspectionState
	generations      CoreGenerations
	expiresUnixNano  int64
	activeExecutions uint16
	authorityPresent bool
	resourcesPresent bool
}

func NewCorePreparedResult(prepared CorePreparedCapability, generations CoreGenerations, expiresUnixNano int64, bindingCount uint16, manifestSHA256, transactionSHA256 [32]byte) (CorePreparedResult, error) {
	if !validCoreCapabilityDigest(prepared.digest) || !validCompleteCoreGenerations(generations) || expiresUnixNano <= 0 || bindingCount == 0 || bindingCount > credentialprotocol.MaxHelperBindings || manifestSHA256 == ([32]byte{}) || transactionSHA256 == ([32]byte{}) {
		return CorePreparedResult{}, ErrContractInvalidArgument
	}
	return CorePreparedResult{prepared: prepared, generations: generations, expiresUnixNano: expiresUnixNano, bindingCount: bindingCount, manifestSHA256: manifestSHA256, transactionSHA256: transactionSHA256}, nil
}

func NewCoreOutputResult(execution CoreExecutionCapability, kind credentialprotocol.HelperExecStreamKind, offset uint64, byteCount uint32, digest [32]byte, eof, truncated bool) (CoreOutputResult, error) {
	if !validCoreCapabilityDigest(execution.digest) || !validCoreOutputKind(kind) {
		return CoreOutputResult{}, ErrContractInvalidArgument
	}
	emptyDigest := sha256.Sum256(nil)
	validData := !eof && byteCount > 0 && byteCount <= credentialprotocol.MaxHelperExecStreamPayloadBytes && digest != ([32]byte{}) && !truncated
	validEOF := eof && byteCount == 0 && digest == emptyDigest
	if !validData && !validEOF {
		return CoreOutputResult{}, ErrContractResultMatrix
	}
	return CoreOutputResult{execution: execution, kind: kind, offset: offset, byteCount: byteCount, sha256: digest, eof: eof, truncated: truncated}, nil
}

func NewCoreExecResult(execution CoreExecutionCapability, exitCategory CoreExecExitCategory, exitCode int32, stdinBytes uint64, stdinSHA256, stdinTranscriptSHA256 [32]byte, stdoutBytes uint64, stdoutSHA256 [32]byte, stdoutTruncated bool, stderrBytes uint64, stderrSHA256 [32]byte, stderrTruncated bool, execTransactionSHA256 [32]byte) (CoreExecResult, error) {
	if !validCoreCapabilityDigest(execution.digest) {
		return CoreExecResult{}, ErrContractInvalidArgument
	}
	if !validCoreExit(exitCategory, exitCode) || !validCoreStreamSummary(stdinBytes, stdinSHA256) || !validCoreStreamSummary(stdoutBytes, stdoutSHA256) || !validCoreStreamSummary(stderrBytes, stderrSHA256) || stdinTranscriptSHA256 == ([32]byte{}) || execTransactionSHA256 == ([32]byte{}) {
		return CoreExecResult{}, ErrContractResultMatrix
	}
	return CoreExecResult{
		execution: execution, exitCategory: exitCategory, exitCode: exitCode,
		stdinBytes: stdinBytes, stdinSHA256: stdinSHA256, stdinTranscriptSHA256: stdinTranscriptSHA256,
		stdoutBytes: stdoutBytes, stdoutSHA256: stdoutSHA256, stdoutTruncated: stdoutTruncated,
		stderrBytes: stderrBytes, stderrSHA256: stderrSHA256, stderrTruncated: stderrTruncated,
		execTransactionSHA256: execTransactionSHA256,
	}, nil
}

func NewCoreCleanupResult(cleanup CoreCleanupCapability, category CoreCleanupCategory, authorityAbsent, resourcesAbsent bool) (CoreCleanupResult, error) {
	if !validCoreCapabilityDigest(cleanup.digest) {
		return CoreCleanupResult{}, ErrContractInvalidArgument
	}
	valid := category == CoreCleanupComplete && authorityAbsent && resourcesAbsent ||
		category == CoreCleanupRetryRequired && authorityAbsent && !resourcesAbsent ||
		category == CoreCleanupStopVMRequired && !(authorityAbsent && resourcesAbsent)
	if !valid {
		return CoreCleanupResult{}, ErrContractResultMatrix
	}
	return CoreCleanupResult{cleanup: cleanup, category: category, authorityAbsent: authorityAbsent, resourcesAbsent: resourcesAbsent}, nil
}

func NewCoreInspection(prepared CorePreparedCapability, state CoreInspectionState, generations CoreGenerations, expiresUnixNano int64, activeExecutions uint16, authorityPresent, resourcesPresent bool) (CoreInspection, error) {
	if !validCoreCapabilityDigest(prepared.digest) || !validCompleteCoreGenerations(generations) {
		return CoreInspection{}, ErrContractInvalidArgument
	}
	valid := state == CoreInspectionPreparing && expiresUnixNano > 0 && activeExecutions == 0 && !authorityPresent && resourcesPresent ||
		state == CoreInspectionPrepared && expiresUnixNano > 0 && activeExecutions == 0 && authorityPresent && resourcesPresent ||
		state == CoreInspectionExecuting && expiresUnixNano > 0 && activeExecutions == 1 && authorityPresent && resourcesPresent ||
		state == CoreInspectionRevoking && expiresUnixNano > 0 && activeExecutions <= 1 && !authorityPresent && resourcesPresent ||
		state == CoreInspectionAbsent && expiresUnixNano == 0 && activeExecutions == 0 && !authorityPresent && !resourcesPresent
	if !valid {
		return CoreInspection{}, ErrContractResultMatrix
	}
	return CoreInspection{prepared: prepared, state: state, generations: generations, expiresUnixNano: expiresUnixNano, activeExecutions: activeExecutions, authorityPresent: authorityPresent, resourcesPresent: resourcesPresent}, nil
}

func validCoreExit(category CoreExecExitCategory, code int32) bool {
	switch category {
	case CoreExecExitExited:
		return code >= 0 && code <= 255
	case CoreExecExitSignaled:
		return code >= 1 && code <= 64
	case CoreExecExitSetupFailed:
		return code == 1
	default:
		return false
	}
}

func validCoreStreamSummary(count uint64, digest [32]byte) bool {
	if count > credentialprotocol.MaxHelperExecStreamAggregateBytes {
		return false
	}
	if count == 0 {
		return digest == sha256.Sum256(nil)
	}
	return digest != ([32]byte{})
}
