package credentialprotocol

import "errors"

var (
	ErrUnknownRevokeReason        = errors.New("credential protocol revoke reason is unknown")
	ErrUnknownResponseDisposition = errors.New("credential protocol response disposition is unknown")
	ErrUnknownFailureCode         = errors.New("credential protocol failure code is unknown")
	ErrUnknownEventCode           = errors.New("credential protocol event code is unknown")
	ErrUnknownCloseReason         = errors.New("credential protocol close reason is unknown")
)

// RevokeReason is the closed one-byte HL8P revoke-reason catalog.
type RevokeReason uint8

const (
	RevokeReasonRequested      RevokeReason = 1
	RevokeReasonExpired        RevokeReason = 2
	RevokeReasonSessionLoss    RevokeReason = 3
	RevokeReasonSourceRevoked  RevokeReason = 4
	RevokeReasonWorkerCancel   RevokeReason = 5
	RevokeReasonDaemonShutdown RevokeReason = 6
)

func ValidateRevokeReason(value RevokeReason) error {
	switch value {
	case RevokeReasonRequested, RevokeReasonExpired, RevokeReasonSessionLoss, RevokeReasonSourceRevoked, RevokeReasonWorkerCancel, RevokeReasonDaemonShutdown:
		return nil
	default:
		return ErrUnknownRevokeReason
	}
}

func (value RevokeReason) String() string {
	switch value {
	case RevokeReasonRequested:
		return "requested"
	case RevokeReasonExpired:
		return "expired"
	case RevokeReasonSessionLoss:
		return "session_loss"
	case RevokeReasonSourceRevoked:
		return "source_revoked"
	case RevokeReasonWorkerCancel:
		return "worker_cancel"
	case RevokeReasonDaemonShutdown:
		return "daemon_shutdown"
	default:
		return "unknown"
	}
}

// ResponseDisposition is the closed one-byte HL8P response disposition.
type ResponseDisposition uint8

const (
	ResponseDispositionAccepted        ResponseDisposition = 1
	ResponseDispositionRejected        ResponseDisposition = 2
	ResponseDispositionCleanupComplete ResponseDisposition = 3
	ResponseDispositionCleanupRetry    ResponseDisposition = 4
	ResponseDispositionStopVMRequired  ResponseDisposition = 5
)

func ValidateResponseDisposition(value ResponseDisposition) error {
	switch value {
	case ResponseDispositionAccepted, ResponseDispositionRejected, ResponseDispositionCleanupComplete, ResponseDispositionCleanupRetry, ResponseDispositionStopVMRequired:
		return nil
	default:
		return ErrUnknownResponseDisposition
	}
}

func (value ResponseDisposition) String() string {
	switch value {
	case ResponseDispositionAccepted:
		return "accepted"
	case ResponseDispositionRejected:
		return "rejected"
	case ResponseDispositionCleanupComplete:
		return "cleanup_complete"
	case ResponseDispositionCleanupRetry:
		return "cleanup_retry"
	case ResponseDispositionStopVMRequired:
		return "stop_vm_required"
	default:
		return "unknown"
	}
}

// FailureCode is the closed one-byte HL8P failure catalog. Zero is the
// canonical none value; later response-body validation owns its disposition
// correlation.
type FailureCode uint8

const (
	FailureCodeNone              FailureCode = 0
	FailureCodeMalformed         FailureCode = 1
	FailureCodeIdentityMismatch  FailureCode = 2
	FailureCodeRevisionStale     FailureCode = 3
	FailureCodeExpired           FailureCode = 4
	FailureCodeResourceLimit     FailureCode = 5
	FailureCodePrepareFailed     FailureCode = 6
	FailureCodeRenewFailed       FailureCode = 7
	FailureCodeRevokeFailed      FailureCode = 8
	FailureCodeExecFailed        FailureCode = 9
	FailureCodeCleanupIncomplete FailureCode = 10
	FailureCodeHelperUnavailable FailureCode = 11
)

func ValidateFailureCode(value FailureCode) error {
	switch value {
	case FailureCodeNone, FailureCodeMalformed, FailureCodeIdentityMismatch, FailureCodeRevisionStale, FailureCodeExpired, FailureCodeResourceLimit, FailureCodePrepareFailed, FailureCodeRenewFailed, FailureCodeRevokeFailed, FailureCodeExecFailed, FailureCodeCleanupIncomplete, FailureCodeHelperUnavailable:
		return nil
	default:
		return ErrUnknownFailureCode
	}
}

func (value FailureCode) String() string {
	switch value {
	case FailureCodeNone:
		return "none"
	case FailureCodeMalformed:
		return "malformed"
	case FailureCodeIdentityMismatch:
		return "identity_mismatch"
	case FailureCodeRevisionStale:
		return "revision_stale"
	case FailureCodeExpired:
		return "expired"
	case FailureCodeResourceLimit:
		return "resource_limit"
	case FailureCodePrepareFailed:
		return "prepare_failed"
	case FailureCodeRenewFailed:
		return "renew_failed"
	case FailureCodeRevokeFailed:
		return "revoke_failed"
	case FailureCodeExecFailed:
		return "exec_failed"
	case FailureCodeCleanupIncomplete:
		return "cleanup_incomplete"
	case FailureCodeHelperUnavailable:
		return "helper_unavailable"
	default:
		return "unknown"
	}
}

// EventCode is the closed one-byte HL8P event catalog.
type EventCode uint8

const (
	EventCodeExpired         EventCode = 1
	EventCodeSessionLoss     EventCode = 2
	EventCodeSourceRevoked   EventCode = 3
	EventCodeCleanupRequired EventCode = 4
)

func ValidateEventCode(value EventCode) error {
	switch value {
	case EventCodeExpired, EventCodeSessionLoss, EventCodeSourceRevoked, EventCodeCleanupRequired:
		return nil
	default:
		return ErrUnknownEventCode
	}
}

func (value EventCode) String() string {
	switch value {
	case EventCodeExpired:
		return "expired"
	case EventCodeSessionLoss:
		return "session_loss"
	case EventCodeSourceRevoked:
		return "source_revoked"
	case EventCodeCleanupRequired:
		return "cleanup_required"
	default:
		return "unknown"
	}
}

// CloseReason is the closed one-byte HL8P close-reason catalog.
type CloseReason uint8

const (
	CloseReasonNormal        CloseReason = 1
	CloseReasonProtocolError CloseReason = 2
	CloseReasonIdentityDrift CloseReason = 3
	CloseReasonExpired       CloseReason = 4
	CloseReasonHelperLoss    CloseReason = 5
	CloseReasonShutdown      CloseReason = 6
)

func ValidateCloseReason(value CloseReason) error {
	switch value {
	case CloseReasonNormal, CloseReasonProtocolError, CloseReasonIdentityDrift, CloseReasonExpired, CloseReasonHelperLoss, CloseReasonShutdown:
		return nil
	default:
		return ErrUnknownCloseReason
	}
}

func (value CloseReason) String() string {
	switch value {
	case CloseReasonNormal:
		return "normal"
	case CloseReasonProtocolError:
		return "protocol_error"
	case CloseReasonIdentityDrift:
		return "identity_drift"
	case CloseReasonExpired:
		return "expired"
	case CloseReasonHelperLoss:
		return "helper_loss"
	case CloseReasonShutdown:
		return "shutdown"
	default:
		return "unknown"
	}
}
