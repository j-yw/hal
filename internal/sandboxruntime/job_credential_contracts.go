package sandboxruntime

import (
	"context"
	"errors"
	"time"
)

// Stable neutral credential lifecycle errors. These deliberately contain no
// wrapped implementation cause or live identity.
var (
	ErrAuthenticatedWorkerPrincipal  = errors.New("authenticated worker principal rejected")
	ErrJobCredentialExpired          = errors.New("credential_expired")
	ErrJobCredentialIdentityMismatch = errors.New("credential_identity_mismatch")
	ErrJobCredentialProofInvalid     = errors.New("credential proof invalid")
	ErrJobCredentialProofStale       = errors.New("credential proof stale")
	ErrJobCredentialReplayRejected   = errors.New("credential_replay_rejected")
	ErrJobCredentialRevisionStale    = errors.New("credential_revision_stale")
	ErrJobCredentialSerialization    = errors.New("job credential live state is not serializable")
	ErrJobCredentialTransition       = errors.New("job credential lifecycle transition rejected")
)

const (
	MaxJobCredentialLifetime              = time.Hour
	MaxJobCredentialCleanupObservationAge = 5 * time.Minute
)

type JobCredentialDeliveryMode string

const (
	JobCredentialDeliveryModeHTTPProxy JobCredentialDeliveryMode = "http_proxy"
	JobCredentialDeliveryModeFileTmpfs JobCredentialDeliveryMode = "file_tmpfs"
	JobCredentialDeliveryModeSSHAgent  JobCredentialDeliveryMode = "ssh_agent"
)

type JobCredentialState string

const (
	JobCredentialStatePreparing         JobCredentialState = "preparing"
	JobCredentialStateActive            JobCredentialState = "active"
	JobCredentialStateRenewing          JobCredentialState = "renewing"
	JobCredentialStateRevoking          JobCredentialState = "revoking"
	JobCredentialStateRevoked           JobCredentialState = "revoked"
	JobCredentialStateExpired           JobCredentialState = "expired"
	JobCredentialStateCleanupIncomplete JobCredentialState = "cleanup_incomplete"
)

type JobCredentialFailureCode string

const (
	JobCredentialFailureProtocolUnsupported           JobCredentialFailureCode = "credential_protocol_unsupported"
	JobCredentialFailureIdentityMismatch              JobCredentialFailureCode = "credential_identity_mismatch"
	JobCredentialFailureReplayRejected                JobCredentialFailureCode = "credential_replay_rejected"
	JobCredentialFailureRevisionStale                 JobCredentialFailureCode = "credential_revision_stale"
	JobCredentialFailureExpired                       JobCredentialFailureCode = "credential_expired"
	JobCredentialFailureMemoryUnlocked                JobCredentialFailureCode = "credential_memory_unlocked"
	JobCredentialFailureAdmissionDenied               JobCredentialFailureCode = "credential_admission_denied"
	JobCredentialFailureSourceUnavailable             JobCredentialFailureCode = "credential_source_unavailable"
	JobCredentialFailureWorkerProtocolUnsupported     JobCredentialFailureCode = "credential_worker_protocol_unsupported"
	JobCredentialFailureNetworkProofUnavailable       JobCredentialFailureCode = "credential_network_proof_unavailable"
	JobCredentialFailureServiceUnapproved             JobCredentialFailureCode = "credential_service_unapproved"
	JobCredentialFailurePrepareFailed                 JobCredentialFailureCode = "credential_prepare_failed"
	JobCredentialFailureRenewFailed                   JobCredentialFailureCode = "credential_renew_failed"
	JobCredentialFailureRevokeFailed                  JobCredentialFailureCode = "credential_revoke_failed"
	JobCredentialFailureProcessTerminationUnconfirmed JobCredentialFailureCode = "credential_process_termination_unconfirmed"
	JobCredentialFailureGuestHelperUnavailable        JobCredentialFailureCode = "credential_guest_helper_unavailable"
	JobCredentialFailureCleanupIncomplete             JobCredentialFailureCode = "credential_cleanup_incomplete"
)

// JobCredentialIdentitySeed is the complete safe correlation tuple available
// before guest authentication supplies its session and helper generations.
type JobCredentialIdentitySeed struct {
	SandboxID                    string
	ExecutionID                  string
	WorkerID                     string
	HostID                       string
	RuntimeDriver                string
	RuntimeID                    string
	RuntimeGeneration            string
	FirecrackerProcessGeneration string
	VsockGeneration              string
	WorkerJobID                  string
	SubmissionID                 string
	PlanID                       string
	ActivationGeneration         string
	CredentialGeneration         string
	NetworkPlanID                string
	PolicySnapshotID             string
	ProxySessionID               string
	ProxyGenerationID            string
	TopologyGenerationID         string
	RuleGenerationID             string
	AdmissionGrantID             string
	PrincipalID                  string
	TemplatePolicyID             string
	WorkspacePolicyID            string
	ControllerKeyGeneration      string
	GuestBootGeneration          string
	GuestImageGeneration         string
	GuestImageDigest             string
	AdmissionGrantRevision       uint64
	BindingIDs                   []string
	DeliveryModes                []JobCredentialDeliveryMode
	IssuedAt                     time.Time
}

// JobCredentialIdentity is the complete safe correlation tuple for one live
// credential activation. It never contains a value, path, endpoint, or ticket.
type JobCredentialIdentity struct {
	SandboxID                    string
	ExecutionID                  string
	WorkerID                     string
	HostID                       string
	RuntimeDriver                string
	RuntimeID                    string
	RuntimeGeneration            string
	FirecrackerProcessGeneration string
	VsockGeneration              string
	WorkerJobID                  string
	SubmissionID                 string
	PlanID                       string
	ActivationGeneration         string
	CredentialGeneration         string
	NetworkPlanID                string
	PolicySnapshotID             string
	ProxySessionID               string
	ProxyGenerationID            string
	TopologyGenerationID         string
	RuleGenerationID             string
	AdmissionGrantID             string
	PrincipalID                  string
	TemplatePolicyID             string
	WorkspacePolicyID            string
	ControllerKeyGeneration      string
	GuestBootGeneration          string
	GuestImageGeneration         string
	GuestImageDigest             string
	GuestSessionGeneration       string
	GuestHelperGeneration        string
	AdmissionGrantRevision       uint64
	BindingIDs                   []string
	DeliveryModes                []JobCredentialDeliveryMode
	IssuedAt                     time.Time
}

// JobCredentialAdmissionIdentity is the safe job/runtime portion of an
// authorization request. The server-derived principal is intentionally absent.
type JobCredentialAdmissionIdentity struct {
	SandboxID                    string
	ExecutionID                  string
	WorkerID                     string
	HostID                       string
	RuntimeDriver                string
	RuntimeID                    string
	RuntimeGeneration            string
	FirecrackerProcessGeneration string
	VsockGeneration              string
	WorkerJobID                  string
	SubmissionID                 string
	PlanID                       string
	ActivationGeneration         string
	CredentialGeneration         string
	NetworkPlanID                string
	PolicySnapshotID             string
	ProxySessionID               string
	ProxyGenerationID            string
	TopologyGenerationID         string
	RuleGenerationID             string
	IssuedAt                     time.Time
}

type JobCredentialBindingRequest struct {
	ID                string
	Mode              JobCredentialDeliveryMode
	SourceReferenceID string
	ServiceID         string
}

type JobCredentialAdmissionRequest struct {
	Identity           JobCredentialAdmissionIdentity
	GrantID            string
	GrantRevision      uint64
	PlanID             string
	TemplatePolicyID   string
	WorkspacePolicyID  string
	SourceReferenceIDs []string
	Bindings           []JobCredentialBindingRequest
}

// AuthenticatedWorkerPrincipal is issued by an authority bound to an
// authenticated server connection. Implementations are validated by that
// authority before use; visible fields alone are never sufficient.
type AuthenticatedWorkerPrincipal interface {
	IsAuthenticatedWorkerPrincipal()
	ID() string
	UID() uint32
	GID() uint32
	AuthorityID() string
	AuthorityGeneration() string
}

// CredentialAdmissionAuthorization is an opaque, registry-owned live result.
// Its concrete registry must validate ownership before resolving a source.
type CredentialAdmissionAuthorization interface{}

type CredentialAdmissionAuthorizer interface {
	AuthorizeJobCredentials(context.Context, AuthenticatedWorkerPrincipal, JobCredentialAdmissionRequest) (CredentialAdmissionAuthorization, error)
}

type JobCredentialSecretSink interface {
	MaxCredentialBytes() int
	WriteCredential([]byte) error
}

type LiveSecretSource interface {
	FillSecret(context.Context, JobCredentialSecretSink) error
}

type AuthorizedCredentialSourceRegistry interface {
	ResolveAuthorizedSource(context.Context, CredentialAdmissionAuthorization, string) (LiveSecretSource, error)
}

type JobCredentialPrepareRequest struct {
	Identity          JobCredentialIdentity
	Admission         JobCredentialAdmissionRequest
	Authorization     CredentialAdmissionAuthorization
	AuthorizedSources []JobCredentialAuthorizedSource
}

type JobCredentialAuthorizedSource struct {
	ReferenceID string
	Source      LiveSecretSource
}

type JobCredentialRecoveryRequest struct {
	Identity JobCredentialIdentity
	Revision uint64
}

type JobCredentialExecBinding interface{}

type JobCredentialRevokeReason string

type JobCredentialLoss struct {
	Identity JobCredentialIdentity
	Revision uint64
	Code     JobCredentialFailureCode
}

// JobCredentialRuntimeBindingRequest contains only the worker-owned job and
// admission identity that a retained runtime target must complete with its
// live Firecracker, guest, image, and network generations. Target may carry
// live connection state and must never be serialized with the returned
// binding.
type JobCredentialRuntimeBindingRequest struct {
	Target                 Target
	WorkerID               string
	WorkerJobID            string
	SubmissionID           string
	ExecutionID            string
	PlanID                 string
	AdmissionGrantID       string
	AdmissionGrantRevision uint64
	PrincipalID            string
	TemplatePolicyID       string
	WorkspacePolicyID      string
	BindingIDs             []string
	DeliveryModes          []JobCredentialDeliveryMode
	IssuedAt               time.Time
}

// JobCredentialRuntimeBinding is a live, non-serializable association between
// one complete credential identity seed and the exact retained runtime that
// owns those generations.
type JobCredentialRuntimeBinding struct {
	Seed    JobCredentialIdentitySeed
	Runtime JobCredentialRuntime
}

// JobCredentialRuntimeBindingProvider is implemented only by runtime drivers
// that retain the authority needed to complete a credential identity. Worker
// code must not derive generations from sanitized target metadata.
type JobCredentialRuntimeBindingProvider interface {
	BindJobCredentialRuntime(context.Context, JobCredentialRuntimeBindingRequest) (JobCredentialRuntimeBinding, error)
}

type JobCredentialRuntime interface {
	PreflightJobCredentials(context.Context, JobCredentialIdentitySeed) (JobCredentialRuntimePreflight, error)
	RecoverJobCredentials(context.Context, JobCredentialRecoveryRequest) (JobCredentialCleanupProof, error)
}

type JobCredentialRuntimePreflight interface {
	Identity() JobCredentialIdentity
	PrepareJobCredentials(context.Context, JobCredentialPrepareRequest) (JobCredentialSession, error)
	Abort(context.Context) (JobCredentialCleanupProof, error)
	Loss() <-chan JobCredentialLoss
}

type JobCredentialSession interface {
	ExecBinding() JobCredentialExecBinding
	ActiveProof() JobCredentialActiveProof
	Renew(context.Context) (JobCredentialActiveProof, error)
	Revoke(context.Context, JobCredentialRevokeReason) (JobCredentialCleanupProof, error)
	Loss() <-chan JobCredentialLoss
}

func cloneJobCredentialIdentity(identity JobCredentialIdentity) JobCredentialIdentity {
	identity.BindingIDs = append([]string(nil), identity.BindingIDs...)
	identity.DeliveryModes = append([]JobCredentialDeliveryMode(nil), identity.DeliveryModes...)
	return identity
}

func validJobCredentialIdentity(identity JobCredentialIdentity) bool {
	return ValidateJobCredentialIdentity(identity) == nil
}

func validJobCredentialSafeID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func validJobCredentialDeliveryMode(mode JobCredentialDeliveryMode) bool {
	switch mode {
	case JobCredentialDeliveryModeHTTPProxy, JobCredentialDeliveryModeFileTmpfs, JobCredentialDeliveryModeSSHAgent:
		return true
	default:
		return false
	}
}

func sameJobCredentialIdentity(left, right JobCredentialIdentity) bool {
	return sameJobCredentialIdentitySeed(jobCredentialIdentitySeedFromIdentity(left), jobCredentialIdentitySeedFromIdentity(right)) &&
		left.GuestSessionGeneration == right.GuestSessionGeneration && left.GuestHelperGeneration == right.GuestHelperGeneration
}
