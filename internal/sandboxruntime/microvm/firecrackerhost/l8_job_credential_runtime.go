package firecrackerhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	guestsession "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

const l8JobCredentialRuntimeValuePlaceholder = "[firecracker-l8-job-credential-runtime]"

var (
	ErrL8JobCredentialRuntimeUnavailable = errors.New("Firecracker L8 job credential runtime unavailable")
	ErrL8JobCredentialRuntimeInvalid     = errors.New("Firecracker L8 job credential runtime invalid")
	ErrL8JobCredentialRuntimeUnsupported = errors.New("Firecracker L8 job credential runtime unsupported")
	ErrL8JobCredentialRuntimeSerialization = errors.New("Firecracker L8 job credential runtime serialization denied")
	errL8JobCredentialRuntimeDependencyUnaccepted = errors.New("dependency_unaccepted")
)

type l8JobCredentialGuestSessionOpener interface {
	Open(context.Context, sandboxruntime.JobCredentialIdentitySeed) (l8JobCredentialGuestSession, error)
}

type l8JobCredentialGuestSession interface {
	GuestSessionGeneration() string
	GuestHelperGeneration() string
	SessionID() [32]byte
	HardExpiry() time.Time
	Prepare(context.Context, sandboxruntime.JobCredentialIdentity, time.Time, []l8JobCredentialGuestBindingManifest) (l8JobCredentialGuestPrepareResult, error)
	Renew(context.Context, sandboxruntime.JobCredentialIdentity, uint64, time.Time, string) (string, error)
	Revoke(context.Context, sandboxruntime.JobCredentialIdentity, uint64, sandboxruntime.JobCredentialRevokeReason) (string, error)
	Loss() <-chan struct{}
	Close() error
}

type l8JobCredentialGuestBindingManifest struct {
	BindingID         string
	Mode              sandboxruntime.JobCredentialDeliveryMode
	ServiceID         string
	TargetPath        string
	DeclaredFileBytes uint32
	FileSHA256        string
	SSHPolicyID       string
	SSHPolicyRevision uint64
}

type l8JobCredentialGuestPrepareResult struct {
	ActiveProofID string
	ExecBindingID string
	BindingProofs []l8JobCredentialGuestBindingProof
}

type l8JobCredentialGuestBindingProof struct {
	BindingID string
	Mode      sandboxruntime.JobCredentialDeliveryMode
	ProofID   string
}

type l8JobCredentialHTTPProxyActivator interface {
	Activate(context.Context, sandboxruntime.JobCredentialIdentity, sandboxruntime.JobCredentialBindingRequest, sandboxruntime.LiveSecretSource) (l8JobCredentialHTTPProxyHandle, error)
}

type l8JobCredentialHTTPProxyHandle interface {
	ServiceID() string
	Renew(context.Context) error
	Revoke(context.Context) error
}

type l8JobCredentialFileTmpfsActivator interface {
	Materialize(context.Context, sandboxruntime.JobCredentialIdentity, sandboxruntime.JobCredentialBindingRequest, sandboxruntime.LiveSecretSource) (l8JobCredentialFileHandle, error)
}

type l8JobCredentialFileHandle interface {
	TargetPath() string
	DeclaredFileBytes() uint32
	FileSHA256() string
	Revoke(context.Context) error
}

type l8JobCredentialSSHRelayActivator interface {
	Activate(context.Context, sandboxruntime.JobCredentialIdentity, sandboxruntime.JobCredentialBindingRequest) (l8JobCredentialSSHRelayHandle, error)
}

type l8JobCredentialSSHRelayHandle interface {
	PolicyID() string
	PolicyRevision() uint64
	Renew(context.Context) error
	Revoke(context.Context) error
}

type l8JobCredentialRuntimeDependencies struct {
	GuestSession l8JobCredentialGuestSessionOpener
	HTTPProxy    l8JobCredentialHTTPProxyActivator
	FileTmpfs    l8JobCredentialFileTmpfsActivator
	SSHRelay     l8JobCredentialSSHRelayActivator
	Now          func() time.Time
	Random       io.Reader
}

// L8JobCredentialRuntime is the default-off Firecracker host implementation of
// sandboxruntime.JobCredentialRuntime. Callers must inject it explicitly.
type L8JobCredentialRuntime struct {
	mu         sync.Mutex
	deps       l8JobCredentialRuntimeDependencies
	attempted  bool
	production bool
}

// NewProductionL8JobCredentialRuntime constructs the explicit Firecracker host
// credential runtime. It is never invoked by default backend, sandboxd, worker,
// or command paths.
func NewProductionL8JobCredentialRuntime(deps l8JobCredentialRuntimeDependencies) (*L8JobCredentialRuntime, error) {
	if !l8JobCredentialRuntimePlatformSupported() {
		return nil, ErrL8JobCredentialRuntimeUnsupported
	}
	return newL8JobCredentialRuntime(deps, true)
}

func newL8JobCredentialRuntime(deps l8JobCredentialRuntimeDependencies, production bool) (*L8JobCredentialRuntime, error) {
	if l8JobCredentialRuntimeValueIsNil(deps.GuestSession) || deps.Now == nil || l8JobCredentialRuntimeValueIsNil(deps.Random) {
		return nil, ErrL8JobCredentialRuntimeInvalid
	}
	return &L8JobCredentialRuntime{deps: deps, production: production}, nil
}

func (runtime *L8JobCredentialRuntime) PreflightJobCredentials(ctx context.Context, seed sandboxruntime.JobCredentialIdentitySeed) (sandboxruntime.JobCredentialRuntimePreflight, error) {
	return nil, ErrL8JobCredentialRuntimeUnavailable
}

func (runtime *L8JobCredentialRuntime) RecoverJobCredentials(context.Context, sandboxruntime.JobCredentialRecoveryRequest) (sandboxruntime.JobCredentialCleanupProof, error) {
	return sandboxruntime.JobCredentialCleanupProof{}, errL8JobCredentialRuntimeDependencyUnaccepted
}

func (*L8JobCredentialRuntime) String() string { return l8JobCredentialRuntimeValuePlaceholder }
func (*L8JobCredentialRuntime) GoString() string {
	return l8JobCredentialRuntimeValuePlaceholder
}
func (*L8JobCredentialRuntime) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, l8JobCredentialRuntimeValuePlaceholder)
}
func (*L8JobCredentialRuntime) MarshalJSON() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}
func (*L8JobCredentialRuntime) MarshalText() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}
func (*L8JobCredentialRuntime) MarshalBinary() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}

func l8JobCredentialRuntimeValueIsNil(value any) bool {
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

func sanitizeL8JobCredentialRuntimeError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sandboxruntime.ErrJobCredentialIdentityMismatch):
		return sandboxruntime.ErrJobCredentialIdentityMismatch
	case errors.Is(err, sandboxruntime.ErrJobCredentialTransition):
		return sandboxruntime.ErrJobCredentialTransition
	case errors.Is(err, sandboxruntime.ErrJobCredentialReplayRejected):
		return sandboxruntime.ErrJobCredentialReplayRejected
	case errors.Is(err, sandboxruntime.ErrJobCredentialRevisionStale):
		return sandboxruntime.ErrJobCredentialRevisionStale
	case errors.Is(err, sandboxruntime.ErrJobCredentialExpired):
		return sandboxruntime.ErrJobCredentialExpired
	case errors.Is(err, sandboxruntime.ErrJobCredentialProofInvalid):
		return sandboxruntime.ErrJobCredentialProofInvalid
	case errors.Is(err, sandboxruntime.ErrJobCredentialProofStale):
		return sandboxruntime.ErrJobCredentialProofStale
	case errors.Is(err, ErrL8JobCredentialRuntimeUnsupported):
		return ErrL8JobCredentialRuntimeUnsupported
	case errors.Is(err, ErrL8JobCredentialRuntimeInvalid):
		return ErrL8JobCredentialRuntimeInvalid
	case errors.Is(err, errL8JobCredentialRuntimeDependencyUnaccepted):
		return errL8JobCredentialRuntimeDependencyUnaccepted
	default:
		return ErrL8JobCredentialRuntimeUnavailable
	}
}

var (
	_ sandboxruntime.JobCredentialRuntime = (*L8JobCredentialRuntime)(nil)
	_ fmt.Stringer                        = (*L8JobCredentialRuntime)(nil)
)

const l8JobCredentialRuntimeSessionLifetime = guestsession.MaxGuestCredentialSessionLifetime
