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
	ErrL8JobCredentialRuntimeUnavailable          = errors.New("Firecracker L8 job credential runtime unavailable")
	ErrL8JobCredentialRuntimeInvalid              = errors.New("Firecracker L8 job credential runtime invalid")
	ErrL8JobCredentialRuntimeUnsupported          = errors.New("Firecracker L8 job credential runtime unsupported")
	ErrL8JobCredentialRuntimeSerialization        = errors.New("Firecracker L8 job credential runtime serialization denied")
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
	if runtime == nil || l8JobCredentialRuntimeValueIsNil(ctx) {
		return nil, ErrL8JobCredentialRuntimeInvalid
	}
	if runtime.production && !l8JobCredentialRuntimePlatformSupported() {
		return nil, ErrL8JobCredentialRuntimeUnsupported
	}
	cloned, err := sandboxruntime.CloneJobCredentialIdentitySeed(seed)
	if err != nil {
		return nil, sandboxruntime.ErrJobCredentialIdentityMismatch
	}

	runtime.mu.Lock()
	if runtime.attempted {
		runtime.mu.Unlock()
		return nil, sandboxruntime.ErrJobCredentialTransition
	}
	runtime.attempted = true
	deps := runtime.deps
	runtime.mu.Unlock()

	session, openErr := callL8JobCredentialGuestSessionOpener(deps.GuestSession, ctx, cloned)
	if openErr != nil || l8JobCredentialRuntimeValueIsNil(session) {
		if !l8JobCredentialRuntimeValueIsNil(session) {
			_ = session.Close()
		}
		if openErr != nil {
			return nil, sanitizeL8JobCredentialRuntimeError(openErr)
		}
		return nil, ErrL8JobCredentialRuntimeInvalid
	}
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(cloned, session.GuestSessionGeneration(), session.GuestHelperGeneration())
	if err != nil {
		_ = session.Close()
		return nil, sandboxruntime.ErrJobCredentialIdentityMismatch
	}
	preflight := &l8JobCredentialRuntimePreflight{
		deps:      deps,
		identity:  cloneL8JobCredentialIdentity(identity),
		session:   session,
		loss:      make(chan sandboxruntime.JobCredentialLoss, 1),
		stopWatch: make(chan struct{}),
		watchDone: make(chan struct{}),
		state:     l8JobCredentialPreflightOpen,
	}
	go preflight.watchLoss()
	return preflight, nil
}

func (runtime *L8JobCredentialRuntime) RecoverJobCredentials(context.Context, sandboxruntime.JobCredentialRecoveryRequest) (sandboxruntime.JobCredentialCleanupProof, error) {
	return sandboxruntime.JobCredentialCleanupProof{}, errL8JobCredentialRuntimeDependencyUnaccepted
}

type l8JobCredentialPreflightState uint8

const (
	l8JobCredentialPreflightOpen l8JobCredentialPreflightState = iota + 1
	l8JobCredentialPreflightPreparing
	l8JobCredentialPreflightTransferred
	l8JobCredentialPreflightAborted
)

type l8JobCredentialRuntimePreflight struct {
	mu              sync.Mutex
	deps            l8JobCredentialRuntimeDependencies
	identity        sandboxruntime.JobCredentialIdentity
	session         l8JobCredentialGuestSession
	loss            chan sandboxruntime.JobCredentialLoss
	stopWatch       chan struct{}
	watchDone       chan struct{}
	state           l8JobCredentialPreflightState
	lossLatched     bool
	lossOnce        sync.Once
	stopOnce        sync.Once
	abortOnce       sync.Once
	cleanupProof    sandboxruntime.JobCredentialCleanupProof
	abortErr        error
	resources       *l8JobCredentialPreparedResources
	owned           *l8JobCredentialRuntimeSession
	currentRevision uint64
}

type l8JobCredentialRuntimeSession struct {
	mu           sync.Mutex
	preflight    *l8JobCredentialRuntimePreflight
	identity     sandboxruntime.JobCredentialIdentity
	activeProof  sandboxruntime.JobCredentialActiveProof
	cleanupProof sandboxruntime.JobCredentialCleanupProof
	issuedAt     time.Time
	expiresAt    time.Time
	revision     uint64
	guestProofID string
	execBinding  l8JobCredentialExecBinding
	resources    *l8JobCredentialPreparedResources
	revoked      bool
}

type l8JobCredentialExecBinding struct {
	id string
}

type l8JobCredentialPreparedResources struct {
	http      []l8JobCredentialHTTPProxyHandle
	files     []l8JobCredentialFileHandle
	ssh       []l8JobCredentialSSHRelayHandle
	manifests []l8JobCredentialGuestBindingManifest
}

func (preflight *l8JobCredentialRuntimePreflight) Identity() sandboxruntime.JobCredentialIdentity {
	if preflight == nil {
		return sandboxruntime.JobCredentialIdentity{}
	}
	preflight.mu.Lock()
	defer preflight.mu.Unlock()
	return cloneL8JobCredentialIdentity(preflight.identity)
}

func (preflight *l8JobCredentialRuntimePreflight) Loss() <-chan sandboxruntime.JobCredentialLoss {
	if preflight == nil {
		return nil
	}
	return preflight.loss
}

func (preflight *l8JobCredentialRuntimePreflight) PrepareJobCredentials(ctx context.Context, request sandboxruntime.JobCredentialPrepareRequest) (sandboxruntime.JobCredentialSession, error) {
	if preflight == nil || l8JobCredentialRuntimeValueIsNil(ctx) {
		return nil, ErrL8JobCredentialRuntimeInvalid
	}
	preflight.mu.Lock()
	if preflight.state != l8JobCredentialPreflightOpen || preflight.lossLatched {
		preflight.mu.Unlock()
		return nil, sandboxruntime.ErrJobCredentialTransition
	}
	preflight.state = l8JobCredentialPreflightPreparing
	identity := cloneL8JobCredentialIdentity(preflight.identity)
	session := preflight.session
	deps := preflight.deps
	preflight.mu.Unlock()

	if err := validateL8JobCredentialPrepareRequest(identity, request); err != nil {
		preflight.revertPrepare()
		return nil, err
	}
	resources, err := activateL8JobCredentialBindings(ctx, deps, identity, request)
	if err != nil {
		revokeL8JobCredentialResources(ctx, resources)
		preflight.revertPrepare()
		return nil, sanitizeL8JobCredentialRuntimeError(err)
	}
	now := deps.Now().UTC()
	expiresAt, err := l8JobCredentialRuntimeExpiry(identity, session, now, time.Time{})
	if err != nil {
		revokeL8JobCredentialResources(ctx, resources)
		preflight.revertPrepare()
		return nil, err
	}
	guestResult, err := callL8JobCredentialGuestPrepare(session, ctx, identity, expiresAt, resources.manifests)
	if err != nil || guestResult.ActiveProofID == "" || guestResult.ExecBindingID == "" {
		revokeL8JobCredentialResources(ctx, resources)
		preflight.revertPrepare()
		if err != nil {
			return nil, sanitizeL8JobCredentialRuntimeError(err)
		}
		return nil, ErrL8JobCredentialRuntimeInvalid
	}
	proof, err := sandboxruntime.NewJobCredentialActiveProof(sandboxruntime.JobCredentialActiveProofInput{
		ProofID: "active-1", Identity: identity, Revision: 1, IssuedAt: now, ExpiresAt: expiresAt,
	})
	if err != nil {
		revokeL8JobCredentialResources(ctx, resources)
		preflight.revertPrepare()
		return nil, sandboxruntime.ErrJobCredentialProofInvalid
	}

	preflight.mu.Lock()
	if preflight.state != l8JobCredentialPreflightPreparing || preflight.lossLatched {
		if preflight.state == l8JobCredentialPreflightPreparing {
			preflight.state = l8JobCredentialPreflightOpen
		}
		preflight.mu.Unlock()
		revokeL8JobCredentialResources(ctx, resources)
		return nil, sandboxruntime.ErrJobCredentialTransition
	}
	owned := &l8JobCredentialRuntimeSession{
		preflight:    preflight,
		identity:     cloneL8JobCredentialIdentity(identity),
		activeProof:  proof,
		issuedAt:     now,
		expiresAt:    expiresAt,
		revision:     1,
		guestProofID: guestResult.ActiveProofID,
		execBinding:  l8JobCredentialExecBinding{id: guestResult.ExecBindingID},
		resources:    resources,
	}
	preflight.resources = resources
	preflight.owned = owned
	preflight.currentRevision = 1
	preflight.state = l8JobCredentialPreflightTransferred
	preflight.mu.Unlock()
	return owned, nil
}

func (preflight *l8JobCredentialRuntimePreflight) Abort(ctx context.Context) (sandboxruntime.JobCredentialCleanupProof, error) {
	if preflight == nil {
		return sandboxruntime.JobCredentialCleanupProof{}, ErrL8JobCredentialRuntimeInvalid
	}
	preflight.abortOnce.Do(func() {
		preflight.mu.Lock()
		if preflight.state == l8JobCredentialPreflightTransferred {
			preflight.mu.Unlock()
			preflight.abortErr = sandboxruntime.ErrJobCredentialTransition
			return
		}
		preflight.state = l8JobCredentialPreflightAborted
		session := preflight.session
		resources := preflight.resources
		preflight.resources = nil
		nowFn := preflight.deps.Now
		identity := cloneL8JobCredentialIdentity(preflight.identity)
		preflight.mu.Unlock()

		preflight.stopLossWatch()
		revokeL8JobCredentialResources(ctx, resources)
		if !l8JobCredentialRuntimeValueIsNil(session) {
			_ = session.Close()
		}
		observed := nowFn().UTC()
		if observed.Before(identity.IssuedAt) {
			observed = identity.IssuedAt
		}
		proof, err := sandboxruntime.NewJobCredentialCleanupProof(sandboxruntime.JobCredentialCleanupProofInput{
			ProofID: "cleanup-2", Identity: identity, Revision: 2,
			RevokedAt: observed, AbsenceInspectedAt: observed,
			AuthorityAbsent: true, ResourcesAbsent: true,
		})
		preflight.mu.Lock()
		preflight.cleanupProof = proof
		preflight.abortErr = err
		if err != nil {
			preflight.abortErr = sandboxruntime.ErrJobCredentialProofInvalid
		}
		preflight.mu.Unlock()
	})
	preflight.mu.Lock()
	defer preflight.mu.Unlock()
	if preflight.state == l8JobCredentialPreflightTransferred && preflight.abortErr == nil {
		return sandboxruntime.JobCredentialCleanupProof{}, sandboxruntime.ErrJobCredentialTransition
	}
	return preflight.cleanupProof, preflight.abortErr
}

func (preflight *l8JobCredentialRuntimePreflight) revertPrepare() {
	preflight.mu.Lock()
	defer preflight.mu.Unlock()
	if preflight.state == l8JobCredentialPreflightPreparing {
		preflight.state = l8JobCredentialPreflightOpen
	}
}

func (preflight *l8JobCredentialRuntimePreflight) watchLoss() {
	defer close(preflight.watchDone)
	if preflight.session == nil {
		return
	}
	select {
	case <-preflight.session.Loss():
		preflight.emitLoss(sandboxruntime.JobCredentialFailureGuestHelperUnavailable)
	case <-preflight.stopWatch:
	}
}

func (preflight *l8JobCredentialRuntimePreflight) emitLoss(code sandboxruntime.JobCredentialFailureCode) {
	preflight.lossOnce.Do(func() {
		preflight.mu.Lock()
		preflight.lossLatched = true
		identity := cloneL8JobCredentialIdentity(preflight.identity)
		revision := preflight.currentRevision
		if revision == 0 {
			revision = 1
		}
		preflight.mu.Unlock()
		preflight.loss <- sandboxruntime.JobCredentialLoss{Identity: identity, Revision: revision, Code: code}
		close(preflight.loss)
	})
}

func (preflight *l8JobCredentialRuntimePreflight) stopLossWatch() {
	preflight.stopOnce.Do(func() {
		if preflight.stopWatch != nil {
			close(preflight.stopWatch)
		}
	})
	if preflight.watchDone != nil {
		<-preflight.watchDone
	}
}

func (session *l8JobCredentialRuntimeSession) ExecBinding() sandboxruntime.JobCredentialExecBinding {
	if session == nil {
		return nil
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.execBinding
}

func (session *l8JobCredentialRuntimeSession) ActiveProof() sandboxruntime.JobCredentialActiveProof {
	if session == nil {
		return sandboxruntime.JobCredentialActiveProof{}
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.activeProof
}

func (session *l8JobCredentialRuntimeSession) Loss() <-chan sandboxruntime.JobCredentialLoss {
	if session == nil || session.preflight == nil {
		return nil
	}
	return session.preflight.Loss()
}

func (session *l8JobCredentialRuntimeSession) Renew(ctx context.Context) (sandboxruntime.JobCredentialActiveProof, error) {
	if session == nil || l8JobCredentialRuntimeValueIsNil(ctx) {
		return sandboxruntime.JobCredentialActiveProof{}, ErrL8JobCredentialRuntimeInvalid
	}
	session.mu.Lock()
	if session.revoked || sandboxruntime.ActiveProofKind(session.activeProof) == "" {
		session.mu.Unlock()
		return sandboxruntime.JobCredentialActiveProof{}, sandboxruntime.ErrJobCredentialTransition
	}
	identity := cloneL8JobCredentialIdentity(session.identity)
	previousIssued := session.issuedAt
	previousExpiry := session.expiresAt
	revision := session.revision
	guestProofID := session.guestProofID
	resources := session.resources
	guest := session.preflight.session
	nowFn := session.preflight.deps.Now
	session.mu.Unlock()

	now := nowFn().UTC()
	if err := sandboxruntime.ValidateJobCredentialActiveProof(session.ActiveProof(), identity, revision, now); err != nil {
		return sandboxruntime.JobCredentialActiveProof{}, err
	}
	expiresAt, err := l8JobCredentialRuntimeExpiry(identity, guest, now, previousExpiry)
	if err != nil {
		return sandboxruntime.JobCredentialActiveProof{}, err
	}
	if !now.After(previousIssued) || !expiresAt.After(previousExpiry) {
		return sandboxruntime.JobCredentialActiveProof{}, sandboxruntime.ErrJobCredentialRevisionStale
	}
	if err := renewL8JobCredentialResources(ctx, resources); err != nil {
		return sandboxruntime.JobCredentialActiveProof{}, sanitizeL8JobCredentialRuntimeError(err)
	}
	replacement, err := callL8JobCredentialGuestRenew(guest, ctx, identity, revision, expiresAt, guestProofID)
	if err != nil || replacement == "" {
		if err != nil {
			return sandboxruntime.JobCredentialActiveProof{}, sanitizeL8JobCredentialRuntimeError(err)
		}
		return sandboxruntime.JobCredentialActiveProof{}, ErrL8JobCredentialRuntimeInvalid
	}
	proof, err := sandboxruntime.NewJobCredentialActiveProof(sandboxruntime.JobCredentialActiveProofInput{
		ProofID: fmt.Sprintf("active-%d", revision+1), Identity: identity, Revision: revision + 1,
		IssuedAt: now, ExpiresAt: expiresAt,
	})
	if err != nil {
		return sandboxruntime.JobCredentialActiveProof{}, sandboxruntime.ErrJobCredentialProofInvalid
	}

	session.mu.Lock()
	if session.revoked || session.revision != revision {
		session.mu.Unlock()
		return sandboxruntime.JobCredentialActiveProof{}, sandboxruntime.ErrJobCredentialTransition
	}
	session.activeProof = proof
	session.issuedAt = now
	session.expiresAt = expiresAt
	session.revision = revision + 1
	session.guestProofID = replacement
	session.mu.Unlock()
	session.preflight.mu.Lock()
	session.preflight.currentRevision = revision + 1
	session.preflight.mu.Unlock()
	return proof, nil
}

func (session *l8JobCredentialRuntimeSession) Revoke(ctx context.Context, reason sandboxruntime.JobCredentialRevokeReason) (sandboxruntime.JobCredentialCleanupProof, error) {
	if session == nil {
		return sandboxruntime.JobCredentialCleanupProof{}, ErrL8JobCredentialRuntimeInvalid
	}
	session.mu.Lock()
	if session.revoked {
		proof := session.cleanupProof
		session.mu.Unlock()
		return proof, nil
	}
	identity := cloneL8JobCredentialIdentity(session.identity)
	revision := session.revision
	guest := session.preflight.session
	resources := session.resources
	nowFn := session.preflight.deps.Now
	session.mu.Unlock()

	if l8JobCredentialRuntimeValueIsNil(ctx) {
		ctx = context.Background()
	}
	if !l8JobCredentialRuntimeValueIsNil(guest) {
		if _, err := callL8JobCredentialGuestRevoke(guest, ctx, identity, revision, reason); err != nil {
			return sandboxruntime.JobCredentialCleanupProof{}, sanitizeL8JobCredentialRuntimeError(err)
		}
	}
	revokeL8JobCredentialResources(ctx, resources)
	if !l8JobCredentialRuntimeValueIsNil(guest) {
		_ = guest.Close()
	}
	session.preflight.stopLossWatch()
	observed := nowFn().UTC()
	if observed.Before(identity.IssuedAt) {
		observed = identity.IssuedAt
	}
	proof, err := sandboxruntime.NewJobCredentialCleanupProof(sandboxruntime.JobCredentialCleanupProofInput{
		ProofID: fmt.Sprintf("cleanup-%d", revision+1), Identity: identity, Revision: revision + 1,
		RevokedAt: observed, AbsenceInspectedAt: observed,
		AuthorityAbsent: true, ResourcesAbsent: true,
	})
	if err != nil {
		return sandboxruntime.JobCredentialCleanupProof{}, sandboxruntime.ErrJobCredentialProofInvalid
	}
	session.mu.Lock()
	session.revoked = true
	session.activeProof = sandboxruntime.JobCredentialActiveProof{}
	session.cleanupProof = proof
	session.mu.Unlock()
	return proof, nil
}

func (*l8JobCredentialRuntimePreflight) String() string {
	return l8JobCredentialRuntimeValuePlaceholder
}
func (*l8JobCredentialRuntimePreflight) GoString() string {
	return l8JobCredentialRuntimeValuePlaceholder
}
func (*l8JobCredentialRuntimePreflight) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, l8JobCredentialRuntimeValuePlaceholder)
}
func (*l8JobCredentialRuntimePreflight) MarshalJSON() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}
func (*l8JobCredentialRuntimeSession) String() string {
	return l8JobCredentialRuntimeValuePlaceholder
}
func (*l8JobCredentialRuntimeSession) GoString() string {
	return l8JobCredentialRuntimeValuePlaceholder
}
func (*l8JobCredentialRuntimeSession) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, l8JobCredentialRuntimeValuePlaceholder)
}
func (*l8JobCredentialRuntimeSession) MarshalJSON() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}
func (l8JobCredentialExecBinding) String() string { return l8JobCredentialRuntimeValuePlaceholder }
func (l8JobCredentialExecBinding) MarshalJSON() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
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
	case errors.Is(err, ErrL8JobCredentialRuntimeUnavailable):
		return ErrL8JobCredentialRuntimeUnavailable
	default:
		return ErrL8JobCredentialRuntimeUnavailable
	}
}

func callL8JobCredentialGuestSessionOpener(opener l8JobCredentialGuestSessionOpener, ctx context.Context, seed sandboxruntime.JobCredentialIdentitySeed) (session l8JobCredentialGuestSession, err error) {
	defer func() {
		if recover() != nil {
			session = nil
			err = ErrL8JobCredentialRuntimeUnavailable
		}
	}()
	if l8JobCredentialRuntimeValueIsNil(opener) {
		return nil, ErrL8JobCredentialRuntimeInvalid
	}
	return opener.Open(ctx, seed)
}

func callL8JobCredentialGuestPrepare(session l8JobCredentialGuestSession, ctx context.Context, identity sandboxruntime.JobCredentialIdentity, expiresAt time.Time, manifests []l8JobCredentialGuestBindingManifest) (result l8JobCredentialGuestPrepareResult, err error) {
	defer func() {
		if recover() != nil {
			result = l8JobCredentialGuestPrepareResult{}
			err = ErrL8JobCredentialRuntimeUnavailable
		}
	}()
	if l8JobCredentialRuntimeValueIsNil(session) {
		return l8JobCredentialGuestPrepareResult{}, ErrL8JobCredentialRuntimeInvalid
	}
	return session.Prepare(ctx, identity, expiresAt, manifests)
}

func callL8JobCredentialGuestRenew(session l8JobCredentialGuestSession, ctx context.Context, identity sandboxruntime.JobCredentialIdentity, revision uint64, expiresAt time.Time, priorProofID string) (replacement string, err error) {
	defer func() {
		if recover() != nil {
			replacement = ""
			err = ErrL8JobCredentialRuntimeUnavailable
		}
	}()
	if l8JobCredentialRuntimeValueIsNil(session) {
		return "", ErrL8JobCredentialRuntimeInvalid
	}
	return session.Renew(ctx, identity, revision, expiresAt, priorProofID)
}

func callL8JobCredentialGuestRevoke(session l8JobCredentialGuestSession, ctx context.Context, identity sandboxruntime.JobCredentialIdentity, revision uint64, reason sandboxruntime.JobCredentialRevokeReason) (proofID string, err error) {
	defer func() {
		if recover() != nil {
			proofID = ""
			err = ErrL8JobCredentialRuntimeUnavailable
		}
	}()
	if l8JobCredentialRuntimeValueIsNil(session) {
		return "", ErrL8JobCredentialRuntimeInvalid
	}
	return session.Revoke(ctx, identity, revision, reason)
}

func cloneL8JobCredentialIdentity(identity sandboxruntime.JobCredentialIdentity) sandboxruntime.JobCredentialIdentity {
	identity.BindingIDs = append([]string(nil), identity.BindingIDs...)
	identity.DeliveryModes = append([]sandboxruntime.JobCredentialDeliveryMode(nil), identity.DeliveryModes...)
	return identity
}

func sameL8JobCredentialIdentity(left, right sandboxruntime.JobCredentialIdentity) bool {
	leftDigest, leftErr := sandboxruntime.JobCredentialIdentityDigest(left)
	rightDigest, rightErr := sandboxruntime.JobCredentialIdentityDigest(right)
	return leftErr == nil && rightErr == nil && leftDigest == rightDigest
}

func l8JobCredentialRuntimeExpiry(identity sandboxruntime.JobCredentialIdentity, session l8JobCredentialGuestSession, issuedAt, previousExpiry time.Time) (time.Time, error) {
	if issuedAt.IsZero() || issuedAt.Before(identity.IssuedAt) {
		return time.Time{}, sandboxruntime.ErrJobCredentialProofInvalid
	}
	lifetime := 20 * time.Minute
	if !previousExpiry.IsZero() {
		lifetime = 30 * time.Minute
	}
	expiresAt := issuedAt.Add(lifetime)
	maxExpiry := identity.IssuedAt.Add(sandboxruntime.MaxJobCredentialLifetime)
	if expiresAt.After(maxExpiry) {
		expiresAt = maxExpiry
	}
	sessionCap := identity.IssuedAt.Add(l8JobCredentialRuntimeSessionLifetime)
	if !l8JobCredentialRuntimeValueIsNil(session) {
		if hard := session.HardExpiry(); !hard.IsZero() && hard.Before(sessionCap) {
			sessionCap = hard
		}
	}
	if expiresAt.After(sessionCap) {
		expiresAt = sessionCap
	}
	if !expiresAt.After(issuedAt) || expiresAt.Sub(identity.IssuedAt) > sandboxruntime.MaxJobCredentialLifetime {
		return time.Time{}, sandboxruntime.ErrJobCredentialProofInvalid
	}
	if !previousExpiry.IsZero() && !expiresAt.After(previousExpiry) {
		return time.Time{}, sandboxruntime.ErrJobCredentialRevisionStale
	}
	return expiresAt, nil
}

func validateL8JobCredentialPrepareRequest(identity sandboxruntime.JobCredentialIdentity, request sandboxruntime.JobCredentialPrepareRequest) error {
	if sandboxruntime.ValidateJobCredentialIdentity(request.Identity) != nil || !sameL8JobCredentialIdentity(identity, request.Identity) {
		return sandboxruntime.ErrJobCredentialIdentityMismatch
	}
	if l8JobCredentialRuntimeValueIsNil(request.Authorization) {
		return ErrL8JobCredentialRuntimeInvalid
	}
	admission := request.Admission
	if admission.GrantID != identity.AdmissionGrantID || admission.GrantRevision != identity.AdmissionGrantRevision ||
		admission.PlanID != identity.PlanID || admission.TemplatePolicyID != identity.TemplatePolicyID ||
		admission.WorkspacePolicyID != identity.WorkspacePolicyID ||
		!sameL8JobCredentialAdmissionIdentity(identity, admission.Identity) {
		return sandboxruntime.ErrJobCredentialIdentityMismatch
	}
	if len(admission.Bindings) != len(identity.BindingIDs) {
		return sandboxruntime.ErrJobCredentialIdentityMismatch
	}
	needed := make(map[string]struct{}, len(identity.BindingIDs))
	for index, binding := range admission.Bindings {
		if binding.ID != identity.BindingIDs[index] {
			return sandboxruntime.ErrJobCredentialIdentityMismatch
		}
		if !validL8JobCredentialProductionMode(binding.Mode) {
			return ErrL8JobCredentialRuntimeInvalid
		}
		if binding.Mode != identity.DeliveryModes[index] {
			return sandboxruntime.ErrJobCredentialIdentityMismatch
		}
		if binding.Mode != sandboxruntime.JobCredentialDeliveryModeSSHAgent {
			if binding.SourceReferenceID == "" {
				return ErrL8JobCredentialRuntimeInvalid
			}
			needed[binding.SourceReferenceID] = struct{}{}
		}
	}
	seen := make(map[string]struct{}, len(request.AuthorizedSources))
	for _, source := range request.AuthorizedSources {
		if _, required := needed[source.ReferenceID]; !required || l8JobCredentialRuntimeValueIsNil(source.Source) {
			return ErrL8JobCredentialRuntimeInvalid
		}
		if _, duplicate := seen[source.ReferenceID]; duplicate {
			return ErrL8JobCredentialRuntimeInvalid
		}
		seen[source.ReferenceID] = struct{}{}
	}
	if len(seen) != len(needed) {
		return ErrL8JobCredentialRuntimeInvalid
	}
	return nil
}

func sameL8JobCredentialAdmissionIdentity(identity sandboxruntime.JobCredentialIdentity, admission sandboxruntime.JobCredentialAdmissionIdentity) bool {
	return admission.SandboxID == identity.SandboxID && admission.ExecutionID == identity.ExecutionID &&
		admission.WorkerID == identity.WorkerID && admission.HostID == identity.HostID &&
		admission.RuntimeDriver == identity.RuntimeDriver && admission.RuntimeID == identity.RuntimeID &&
		admission.RuntimeGeneration == identity.RuntimeGeneration &&
		admission.FirecrackerProcessGeneration == identity.FirecrackerProcessGeneration &&
		admission.VsockGeneration == identity.VsockGeneration && admission.WorkerJobID == identity.WorkerJobID &&
		admission.SubmissionID == identity.SubmissionID && admission.PlanID == identity.PlanID &&
		admission.ActivationGeneration == identity.ActivationGeneration &&
		admission.CredentialGeneration == identity.CredentialGeneration &&
		admission.NetworkPlanID == identity.NetworkPlanID && admission.PolicySnapshotID == identity.PolicySnapshotID &&
		admission.ProxySessionID == identity.ProxySessionID && admission.ProxyGenerationID == identity.ProxyGenerationID &&
		admission.TopologyGenerationID == identity.TopologyGenerationID &&
		admission.RuleGenerationID == identity.RuleGenerationID && admission.IssuedAt.Equal(identity.IssuedAt)
}

func validL8JobCredentialProductionMode(mode sandboxruntime.JobCredentialDeliveryMode) bool {
	switch mode {
	case sandboxruntime.JobCredentialDeliveryModeHTTPProxy, sandboxruntime.JobCredentialDeliveryModeFileTmpfs, sandboxruntime.JobCredentialDeliveryModeSSHAgent:
		return true
	default:
		return false
	}
}

func activateL8JobCredentialBindings(ctx context.Context, deps l8JobCredentialRuntimeDependencies, identity sandboxruntime.JobCredentialIdentity, request sandboxruntime.JobCredentialPrepareRequest) (*l8JobCredentialPreparedResources, error) {
	resources := &l8JobCredentialPreparedResources{}
	sources := make(map[string]sandboxruntime.LiveSecretSource, len(request.AuthorizedSources))
	for _, source := range request.AuthorizedSources {
		sources[source.ReferenceID] = source.Source
	}
	for _, binding := range request.Admission.Bindings {
		manifest := l8JobCredentialGuestBindingManifest{BindingID: binding.ID, Mode: binding.Mode}
		switch binding.Mode {
		case sandboxruntime.JobCredentialDeliveryModeHTTPProxy:
			if l8JobCredentialRuntimeValueIsNil(deps.HTTPProxy) {
				return resources, ErrL8JobCredentialRuntimeInvalid
			}
			handle, err := deps.HTTPProxy.Activate(ctx, identity, binding, sources[binding.SourceReferenceID])
			if err != nil || l8JobCredentialRuntimeValueIsNil(handle) {
				if err != nil {
					return resources, err
				}
				return resources, ErrL8JobCredentialRuntimeInvalid
			}
			resources.http = append(resources.http, handle)
			manifest.ServiceID = handle.ServiceID()
			if manifest.ServiceID == "" {
				manifest.ServiceID = binding.ServiceID
			}
		case sandboxruntime.JobCredentialDeliveryModeFileTmpfs:
			if l8JobCredentialRuntimeValueIsNil(deps.FileTmpfs) {
				return resources, ErrL8JobCredentialRuntimeInvalid
			}
			handle, err := deps.FileTmpfs.Materialize(ctx, identity, binding, sources[binding.SourceReferenceID])
			if err != nil || l8JobCredentialRuntimeValueIsNil(handle) {
				if err != nil {
					return resources, err
				}
				return resources, ErrL8JobCredentialRuntimeInvalid
			}
			resources.files = append(resources.files, handle)
			manifest.TargetPath = handle.TargetPath()
			manifest.DeclaredFileBytes = handle.DeclaredFileBytes()
			manifest.FileSHA256 = handle.FileSHA256()
		case sandboxruntime.JobCredentialDeliveryModeSSHAgent:
			if l8JobCredentialRuntimeValueIsNil(deps.SSHRelay) {
				return resources, ErrL8JobCredentialRuntimeInvalid
			}
			handle, err := deps.SSHRelay.Activate(ctx, identity, binding)
			if err != nil || l8JobCredentialRuntimeValueIsNil(handle) {
				if err != nil {
					return resources, err
				}
				return resources, ErrL8JobCredentialRuntimeInvalid
			}
			resources.ssh = append(resources.ssh, handle)
			manifest.SSHPolicyID = handle.PolicyID()
			manifest.SSHPolicyRevision = handle.PolicyRevision()
		default:
			return resources, ErrL8JobCredentialRuntimeInvalid
		}
		resources.manifests = append(resources.manifests, manifest)
	}
	return resources, nil
}

func renewL8JobCredentialResources(ctx context.Context, resources *l8JobCredentialPreparedResources) error {
	if resources == nil {
		return nil
	}
	for _, handle := range resources.http {
		if err := handle.Renew(ctx); err != nil {
			return err
		}
	}
	for _, handle := range resources.ssh {
		if err := handle.Renew(ctx); err != nil {
			return err
		}
	}
	return nil
}

func revokeL8JobCredentialResources(ctx context.Context, resources *l8JobCredentialPreparedResources) {
	if resources == nil {
		return
	}
	if l8JobCredentialRuntimeValueIsNil(ctx) {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
	}
	for index := len(resources.http) - 1; index >= 0; index-- {
		_ = resources.http[index].Revoke(ctx)
	}
	for index := len(resources.files) - 1; index >= 0; index-- {
		_ = resources.files[index].Revoke(ctx)
	}
	for index := len(resources.ssh) - 1; index >= 0; index-- {
		_ = resources.ssh[index].Revoke(ctx)
	}
}

var (
	_ sandboxruntime.JobCredentialRuntime          = (*L8JobCredentialRuntime)(nil)
	_ sandboxruntime.JobCredentialRuntimePreflight = (*l8JobCredentialRuntimePreflight)(nil)
	_ sandboxruntime.JobCredentialSession          = (*l8JobCredentialRuntimeSession)(nil)
	_ fmt.Stringer                                 = (*L8JobCredentialRuntime)(nil)
)

const l8JobCredentialRuntimeSessionLifetime = guestsession.MaxGuestCredentialSessionLifetime
