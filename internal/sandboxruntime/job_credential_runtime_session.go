package sandboxruntime

import (
	"context"
	"errors"
	"fmt"
)

// JobCredentialSessionBinding retains one transferred session and the
// worker-owned loss latch started during preflight.
type JobCredentialSessionBinding struct {
	session  JobCredentialSession
	identity JobCredentialIdentity
	loss     *jobCredentialRuntimeLossLatch
}

func (binding *JobCredentialRuntimePreflightBinding) Prepare(ctx context.Context, request JobCredentialPrepareRequest) (*JobCredentialSessionBinding, error) {
	if binding == nil || jobCredentialBindingValueIsNil(ctx) {
		return nil, ErrJobCredentialRuntimeBindingUnavailable
	}
	if ValidateJobCredentialIdentity(request.Identity) != nil || !sameJobCredentialIdentity(request.Identity, binding.identity) {
		return nil, ErrJobCredentialIdentityMismatch
	}
	session, err := callJobCredentialRuntimePreflightPrepare(binding.preflight, ctx, request)
	if err != nil {
		if !jobCredentialBindingValueIsNil(session) {
			return nil, ErrJobCredentialRuntimeBindingInvalid
		}
		if errors.Is(err, ErrJobCredentialTransition) {
			return nil, ErrJobCredentialTransition
		}
		return nil, ErrJobCredentialRuntimeBindingUnavailable
	}
	if jobCredentialBindingValueIsNil(session) {
		return nil, ErrJobCredentialRuntimeBindingInvalid
	}
	return &JobCredentialSessionBinding{
		session:  session,
		identity: cloneJobCredentialIdentity(binding.identity),
		loss:     binding.loss,
	}, nil
}

func (binding *JobCredentialSessionBinding) ActiveProof() JobCredentialActiveProof {
	if binding == nil || jobCredentialBindingValueIsNil(binding.session) {
		return JobCredentialActiveProof{}
	}
	return callJobCredentialSessionActiveProof(binding.session)
}

func (binding *JobCredentialSessionBinding) Renew(ctx context.Context) (JobCredentialActiveProof, error) {
	if binding == nil || jobCredentialBindingValueIsNil(ctx) || jobCredentialBindingValueIsNil(binding.session) {
		return JobCredentialActiveProof{}, ErrJobCredentialRuntimeBindingUnavailable
	}
	proof, err := callJobCredentialSessionRenew(binding.session, ctx)
	if err != nil || ActiveProofKind(proof) == "" {
		return JobCredentialActiveProof{}, ErrJobCredentialRuntimeBindingUnavailable
	}
	return proof, nil
}

func (binding *JobCredentialSessionBinding) Revoke(ctx context.Context, reason JobCredentialRevokeReason) (JobCredentialCleanupProof, error) {
	if binding == nil || jobCredentialBindingValueIsNil(ctx) || jobCredentialBindingValueIsNil(binding.session) {
		return JobCredentialCleanupProof{}, ErrJobCredentialRuntimeCleanupIncomplete
	}
	proof, err := callJobCredentialSessionRevoke(binding.session, ctx, reason)
	if err != nil || CleanupProofKind(proof) == "" {
		return JobCredentialCleanupProof{}, ErrJobCredentialRuntimeCleanupIncomplete
	}
	return proof, nil
}

func (binding *JobCredentialSessionBinding) Loss() <-chan JobCredentialLoss {
	if binding == nil || binding.loss == nil {
		return nil
	}
	return binding.loss.output
}

func callJobCredentialRuntimePreflightPrepare(preflight JobCredentialRuntimePreflight, ctx context.Context, request JobCredentialPrepareRequest) (session JobCredentialSession, err error) {
	defer func() {
		if recover() != nil {
			session = nil
			err = ErrJobCredentialRuntimeBindingUnavailable
		}
	}()
	return preflight.PrepareJobCredentials(ctx, request)
}

func callJobCredentialSessionActiveProof(session JobCredentialSession) (proof JobCredentialActiveProof) {
	defer func() {
		if recover() != nil {
			proof = JobCredentialActiveProof{}
		}
	}()
	return session.ActiveProof()
}

func callJobCredentialSessionRenew(session JobCredentialSession, ctx context.Context) (proof JobCredentialActiveProof, err error) {
	defer func() {
		if recover() != nil {
			proof = JobCredentialActiveProof{}
			err = ErrJobCredentialRuntimeBindingUnavailable
		}
	}()
	return session.Renew(ctx)
}

func callJobCredentialSessionRevoke(session JobCredentialSession, ctx context.Context, reason JobCredentialRevokeReason) (proof JobCredentialCleanupProof, err error) {
	defer func() {
		if recover() != nil {
			proof = JobCredentialCleanupProof{}
			err = ErrJobCredentialRuntimeCleanupIncomplete
		}
	}()
	return session.Revoke(ctx, reason)
}

func (*JobCredentialSessionBinding) String() string {
	return "<sandboxruntime.JobCredentialSessionBinding>"
}

func (*JobCredentialSessionBinding) GoString() string {
	return "<sandboxruntime.JobCredentialSessionBinding>"
}

func (*JobCredentialSessionBinding) MarshalJSON() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

func (*JobCredentialSessionBinding) MarshalText() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

func (*JobCredentialSessionBinding) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "<sandboxruntime.JobCredentialSessionBinding>")
}

// JobCredentialRuntimeInterfaceNil reports missing and typed-nil interfaces
// without exposing implementation identity.
func JobCredentialRuntimeInterfaceNil(value any) bool {
	return jobCredentialBindingValueIsNil(value)
}
