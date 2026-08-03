package sandboxruntime

import "fmt"

func (*AuthenticatedWorkerPrincipalAuthority) String() string {
	return "<sandboxruntime.AuthenticatedWorkerPrincipalAuthority>"
}

func (*AuthenticatedWorkerPrincipalAuthority) GoString() string {
	return "<sandboxruntime.AuthenticatedWorkerPrincipalAuthority>"
}

func (*AuthenticatedWorkerPrincipalAuthority) MarshalJSON() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

func (*AuthenticatedWorkerPrincipalAuthority) MarshalText() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

func (*AuthenticatedWorkerPrincipalAuthority) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "<sandboxruntime.AuthenticatedWorkerPrincipalAuthority>")
}

func (*authenticatedWorkerPrincipal) String() string {
	return "<sandboxruntime.authenticatedWorkerPrincipal>"
}

func (*authenticatedWorkerPrincipal) GoString() string {
	return "<sandboxruntime.authenticatedWorkerPrincipal>"
}

func (*authenticatedWorkerPrincipal) MarshalJSON() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

func (*authenticatedWorkerPrincipal) MarshalText() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

func (*authenticatedWorkerPrincipal) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "<sandboxruntime.authenticatedWorkerPrincipal>")
}

func (*JobCredentialLifecycle) String() string {
	return "<sandboxruntime.JobCredentialLifecycle>"
}

func (*JobCredentialLifecycle) GoString() string {
	return "<sandboxruntime.JobCredentialLifecycle>"
}

func (*JobCredentialLifecycle) MarshalJSON() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

func (*JobCredentialLifecycle) MarshalText() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

func (*JobCredentialLifecycle) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "<sandboxruntime.JobCredentialLifecycle>")
}

func (JobCredentialActiveProof) String() string {
	return "<sandboxruntime.JobCredentialActiveProof>"
}

func (JobCredentialActiveProof) GoString() string {
	return "<sandboxruntime.JobCredentialActiveProof>"
}

func (JobCredentialActiveProof) MarshalJSON() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

func (JobCredentialActiveProof) MarshalText() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

func (JobCredentialActiveProof) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "<sandboxruntime.JobCredentialActiveProof>")
}

func (JobCredentialCleanupProof) String() string {
	return "<sandboxruntime.JobCredentialCleanupProof>"
}

func (JobCredentialCleanupProof) GoString() string {
	return "<sandboxruntime.JobCredentialCleanupProof>"
}

func (JobCredentialCleanupProof) MarshalJSON() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

func (JobCredentialCleanupProof) MarshalText() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

func (JobCredentialCleanupProof) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "<sandboxruntime.JobCredentialCleanupProof>")
}
