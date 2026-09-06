//go:build !linux

package firecrackerhost

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8JobCredentialRuntimeNonLinuxFailsClosedBeforeSession(t *testing.T) {
	if l8JobCredentialRuntimePlatformSupported() {
		t.Fatal("non-Linux job credential runtime reported support")
	}
	now := time.Date(2026, time.August, 28, 4, 5, 6, 0, time.UTC)
	opener := &l8JobCredentialGuestSessionOpenerFake{session: l8JobCredentialGuestSessionFakeForTest(t, now)}
	runtime, err := NewProductionL8JobCredentialRuntime(l8JobCredentialRuntimeDependencies{
		GuestSession: opener,
		Now:          func() time.Time { return now },
		Random:       bytesReaderForTest(),
	})
	if runtime != nil || !errors.Is(err, ErrL8JobCredentialRuntimeUnsupported) {
		t.Fatalf("production constructor = %#v, %v", runtime, err)
	}
	if opener.calls != 0 {
		t.Fatalf("non-Linux constructor opened a guest session: calls=%d", opener.calls)
	}

	production := &L8JobCredentialRuntime{
		deps: l8JobCredentialRuntimeDependencies{
			GuestSession: opener,
			Now:          func() time.Time { return now },
			Random:       bytesReaderForTest(),
		},
		production: true,
	}
	seed := l8JobCredentialRuntimeSeed(t, now, []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeFileTmpfs})
	preflight, preflightErr := production.PreflightJobCredentials(context.Background(), seed)
	if preflight != nil || !errors.Is(preflightErr, ErrL8JobCredentialRuntimeUnsupported) {
		t.Fatalf("non-Linux production preflight = %#v, %v", preflight, preflightErr)
	}
	if opener.calls != 0 {
		t.Fatalf("non-Linux production preflight opened a guest session: calls=%d", opener.calls)
	}

	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, l8JobCredentialRuntimeGuestSessionGeneration(), "helper-generation-runtime")
	if err != nil {
		t.Fatal(err)
	}
	proof, recoverErr := production.RecoverJobCredentials(context.Background(), sandboxruntime.JobCredentialRecoveryRequest{
		Identity: identity, Revision: 1,
	})
	if sandboxruntime.CleanupProofKind(proof) != "" || !errors.Is(recoverErr, ErrL8JobCredentialRuntimeUnsupported) {
		t.Fatalf("non-Linux production recover = %#v, %v", proof, recoverErr)
	}
	if opener.calls != 0 {
		t.Fatalf("non-Linux production recover opened a guest session: calls=%d", opener.calls)
	}
}
