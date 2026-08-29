package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8JobCredentialRuntimeMintsActiveProofFromAdmittedHelperSuccess(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	issuedAt := now.Add(time.Second)
	seed, identity, request := l8JobCredentialRuntimePrepareFixture(t, now)
	guest := l8JobCredentialGuestSessionFakeForTest(t, now)
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest},
		&l8JobCredentialHTTPProxyFake{}, &l8JobCredentialFileTmpfsFake{payload: []byte("file-bytes")}, nil)
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	session, err := preflight.PrepareJobCredentials(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt, err := l8JobCredentialRuntimeExpiry(identity, guest, issuedAt, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	want, err := sandboxruntime.NewJobCredentialActiveProof(sandboxruntime.JobCredentialActiveProofInput{
		ProofID: "guest-active-1", Identity: identity, Revision: 1, IssuedAt: issuedAt, ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.ActiveProof() != want {
		t.Fatal("prepare minted an invented active proof instead of the admitted helper success identity")
	}
	if err := sandboxruntime.ValidateJobCredentialActiveProof(session.ActiveProof(), identity, 1, issuedAt); err != nil {
		t.Fatalf("admitted helper active proof: %v", err)
	}
}

func TestL8JobCredentialRuntimeRenewMintsActiveProofFromAdmittedHelperSuccess(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	clock := &l8JobCredentialRuntimeClock{now: now.Add(time.Second)}
	seed, identity, request := l8JobCredentialRuntimePrepareFixture(t, now)
	guest := l8JobCredentialGuestSessionFakeForTest(t, now)
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest},
		&l8JobCredentialHTTPProxyFake{}, &l8JobCredentialFileTmpfsFake{payload: []byte("file-bytes")}, nil)
	runtime.deps.Now = clock.Now
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	session, err := preflight.PrepareJobCredentials(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	prepareExpiry, err := l8JobCredentialRuntimeExpiry(identity, guest, now.Add(time.Second), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	clock.now = now.Add(2 * time.Second)
	renewed, err := session.Renew(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expiresAt, err := l8JobCredentialRuntimeExpiry(identity, guest, clock.now, prepareExpiry)
	if err != nil {
		t.Fatal(err)
	}
	want, err := sandboxruntime.NewJobCredentialActiveProof(sandboxruntime.JobCredentialActiveProofInput{
		ProofID: "guest-active-2", Identity: identity, Revision: 2, IssuedAt: clock.now, ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if renewed != want {
		t.Fatal("renew minted an invented active proof instead of the admitted helper replacement identity")
	}
}

func TestL8JobCredentialRuntimeRevokeMintsCleanupProofFromAdmittedHelperSuccess(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	issuedAt := now.Add(time.Second)
	seed, identity, request := l8JobCredentialRuntimePrepareFixture(t, now)
	guest := l8JobCredentialGuestSessionFakeForTest(t, now)
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest},
		&l8JobCredentialHTTPProxyFake{}, &l8JobCredentialFileTmpfsFake{payload: []byte("file-bytes")}, nil)
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	session, err := preflight.PrepareJobCredentials(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := session.Revoke(context.Background(), sandboxruntime.JobCredentialRevokeReason("requested"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := sandboxruntime.NewJobCredentialCleanupProof(sandboxruntime.JobCredentialCleanupProofInput{
		ProofID: "guest-cleanup-1", Identity: identity, Revision: 2,
		RevokedAt: issuedAt, AbsenceInspectedAt: issuedAt, AuthorityAbsent: true, ResourcesAbsent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cleanup != want {
		t.Fatal("revoke minted an invented cleanup proof instead of the admitted helper cleanup identity")
	}
}

func TestL8JobCredentialRuntimeMissingHelperProofIDIsDependencyUnaccepted(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	seed, _, request := l8JobCredentialRuntimePrepareFixture(t, now)
	guest := l8JobCredentialGuestSessionFakeForTest(t, now)
	guest.omitActiveProofID = true
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest},
		&l8JobCredentialHTTPProxyFake{}, &l8JobCredentialFileTmpfsFake{payload: []byte("file-bytes")}, nil)
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	session, prepareErr := preflight.PrepareJobCredentials(context.Background(), request)
	if !l8JobCredentialRuntimeValueIsNil(session) || !errors.Is(prepareErr, errL8JobCredentialRuntimeDependencyUnaccepted) {
		t.Fatalf("missing helper active proof = %#v, %v", session, prepareErr)
	}
	if prepareErr.Error() != "dependency_unaccepted" {
		t.Fatalf("missing helper active proof error = %q", prepareErr)
	}
	l8JobCredentialRuntimeAssertSafeError(t, prepareErr)

	guest = l8JobCredentialGuestSessionFakeForTest(t, now)
	clock := &l8JobCredentialRuntimeClock{now: now.Add(time.Second)}
	runtime = l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest},
		&l8JobCredentialHTTPProxyFake{}, &l8JobCredentialFileTmpfsFake{payload: []byte("file-bytes")}, nil)
	runtime.deps.Now = clock.Now
	preflight, err = runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	session, err = preflight.PrepareJobCredentials(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	guest.omitRenewProofID = true
	clock.now = now.Add(2 * time.Second)
	renewed, renewErr := session.Renew(context.Background())
	if sandboxruntime.ActiveProofKind(renewed) != "" || !errors.Is(renewErr, errL8JobCredentialRuntimeDependencyUnaccepted) {
		t.Fatalf("missing helper renew proof = %#v, %v", renewed, renewErr)
	}
	l8JobCredentialRuntimeAssertSafeError(t, renewErr)

	guest = l8JobCredentialGuestSessionFakeForTest(t, now)
	runtime = l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest},
		&l8JobCredentialHTTPProxyFake{}, &l8JobCredentialFileTmpfsFake{payload: []byte("file-bytes")}, nil)
	preflight, err = runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	session, err = preflight.PrepareJobCredentials(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	guest.omitRevokeProofID = true
	cleanup, revokeErr := session.Revoke(context.Background(), sandboxruntime.JobCredentialRevokeReason("requested"))
	if sandboxruntime.CleanupProofKind(cleanup) != "" || !errors.Is(revokeErr, errL8JobCredentialRuntimeDependencyUnaccepted) {
		t.Fatalf("missing helper revoke proof = %#v, %v", cleanup, revokeErr)
	}
	l8JobCredentialRuntimeAssertSafeError(t, revokeErr)
}

func TestL8JobCredentialRuntimeProofMintFailsClosedOnIdentityAndRevisionMismatch(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	_, identity, _ := l8JobCredentialRuntimePrepareFixture(t, now)
	issuedAt := now.Add(time.Second)
	expiresAt := issuedAt.Add(20 * time.Minute)

	proof, err := mintL8JobCredentialActiveProofFromAdmittedHelperSuccess("", identity, 1, issuedAt, expiresAt, issuedAt)
	if sandboxruntime.ActiveProofKind(proof) != "" || !errors.Is(err, errL8JobCredentialRuntimeDependencyUnaccepted) {
		t.Fatalf("empty helper identity = %#v, %v", proof, err)
	}
	proof, err = mintL8JobCredentialActiveProofFromAdmittedHelperSuccess("guest-active-1", sandboxruntime.JobCredentialIdentity{}, 1, issuedAt, expiresAt, issuedAt)
	if sandboxruntime.ActiveProofKind(proof) != "" || !errors.Is(err, sandboxruntime.ErrJobCredentialIdentityMismatch) {
		t.Fatalf("invalid identity = %#v, %v", proof, err)
	}
	proof, err = mintL8JobCredentialActiveProofFromAdmittedHelperSuccess("guest-active-1", identity, 0, issuedAt, expiresAt, issuedAt)
	if sandboxruntime.ActiveProofKind(proof) != "" || !errors.Is(err, sandboxruntime.ErrJobCredentialRevisionStale) {
		t.Fatalf("zero revision = %#v, %v", proof, err)
	}
	neighbor := identity
	neighbor.WorkerJobID = "job-neighbor"
	minted, err := mintL8JobCredentialActiveProofFromAdmittedHelperSuccess("guest-active-1", identity, 1, issuedAt, expiresAt, issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxruntime.ValidateJobCredentialActiveProof(minted, neighbor, 1, issuedAt); !errors.Is(err, sandboxruntime.ErrJobCredentialIdentityMismatch) {
		t.Fatalf("neighbor identity validation = %v", err)
	}
	if err := sandboxruntime.ValidateJobCredentialActiveProof(minted, identity, 2, issuedAt); !errors.Is(err, sandboxruntime.ErrJobCredentialRevisionStale) {
		t.Fatalf("stale revision validation = %v", err)
	}

	cleanup, err := mintL8JobCredentialCleanupProofFromAdmittedHelperSuccess("", identity, 2, issuedAt)
	if sandboxruntime.CleanupProofKind(cleanup) != "" || !errors.Is(err, errL8JobCredentialRuntimeDependencyUnaccepted) {
		t.Fatalf("empty helper cleanup identity = %#v, %v", cleanup, err)
	}
	cleanup, err = mintL8JobCredentialCleanupProofFromAdmittedHelperSuccess("guest-cleanup-1", sandboxruntime.JobCredentialIdentity{}, 2, issuedAt)
	if sandboxruntime.CleanupProofKind(cleanup) != "" || !errors.Is(err, sandboxruntime.ErrJobCredentialIdentityMismatch) {
		t.Fatalf("invalid cleanup identity = %#v, %v", cleanup, err)
	}
	cleanup, err = mintL8JobCredentialCleanupProofFromAdmittedHelperSuccess("guest-cleanup-1", identity, 0, issuedAt)
	if sandboxruntime.CleanupProofKind(cleanup) != "" || !errors.Is(err, sandboxruntime.ErrJobCredentialRevisionStale) {
		t.Fatalf("zero cleanup revision = %#v, %v", cleanup, err)
	}
}

func TestL8JobCredentialRuntimeProofMintDoesNotSerializeLiveSecretBodies(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	seed, _, request := l8JobCredentialRuntimePrepareFixture(t, now)
	guest := l8JobCredentialGuestSessionFakeForTest(t, now)
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest},
		&l8JobCredentialHTTPProxyFake{}, &l8JobCredentialFileTmpfsFake{payload: []byte("secret-bytes")}, nil)
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	session, err := preflight.PrepareJobCredentials(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	proof := session.ActiveProof()
	if encoded, marshalErr := proof.MarshalJSON(); marshalErr == nil || encoded != nil {
		t.Fatalf("active proof JSON = %q, %v", encoded, marshalErr)
	}
	cleanup, err := session.Revoke(context.Background(), sandboxruntime.JobCredentialRevokeReason("requested"))
	if err != nil {
		t.Fatal(err)
	}
	if encoded, marshalErr := cleanup.MarshalJSON(); marshalErr == nil || encoded != nil {
		t.Fatalf("cleanup proof JSON = %q, %v", encoded, marshalErr)
	}
	l8JobCredentialRuntimeAssertSafeError(t, err)
	for _, rendered := range []string{proof.String(), cleanup.String()} {
		if strings.Contains(rendered, "secret-bytes") || strings.Contains(rendered, "sk_live") {
			t.Fatalf("proof format leaked live body %q", rendered)
		}
	}
}

func TestL8JobCredentialRuntimeProofMintDoesNotInventActiveOneLiteral(t *testing.T) {
	source, err := os.ReadFile("l8_job_credential_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, invented := range []string{`ProofID: "active-1"`, `ProofID: fmt.Sprintf("active-%d"`, `ProofID: fmt.Sprintf("cleanup-%d", revision+1)`} {
		if strings.Contains(text, invented) {
			t.Fatalf("production runtime still invents helper-success proof id %q", invented)
		}
	}
	for _, required := range []string{
		"mintL8JobCredentialActiveProofFromAdmittedHelperSuccess",
		"mintL8JobCredentialCleanupProofFromAdmittedHelperSuccess",
		"guestResult.ActiveProofID",
		"errL8JobCredentialRuntimeDependencyUnaccepted",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("production runtime omits helper-success mint marker %q", required)
		}
	}
}
