package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

func TestL8JobCredentialRuntimePublicAPIIsExact(t *testing.T) {
	constructor := reflect.TypeOf(NewProductionL8JobCredentialRuntime)
	wantConstructor := reflect.TypeOf((func(l8JobCredentialRuntimeDependencies) (*L8JobCredentialRuntime, error))(nil))
	if constructor != wantConstructor {
		t.Fatalf("NewProductionL8JobCredentialRuntime type = %v, want %v", constructor, wantConstructor)
	}
	runtimeType := reflect.TypeOf((*L8JobCredentialRuntime)(nil))
	l8D6AssertExactExportedMethodSet(t, runtimeType, map[string]reflect.Type{
		"Format":                  reflect.TypeOf((func(*L8JobCredentialRuntime, fmt.State, rune))(nil)),
		"GoString":                reflect.TypeOf((func(*L8JobCredentialRuntime) string)(nil)),
		"MarshalBinary":           reflect.TypeOf((func(*L8JobCredentialRuntime) ([]byte, error))(nil)),
		"MarshalJSON":             reflect.TypeOf((func(*L8JobCredentialRuntime) ([]byte, error))(nil)),
		"MarshalText":             reflect.TypeOf((func(*L8JobCredentialRuntime) ([]byte, error))(nil)),
		"PreflightJobCredentials": reflect.TypeOf((func(*L8JobCredentialRuntime, context.Context, sandboxruntime.JobCredentialIdentitySeed) (sandboxruntime.JobCredentialRuntimePreflight, error))(nil)),
		"RecoverJobCredentials":   reflect.TypeOf((func(*L8JobCredentialRuntime, context.Context, sandboxruntime.JobCredentialRecoveryRequest) (sandboxruntime.JobCredentialCleanupProof, error))(nil)),
		"String":                  reflect.TypeOf((func(*L8JobCredentialRuntime) string)(nil)),
	})
	var _ sandboxruntime.JobCredentialRuntime = (*L8JobCredentialRuntime)(nil)
}

func TestL8JobCredentialRuntimePreflightCompletesIdentityAndOwnsSlices(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	seed := l8JobCredentialRuntimeSeed(t, now, []sandboxruntime.JobCredentialDeliveryMode{
		sandboxruntime.JobCredentialDeliveryModeHTTPProxy,
		sandboxruntime.JobCredentialDeliveryModeFileTmpfs,
	})
	guest := l8JobCredentialGuestSessionFakeForTest(t, now)
	httpProxy := &l8JobCredentialHTTPProxyFake{}
	tmpfs := &l8JobCredentialFileTmpfsFake{payload: []byte("tmpfs-canary")}
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest}, httpProxy, tmpfs, nil)

	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil || l8JobCredentialRuntimeValueIsNil(preflight) {
		t.Fatalf("PreflightJobCredentials = %#v, %v", preflight, err)
	}
	identity := preflight.Identity()
	if err := sandboxruntime.ValidateJobCredentialIdentityCompletion(seed, identity); err != nil {
		t.Fatalf("preflight identity is not the seed completion: %v", err)
	}
	if identity.GuestSessionGeneration != guest.GuestSessionGeneration() || identity.GuestHelperGeneration != guest.GuestHelperGeneration() {
		t.Fatalf("guest generations = %q/%q, want %q/%q", identity.GuestSessionGeneration, identity.GuestHelperGeneration, guest.GuestSessionGeneration(), guest.GuestHelperGeneration())
	}
	identity.BindingIDs[0] = "caller-mutated"
	identity.DeliveryModes[0] = sandboxruntime.JobCredentialDeliveryModeSSHAgent
	second := preflight.Identity()
	if err := sandboxruntime.ValidateJobCredentialIdentityCompletion(seed, second); err != nil {
		t.Fatalf("Identity retained caller-owned slices: %v", err)
	}
	if second.BindingIDs[0] != seed.BindingIDs[0] || second.DeliveryModes[0] != seed.DeliveryModes[0] {
		t.Fatal("Identity did not return a defensive deep copy")
	}
	if httpProxy.activates != 0 || tmpfs.materializes != 0 {
		t.Fatalf("preflight activated delivery adapters: http=%d tmpfs=%d", httpProxy.activates, tmpfs.materializes)
	}
}

func TestL8JobCredentialRuntimePreflightRejectsPartialStaleAndCrossJobSeed(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	valid := l8JobCredentialRuntimeSeed(t, now, []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeFileTmpfs})
	opener := &l8JobCredentialGuestSessionOpenerFake{session: l8JobCredentialGuestSessionFakeForTest(t, now)}
	runtime := l8JobCredentialRuntimeForTest(t, now, opener, nil, &l8JobCredentialFileTmpfsFake{payload: []byte("x")}, nil)

	partial := valid
	partial.RuntimeGeneration = ""
	if preflight, err := runtime.PreflightJobCredentials(context.Background(), partial); !l8JobCredentialRuntimeValueIsNil(preflight) || !errors.Is(err, sandboxruntime.ErrJobCredentialIdentityMismatch) {
		t.Fatalf("partial seed = %#v, %v", preflight, err)
	}
	if opener.calls != 0 {
		t.Fatal("partial seed opened a guest session")
	}

	neighbor := valid
	neighbor.WorkerJobID = "job-neighbor"
	runtime = l8JobCredentialRuntimeForTest(t, now, opener, nil, &l8JobCredentialFileTmpfsFake{payload: []byte("x")}, nil)
	if _, err := runtime.PreflightJobCredentials(context.Background(), neighbor); err != nil {
		t.Fatalf("neighbor seed preflight setup: %v", err)
	}
}

func TestL8JobCredentialRuntimePrepareTransfersSessionAndIssuesActiveProof(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	seed, identity, request := l8JobCredentialRuntimePrepareFixture(t, now)
	guest := l8JobCredentialGuestSessionFakeForTest(t, now)
	httpProxy := &l8JobCredentialHTTPProxyFake{}
	tmpfs := &l8JobCredentialFileTmpfsFake{payload: []byte("file-bytes")}
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest}, httpProxy, tmpfs, nil)
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}

	session, err := preflight.PrepareJobCredentials(context.Background(), request)
	if err != nil || l8JobCredentialRuntimeValueIsNil(session) {
		t.Fatalf("PrepareJobCredentials = %#v, %v", session, err)
	}
	if httpProxy.activates != 1 || tmpfs.materializes != 1 || guest.prepares != 1 {
		t.Fatalf("prepare activations http=%d tmpfs=%d guest=%d", httpProxy.activates, tmpfs.materializes, guest.prepares)
	}
	proof := session.ActiveProof()
	if err := sandboxruntime.ValidateJobCredentialActiveProof(proof, identity, 1, now.Add(time.Second)); err != nil {
		t.Fatalf("active proof: %v", err)
	}
	if sandboxruntime.ActiveProofKind(proof) == "" {
		t.Fatal("active proof kind is empty")
	}
	if l8JobCredentialRuntimeValueIsNil(session.ExecBinding()) {
		t.Fatal("exec binding was nil")
	}
	if session.Loss() != preflight.Loss() {
		t.Fatal("preflight and session do not expose the same loss latch")
	}
	if second, err := preflight.PrepareJobCredentials(context.Background(), request); !l8JobCredentialRuntimeValueIsNil(second) || !errors.Is(err, sandboxruntime.ErrJobCredentialTransition) {
		t.Fatalf("second prepare = %#v, %v", second, err)
	}
	if proof, err := preflight.Abort(context.Background()); sandboxruntime.CleanupProofKind(proof) != "" || !errors.Is(err, sandboxruntime.ErrJobCredentialTransition) {
		t.Fatalf("abort after transfer = %#v, %v", proof, err)
	}
}

func TestL8JobCredentialRuntimePrepareRejectsEnvLegacyAndSimulatedModes(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	seed, _, request := l8JobCredentialRuntimePrepareFixture(t, now)
	request.Admission.Bindings[0].Mode = "env"
	guest := l8JobCredentialGuestSessionFakeForTest(t, now)
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest}, &l8JobCredentialHTTPProxyFake{}, &l8JobCredentialFileTmpfsFake{payload: []byte("x")}, nil)
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	session, prepareErr := preflight.PrepareJobCredentials(context.Background(), request)
	if !l8JobCredentialRuntimeValueIsNil(session) || prepareErr == nil {
		t.Fatalf("env mode prepare = %#v, %v", session, prepareErr)
	}
	l8JobCredentialRuntimeAssertSafeError(t, prepareErr)
	if guest.prepares != 0 {
		t.Fatal("env/legacy prepare reached the guest session")
	}
	for _, mode := range []sandboxruntime.JobCredentialDeliveryMode{"legacy_auth_sync", "simulated"} {
		request.Admission.Bindings[0].Mode = mode
		if session, err := preflight.PrepareJobCredentials(context.Background(), request); !l8JobCredentialRuntimeValueIsNil(session) || err == nil {
			t.Fatalf("mode %q prepare = %#v, %v", mode, session, err)
		}
	}
}

func TestL8JobCredentialRuntimeAbortIsIdempotentBeforeTransfer(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	seed, identity, request := l8JobCredentialRuntimePrepareFixture(t, now)
	guest := l8JobCredentialGuestSessionFakeForTest(t, now)
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest}, &l8JobCredentialHTTPProxyFake{}, &l8JobCredentialFileTmpfsFake{payload: []byte("x")}, nil)
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	first, err := preflight.Abort(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := preflight.Abort(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("repeated abort did not return the identical cleanup proof")
	}
	if err := sandboxruntime.ValidateJobCredentialCleanupProof(first, identity, 2, now.Add(2*time.Second)); err != nil {
		t.Fatalf("abort cleanup proof: %v", err)
	}
	if session, err := preflight.PrepareJobCredentials(context.Background(), request); !l8JobCredentialRuntimeValueIsNil(session) || !errors.Is(err, sandboxruntime.ErrJobCredentialTransition) {
		t.Fatalf("prepare after abort = %#v, %v", session, err)
	}
	if guest.closed != 1 {
		t.Fatalf("guest session closes = %d, want 1", guest.closed)
	}
}

func TestL8JobCredentialRuntimeSessionRenewRevokeAndReplay(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	clock := &l8JobCredentialRuntimeClock{now: now.Add(time.Second)}
	seed, identity, request := l8JobCredentialRuntimePrepareFixture(t, now)
	guest := l8JobCredentialGuestSessionFakeForTest(t, now)
	httpProxy := &l8JobCredentialHTTPProxyFake{}
	tmpfs := &l8JobCredentialFileTmpfsFake{payload: []byte("file-bytes")}
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest}, httpProxy, tmpfs, nil)
	runtime.deps.Now = clock.Now
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	session, err := preflight.PrepareJobCredentials(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}

	clock.now = now.Add(2 * time.Second)
	renewed, err := session.Renew(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxruntime.ValidateJobCredentialActiveProof(renewed, identity, 2, clock.now); err != nil {
		t.Fatalf("renewed proof: %v", err)
	}
	if session.ActiveProof() != renewed {
		t.Fatal("session did not retain the renewed active proof")
	}
	if httpProxy.renews != 1 || guest.renews != 1 {
		t.Fatalf("renew activations http=%d guest=%d", httpProxy.renews, guest.renews)
	}

	cleanup, err := session.Revoke(context.Background(), sandboxruntime.JobCredentialRevokeReason("requested"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxruntime.ValidateJobCredentialCleanupProof(cleanup, identity, 3, clock.now); err != nil {
		t.Fatalf("revoke cleanup proof: %v", err)
	}
	if sandboxruntime.ActiveProofKind(session.ActiveProof()) != "" {
		t.Fatal("revoked session retained an active proof")
	}
	if httpProxy.revokes != 1 || tmpfs.revokes != 1 || guest.revokes != 1 {
		t.Fatalf("revoke activations http=%d tmpfs=%d guest=%d", httpProxy.revokes, tmpfs.revokes, guest.revokes)
	}
	again, err := session.Revoke(context.Background(), sandboxruntime.JobCredentialRevokeReason("requested"))
	if err != nil {
		t.Fatal(err)
	}
	if again != cleanup {
		t.Fatal("repeated revoke changed the durable cleanup proof")
	}
	if _, err := session.Renew(context.Background()); !errors.Is(err, sandboxruntime.ErrJobCredentialTransition) && !errors.Is(err, sandboxruntime.ErrJobCredentialReplayRejected) {
		t.Fatalf("renew after revoke = %v", err)
	}
}

func TestL8JobCredentialRuntimeFailClosedOnStaleCrossJobAndPartialIdentity(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	seed, identity, request := l8JobCredentialRuntimePrepareFixture(t, now)
	guest := l8JobCredentialGuestSessionFakeForTest(t, now)
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest}, &l8JobCredentialHTTPProxyFake{}, &l8JobCredentialFileTmpfsFake{payload: []byte("x")}, nil)
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}

	cross := request
	cross.Identity.WorkerJobID = "job-neighbor"
	if session, err := preflight.PrepareJobCredentials(context.Background(), cross); !l8JobCredentialRuntimeValueIsNil(session) || !errors.Is(err, sandboxruntime.ErrJobCredentialIdentityMismatch) {
		t.Fatalf("cross-job prepare = %#v, %v", session, err)
	}

	partial := request
	partial.Identity.AdmissionGrantID = ""
	session, prepareErr := preflight.PrepareJobCredentials(context.Background(), partial)
	if !l8JobCredentialRuntimeValueIsNil(session) || prepareErr == nil {
		t.Fatalf("partial identity prepare = %#v, %v", session, prepareErr)
	}
	l8JobCredentialRuntimeAssertSafeError(t, prepareErr)

	stale := request
	stale.Identity.RuntimeGeneration = "runtime-generation-stale"
	if session, err := preflight.PrepareJobCredentials(context.Background(), stale); !l8JobCredentialRuntimeValueIsNil(session) || !errors.Is(err, sandboxruntime.ErrJobCredentialIdentityMismatch) {
		t.Fatalf("stale generation prepare = %#v, %v", session, err)
	}
	if guest.prepares != 0 {
		t.Fatal("invalid prepare reached the guest session")
	}

	session, err = preflight.PrepareJobCredentials(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxruntime.ValidateJobCredentialActiveProof(session.ActiveProof(), identity, 1, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestL8JobCredentialRuntimeLossEmitsOneValueThenCloses(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	seed, identity, request := l8JobCredentialRuntimePrepareFixture(t, now)
	guest := l8JobCredentialGuestSessionFakeForTest(t, now)
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest}, &l8JobCredentialHTTPProxyFake{}, &l8JobCredentialFileTmpfsFake{payload: []byte("x")}, nil)
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	session, err := preflight.PrepareJobCredentials(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	guest.emitLoss()
	got, ok := <-session.Loss()
	if !ok || got.Revision != 1 || got.Code != sandboxruntime.JobCredentialFailureGuestHelperUnavailable {
		t.Fatalf("loss = %#v, %t", got, ok)
	}
	if digest, err := sandboxruntime.JobCredentialIdentityDigest(got.Identity); err != nil {
		t.Fatal(err)
	} else if want, err := sandboxruntime.JobCredentialIdentityDigest(identity); err != nil || digest != want {
		t.Fatalf("loss identity digest mismatch: %v", err)
	}
	if _, ok := <-session.Loss(); ok {
		t.Fatal("loss channel emitted more than one value")
	}
}

func TestL8JobCredentialRuntimeRecoverFailsClosedWithoutDurableHandleStore(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	_, identity, request := l8JobCredentialRuntimePrepareFixture(t, now)
	guest := l8JobCredentialGuestSessionFakeForTest(t, now)
	httpProxy := &l8JobCredentialHTTPProxyFake{}
	tmpfs := &l8JobCredentialFileTmpfsFake{payload: []byte("tmpfs-canary")}
	ssh := &l8JobCredentialSSHRelayFake{policyID: "ssh-policy-1", policyRevision: 4}
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest}, httpProxy, tmpfs, ssh)

	proof, err := runtime.RecoverJobCredentials(context.Background(), sandboxruntime.JobCredentialRecoveryRequest{
		Identity: identity, Revision: 1,
	})
	if sandboxruntime.CleanupProofKind(proof) != "" || !errors.Is(err, errL8JobCredentialRuntimeDependencyUnaccepted) {
		t.Fatalf("valid recover = %#v, %v", proof, err)
	}
	if err.Error() != "dependency_unaccepted" {
		t.Fatalf("recover error = %q, want dependency_unaccepted", err)
	}
	l8JobCredentialRuntimeAssertSafeError(t, err)
	if guest.prepares != 0 || guest.renews != 0 || guest.revokes != 0 || guest.closed != 0 {
		t.Fatalf("recover opened guest state prepares=%d renews=%d revokes=%d closed=%d", guest.prepares, guest.renews, guest.revokes, guest.closed)
	}
	if httpProxy.activates != 0 || httpProxy.revokes != 0 || tmpfs.materializes != 0 || tmpfs.revokes != 0 || ssh.activates != 0 || ssh.revokes != 0 {
		t.Fatalf("recover touched delivery adapters http=%d/%d tmpfs=%d/%d ssh=%d/%d", httpProxy.activates, httpProxy.revokes, tmpfs.materializes, tmpfs.revokes, ssh.activates, ssh.revokes)
	}

	empty, emptyErr := runtime.RecoverJobCredentials(context.Background(), sandboxruntime.JobCredentialRecoveryRequest{})
	if sandboxruntime.CleanupProofKind(empty) != "" || !errors.Is(emptyErr, sandboxruntime.ErrJobCredentialIdentityMismatch) {
		t.Fatalf("empty recover = %#v, %v", empty, emptyErr)
	}
	zeroRevision, zeroErr := runtime.RecoverJobCredentials(context.Background(), sandboxruntime.JobCredentialRecoveryRequest{Identity: identity})
	if sandboxruntime.CleanupProofKind(zeroRevision) != "" || !errors.Is(zeroErr, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("zero-revision recover = %#v, %v", zeroRevision, zeroErr)
	}
	nilCtx, nilCtxErr := runtime.RecoverJobCredentials(nil, sandboxruntime.JobCredentialRecoveryRequest{Identity: identity, Revision: 1})
	if sandboxruntime.CleanupProofKind(nilCtx) != "" || !errors.Is(nilCtxErr, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("nil-context recover = %#v, %v", nilCtx, nilCtxErr)
	}
	var nilRuntime *L8JobCredentialRuntime
	nilProof, nilErr := nilRuntime.RecoverJobCredentials(context.Background(), sandboxruntime.JobCredentialRecoveryRequest{Identity: identity, Revision: 1})
	if sandboxruntime.CleanupProofKind(nilProof) != "" || !errors.Is(nilErr, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("nil-runtime recover = %#v, %v", nilProof, nilErr)
	}

	seed := l8JobCredentialRuntimeSeed(t, now, []sandboxruntime.JobCredentialDeliveryMode{
		sandboxruntime.JobCredentialDeliveryModeHTTPProxy,
		sandboxruntime.JobCredentialDeliveryModeFileTmpfs,
	})
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	session, err := preflight.PrepareJobCredentials(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	liveProof, liveErr := runtime.RecoverJobCredentials(context.Background(), sandboxruntime.JobCredentialRecoveryRequest{
		Identity: identity, Revision: 1,
	})
	if sandboxruntime.CleanupProofKind(liveProof) != "" || !errors.Is(liveErr, sandboxruntime.ErrJobCredentialTransition) {
		t.Fatalf("live recover = %#v, %v", liveProof, liveErr)
	}
	if sandboxruntime.ActiveProofKind(session.ActiveProof()) == "" {
		t.Fatal("fail-closed recover revoked a live session it does not own")
	}
	if httpProxy.revokes != 0 || tmpfs.revokes != 0 {
		t.Fatalf("fail-closed recover revoked live handles http=%d tmpfs=%d", httpProxy.revokes, tmpfs.revokes)
	}

	source, err := os.ReadFile("l8_job_credential_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(source, []byte("NewJobCredentialRuntimeAbsenceProof")) {
		t.Fatal("job credential runtime issued a runtime absence proof")
	}
	if !bytes.Contains(source, []byte("HandleStore")) || !bytes.Contains(source, []byte("mints no cleanup proof")) {
		t.Fatal("recover does not document that a missing handle store mints no cleanup proof")
	}
}

func TestL8JobCredentialRuntimeRecoverMintsCleanupProofFromStoreMetadata(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	seed, identity, request := l8JobCredentialRuntimePrepareFixture(t, now)
	store := newL8JobCredentialMemoryHandleStore()
	guest := l8JobCredentialGuestSessionFakeForTest(t, now)
	httpProxy := &l8JobCredentialHTTPProxyFake{}
	tmpfs := &l8JobCredentialFileTmpfsFake{payload: []byte("file-bytes")}
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest}, httpProxy, tmpfs, nil)
	runtime.deps.HandleStore = store

	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := preflight.PrepareJobCredentials(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, present, err := store.Load(context.Background(), identity); err != nil || !present {
		t.Fatalf("prepare did not persist handle metadata: present=%t err=%v", present, err)
	}

	liveProof, liveErr := runtime.RecoverJobCredentials(context.Background(), sandboxruntime.JobCredentialRecoveryRequest{
		Identity: identity, Revision: 1,
	})
	if sandboxruntime.CleanupProofKind(liveProof) != "" || !errors.Is(liveErr, sandboxruntime.ErrJobCredentialTransition) {
		t.Fatalf("same-runtime recover = %#v, %v", liveProof, liveErr)
	}
	if httpProxy.revokes != 0 || tmpfs.revokes != 0 {
		t.Fatalf("same-runtime recover revoked live handles http=%d tmpfs=%d", httpProxy.revokes, tmpfs.revokes)
	}

	recovered := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: l8JobCredentialGuestSessionFakeForTest(t, now)}, httpProxy, tmpfs, nil)
	recovered.deps.HandleStore = store
	stale, staleErr := recovered.RecoverJobCredentials(context.Background(), sandboxruntime.JobCredentialRecoveryRequest{
		Identity: identity, Revision: 2,
	})
	if sandboxruntime.CleanupProofKind(stale) != "" || !errors.Is(staleErr, sandboxruntime.ErrJobCredentialRevisionStale) {
		t.Fatalf("stale-revision recover = %#v, %v", stale, staleErr)
	}
	if httpProxy.revokes != 0 || tmpfs.revokes != 0 {
		t.Fatalf("stale-revision recover revoked handles http=%d tmpfs=%d", httpProxy.revokes, tmpfs.revokes)
	}

	missingRevoker := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: l8JobCredentialGuestSessionFakeForTest(t, now)}, nil, tmpfs, nil)
	missingRevoker.deps.HandleStore = store
	unproved, unprovedErr := missingRevoker.RecoverJobCredentials(context.Background(), sandboxruntime.JobCredentialRecoveryRequest{
		Identity: identity, Revision: 1,
	})
	if sandboxruntime.CleanupProofKind(unproved) != "" || !errors.Is(unprovedErr, errL8JobCredentialRuntimeDependencyUnaccepted) {
		t.Fatalf("missing-revoker recover = %#v, %v", unproved, unprovedErr)
	}
	if httpProxy.revokes != 0 || tmpfs.revokes != 0 {
		t.Fatalf("missing-revoker recover partially revoked handles http=%d tmpfs=%d", httpProxy.revokes, tmpfs.revokes)
	}
	missingLaterRevoker := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: l8JobCredentialGuestSessionFakeForTest(t, now)}, httpProxy, nil, nil)
	missingLaterRevoker.deps.HandleStore = store
	unproved, unprovedErr = missingLaterRevoker.RecoverJobCredentials(context.Background(), sandboxruntime.JobCredentialRecoveryRequest{
		Identity: identity, Revision: 1,
	})
	if sandboxruntime.CleanupProofKind(unproved) != "" || !errors.Is(unprovedErr, errL8JobCredentialRuntimeDependencyUnaccepted) {
		t.Fatalf("missing-later-revoker recover = %#v, %v", unproved, unprovedErr)
	}
	if httpProxy.revokes != 0 || tmpfs.revokes != 0 {
		t.Fatalf("missing-later-revoker partially revoked handles http=%d tmpfs=%d", httpProxy.revokes, tmpfs.revokes)
	}

	proof, err := recovered.RecoverJobCredentials(context.Background(), sandboxruntime.JobCredentialRecoveryRequest{
		Identity: identity, Revision: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxruntime.ValidateJobCredentialCleanupProof(proof, identity, 2, now.Add(2*time.Second)); err != nil {
		t.Fatalf("store recover cleanup proof: %v", err)
	}
	if httpProxy.revokes != 1 || tmpfs.revokes != 1 {
		t.Fatalf("store recover revokes http=%d tmpfs=%d, want 1/1", httpProxy.revokes, tmpfs.revokes)
	}
	if next, nextErr := recovered.PreflightJobCredentials(context.Background(), seed); !l8JobCredentialRuntimeValueIsNil(next) || !errors.Is(nextErr, sandboxruntime.ErrJobCredentialTransition) {
		t.Fatalf("preflight after recovery = %#v, %v", next, nextErr)
	}

	missing := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: l8JobCredentialGuestSessionFakeForTest(t, now)}, nil, nil, nil)
	missing.deps.HandleStore = newL8JobCredentialMemoryHandleStore()
	empty, emptyErr := missing.RecoverJobCredentials(context.Background(), sandboxruntime.JobCredentialRecoveryRequest{
		Identity: identity, Revision: 1,
	})
	if sandboxruntime.CleanupProofKind(empty) != "" || !errors.Is(emptyErr, errL8JobCredentialRuntimeDependencyUnaccepted) {
		t.Fatalf("missing-metadata recover = %#v, %v", empty, emptyErr)
	}

	neighbor := identity
	neighbor.WorkerJobID = "job-neighbor"
	if err := sandboxruntime.ValidateJobCredentialIdentity(neighbor); err != nil {
		t.Fatal(err)
	}
	foreignRuntime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: l8JobCredentialGuestSessionFakeForTest(t, now)}, httpProxy, tmpfs, nil)
	foreignRuntime.deps.HandleStore = store
	foreign, foreignErr := foreignRuntime.RecoverJobCredentials(context.Background(), sandboxruntime.JobCredentialRecoveryRequest{
		Identity: neighbor, Revision: 1,
	})
	if sandboxruntime.CleanupProofKind(foreign) != "" || !errors.Is(foreignErr, errL8JobCredentialRuntimeDependencyUnaccepted) {
		t.Fatalf("neighbor recover = %#v, %v", foreign, foreignErr)
	}
}

func TestL8JobCredentialRuntimeRecoverDoesNotMintWhenStoredRevokeFails(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	seed, identity, request := l8JobCredentialRuntimePrepareFixture(t, now)
	store := newL8JobCredentialMemoryHandleStore()
	httpProxy := &l8JobCredentialHTTPProxyFake{revokeErr: errors.New("ticket=sk_live_canary path=/private/ticket.bin")}
	tmpfs := &l8JobCredentialFileTmpfsFake{payload: []byte("file-bytes")}
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: l8JobCredentialGuestSessionFakeForTest(t, now)}, httpProxy, tmpfs, nil)
	runtime.deps.HandleStore = store
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := preflight.PrepareJobCredentials(context.Background(), request); err != nil {
		t.Fatal(err)
	}

	recovered := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: l8JobCredentialGuestSessionFakeForTest(t, now)}, httpProxy, tmpfs, nil)
	recovered.deps.HandleStore = store
	failed, failedErr := recovered.RecoverJobCredentials(context.Background(), sandboxruntime.JobCredentialRecoveryRequest{
		Identity: identity, Revision: 1,
	})
	if sandboxruntime.CleanupProofKind(failed) != "" || !errors.Is(failedErr, ErrL8JobCredentialRuntimeUnavailable) {
		t.Fatalf("failed stored revoke = %#v, %v", failed, failedErr)
	}
	l8JobCredentialRuntimeAssertSafeError(t, failedErr)
	if strings.Contains(failedErr.Error(), "sk_live") || strings.Contains(failedErr.Error(), "/private/") {
		t.Fatalf("stored revoke leaked canary: %v", failedErr)
	}
}

func TestL8JobCredentialRuntimeSanitizeErrorsAndDenySerialization(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	canary := "/private/runtime.sock OPENAI_API_KEY=sk_live_canary"
	opener := &l8JobCredentialGuestSessionOpenerFake{err: errors.New(canary)}
	runtime := l8JobCredentialRuntimeForTest(t, now, opener, nil, nil, nil)
	seed := l8JobCredentialRuntimeSeed(t, now, []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeFileTmpfs})
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if !l8JobCredentialRuntimeValueIsNil(preflight) || err == nil {
		t.Fatalf("canary preflight = %#v, %v", preflight, err)
	}
	l8JobCredentialRuntimeAssertSafeError(t, err)
	if strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), "sk_live") || strings.Contains(err.Error(), "/private/") {
		t.Fatalf("preflight leaked canary: %v", err)
	}

	values := []any{runtime, &L8JobCredentialRuntime{}}
	for _, value := range values {
		if encoded, marshalErr := json.Marshal(value); marshalErr == nil || encoded != nil || !errors.Is(marshalErr, ErrL8JobCredentialRuntimeSerialization) {
			t.Fatalf("json.Marshal(%T) = %q, %v", value, encoded, marshalErr)
		}
		for _, rendered := range []string{fmt.Sprint(value), fmt.Sprintf("%#v", value), fmt.Sprintf("%+v", value)} {
			if rendered != l8JobCredentialRuntimeValuePlaceholder {
				t.Fatalf("format %T = %q", value, rendered)
			}
		}
	}
}

func TestL8JobCredentialRuntimeRemainsDefaultOff(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", "..", ".."))
	set := token.NewFileSet()
	callers := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.HasSuffix(filepath.ToSlash(path), "microvm/firecrackerhost/l8_job_credential_runtime.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(set, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch function := call.Fun.(type) {
			case *ast.Ident:
				name = function.Name
			case *ast.SelectorExpr:
				name = function.Sel.Name
			}
			if name == "NewProductionL8JobCredentialRuntime" {
				callers++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if callers != 0 {
		t.Fatalf("production NewProductionL8JobCredentialRuntime callers = %d, want zero", callers)
	}

	for _, name := range []string{"adapter.go", "live_driver.go", "l7_live_composition.go"} {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"NewProductionL8JobCredentialRuntime", "L8JobCredentialRuntime", "PreflightJobCredentials"} {
			if bytes.Contains(source, []byte(forbidden)) {
				t.Fatalf("%s wires job credential runtime marker %q", name, forbidden)
			}
		}
	}
	if firecracker.BackendID == "" {
		t.Fatal("firecracker backend id missing")
	}
}

func TestL8JobCredentialRuntimeComposesInjectedGuestHTTPTmpfsAndSSH(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	seed := l8JobCredentialRuntimeSeed(t, now, []sandboxruntime.JobCredentialDeliveryMode{
		sandboxruntime.JobCredentialDeliveryModeHTTPProxy,
		sandboxruntime.JobCredentialDeliveryModeFileTmpfs,
		sandboxruntime.JobCredentialDeliveryModeSSHAgent,
	})
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, l8JobCredentialRuntimeGuestSessionGeneration(), "helper-generation-runtime")
	if err != nil {
		t.Fatal(err)
	}
	request := l8JobCredentialRuntimePrepareRequest(t, identity)
	guest := l8JobCredentialGuestSessionFakeForTest(t, now)
	httpProxy := &l8JobCredentialHTTPProxyFake{}
	tmpfs := &l8JobCredentialFileTmpfsFake{payload: []byte("file-bytes")}
	ssh := &l8JobCredentialSSHRelayFake{policyID: "ssh-policy-1", policyRevision: 4}
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest}, httpProxy, tmpfs, ssh)
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	session, err := preflight.PrepareJobCredentials(context.Background(), request)
	if err != nil || l8JobCredentialRuntimeValueIsNil(session) {
		t.Fatalf("mixed prepare = %#v, %v", session, err)
	}
	if httpProxy.activates != 1 || tmpfs.materializes != 1 || ssh.activates != 1 {
		t.Fatalf("mixed activations http=%d tmpfs=%d ssh=%d", httpProxy.activates, tmpfs.materializes, ssh.activates)
	}
	if len(guest.lastManifests) != 3 {
		t.Fatalf("guest manifests = %d, want 3", len(guest.lastManifests))
	}
	if _, err := session.Revoke(context.Background(), sandboxruntime.JobCredentialRevokeReason("requested")); err != nil {
		t.Fatal(err)
	}
	if httpProxy.revokes != 1 || tmpfs.revokes != 1 || ssh.revokes != 1 {
		t.Fatalf("mixed revokes http=%d tmpfs=%d ssh=%d", httpProxy.revokes, tmpfs.revokes, ssh.revokes)
	}
}

func TestL8JobCredentialRuntimePreflightReturnMatrix(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	seed := l8JobCredentialRuntimeSeed(t, now, []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeFileTmpfs})
	raw := errors.New("token=provider-secret path=/private/provider.sock")
	var typedNil *l8JobCredentialGuestSessionFake
	tests := []struct {
		name    string
		opener  *l8JobCredentialGuestSessionOpenerFake
		wantErr error
	}{
		{name: "nil success", opener: &l8JobCredentialGuestSessionOpenerFake{}, wantErr: ErrL8JobCredentialRuntimeInvalid},
		{name: "typed nil success", opener: &l8JobCredentialGuestSessionOpenerFake{session: typedNil}, wantErr: ErrL8JobCredentialRuntimeInvalid},
		{name: "nil error", opener: &l8JobCredentialGuestSessionOpenerFake{err: raw}, wantErr: ErrL8JobCredentialRuntimeUnavailable},
		{name: "value plus error", opener: &l8JobCredentialGuestSessionOpenerFake{session: l8JobCredentialGuestSessionFakeForTest(t, now), err: raw}, wantErr: ErrL8JobCredentialRuntimeUnavailable},
		{name: "panic", opener: &l8JobCredentialGuestSessionOpenerFake{panicValue: raw}, wantErr: ErrL8JobCredentialRuntimeUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime := l8JobCredentialRuntimeForTest(t, now, tt.opener, nil, &l8JobCredentialFileTmpfsFake{payload: []byte("x")}, nil)
			preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
			if !l8JobCredentialRuntimeValueIsNil(preflight) || !errors.Is(err, tt.wantErr) {
				t.Fatalf("preflight = %#v, %v, want %v", preflight, err, tt.wantErr)
			}
			l8JobCredentialRuntimeAssertSafeError(t, err)
			if tt.opener.session != nil && !l8JobCredentialRuntimeValueIsNil(tt.opener.session) && tt.opener.err != nil {
				if fake, ok := tt.opener.session.(*l8JobCredentialGuestSessionFake); ok && fake.closed == 0 {
					t.Fatal("value-plus-error did not close the attempted guest session")
				}
			}
		})
	}
}

func l8JobCredentialRuntimeForTest(
	t *testing.T,
	now time.Time,
	opener l8JobCredentialGuestSessionOpener,
	httpProxy l8JobCredentialHTTPProxyActivator,
	tmpfs l8JobCredentialFileTmpfsActivator,
	ssh l8JobCredentialSSHRelayActivator,
) *L8JobCredentialRuntime {
	t.Helper()
	runtime, err := newL8JobCredentialRuntime(l8JobCredentialRuntimeTestDeps(t, now, opener, httpProxy, tmpfs, ssh), false)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func l8JobCredentialRuntimeTestDeps(
	t *testing.T,
	now time.Time,
	opener l8JobCredentialGuestSessionOpener,
	httpProxy l8JobCredentialHTTPProxyActivator,
	tmpfs l8JobCredentialFileTmpfsActivator,
	ssh l8JobCredentialSSHRelayActivator,
) l8JobCredentialRuntimeDependencies {
	t.Helper()
	if opener == nil {
		opener = &l8JobCredentialGuestSessionOpenerFake{session: l8JobCredentialGuestSessionFakeForTest(t, now)}
	}
	return l8JobCredentialRuntimeDependencies{
		GuestSession: opener,
		HTTPProxy:    httpProxy,
		FileTmpfs:    tmpfs,
		SSHRelay:     ssh,
		Now:          func() time.Time { return now.Add(time.Second) },
		Random:       bytesReaderForTest(),
	}
}

func l8JobCredentialRuntimeNow() time.Time {
	return time.Date(2026, time.August, 28, 1, 2, 3, 0, time.UTC)
}

func l8JobCredentialRuntimeGuestSessionGeneration() string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x7a}, 32))
}

func l8JobCredentialRuntimeSeed(t *testing.T, now time.Time, modes []sandboxruntime.JobCredentialDeliveryMode) sandboxruntime.JobCredentialIdentitySeed {
	t.Helper()
	bindingIDs := make([]string, len(modes))
	for index := range modes {
		bindingIDs[index] = fmt.Sprintf("binding-%d", index+1)
	}
	seed := sandboxruntime.JobCredentialIdentitySeed{
		SandboxID: "sandbox-runtime", ExecutionID: "execution-runtime", WorkerID: "worker-runtime", HostID: "host-runtime",
		RuntimeDriver: "microvm", RuntimeID: "runtime-1", RuntimeGeneration: "runtime-generation-1",
		FirecrackerProcessGeneration: "process-generation-1", VsockGeneration: "vsock-generation-1",
		WorkerJobID: "job-runtime", SubmissionID: "submission-runtime", PlanID: "plan-runtime",
		ActivationGeneration: "activation-runtime", CredentialGeneration: "credential-runtime",
		AdmissionGrantID: "grant-runtime", PrincipalID: "principal-runtime",
		TemplatePolicyID: "template-runtime", WorkspacePolicyID: "workspace-runtime",
		ControllerKeyGeneration: "controller-key-runtime", GuestBootGeneration: "guest-boot-runtime",
		GuestImageGeneration: "guest-image-runtime", GuestImageDigest: "sha256-" + strings.Repeat("ab", 32),
		AdmissionGrantRevision: 2, BindingIDs: bindingIDs, DeliveryModes: append([]sandboxruntime.JobCredentialDeliveryMode(nil), modes...),
		IssuedAt: now,
	}
	for _, mode := range modes {
		if mode == sandboxruntime.JobCredentialDeliveryModeHTTPProxy {
			seed.NetworkPlanID = "network-plan-runtime"
			seed.PolicySnapshotID = "policy-snapshot-runtime"
			seed.ProxySessionID = "proxy-session-runtime"
			seed.ProxyGenerationID = "proxy-generation-runtime"
			seed.TopologyGenerationID = "topology-generation-runtime"
			seed.RuleGenerationID = "rule-generation-runtime"
			break
		}
	}
	if err := sandboxruntime.ValidateJobCredentialIdentitySeed(seed); err != nil {
		t.Fatalf("seed fixture: %v", err)
	}
	return seed
}

func l8JobCredentialRuntimePrepareFixture(t *testing.T, now time.Time) (sandboxruntime.JobCredentialIdentitySeed, sandboxruntime.JobCredentialIdentity, sandboxruntime.JobCredentialPrepareRequest) {
	t.Helper()
	seed := l8JobCredentialRuntimeSeed(t, now, []sandboxruntime.JobCredentialDeliveryMode{
		sandboxruntime.JobCredentialDeliveryModeHTTPProxy,
		sandboxruntime.JobCredentialDeliveryModeFileTmpfs,
	})
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, l8JobCredentialRuntimeGuestSessionGeneration(), "helper-generation-runtime")
	if err != nil {
		t.Fatal(err)
	}
	return seed, identity, l8JobCredentialRuntimePrepareRequest(t, identity)
}

func l8JobCredentialRuntimePrepareRequest(t *testing.T, identity sandboxruntime.JobCredentialIdentity) sandboxruntime.JobCredentialPrepareRequest {
	t.Helper()
	bindings := make([]sandboxruntime.JobCredentialBindingRequest, len(identity.BindingIDs))
	sources := make([]sandboxruntime.JobCredentialAuthorizedSource, 0, len(identity.BindingIDs))
	sourceIDs := make([]string, 0, len(identity.BindingIDs))
	for index, bindingID := range identity.BindingIDs {
		binding := sandboxruntime.JobCredentialBindingRequest{
			ID: bindingID, Mode: identity.DeliveryModes[index], SourceReferenceID: "source-" + bindingID,
		}
		if identity.DeliveryModes[index] == sandboxruntime.JobCredentialDeliveryModeHTTPProxy {
			binding.ServiceID = "azure-openai-responses-v1"
		}
		bindings[index] = binding
		if identity.DeliveryModes[index] != sandboxruntime.JobCredentialDeliveryModeSSHAgent {
			sourceIDs = append(sourceIDs, binding.SourceReferenceID)
			sources = append(sources, sandboxruntime.JobCredentialAuthorizedSource{
				ReferenceID: binding.SourceReferenceID,
				Source:      l8JobCredentialRuntimeSecretSource{payload: []byte("secret-bytes-" + bindingID)},
			})
		}
	}
	return sandboxruntime.JobCredentialPrepareRequest{
		Identity: identity,
		Admission: sandboxruntime.JobCredentialAdmissionRequest{
			Identity: sandboxruntime.JobCredentialAdmissionIdentity{
				SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID, WorkerID: identity.WorkerID, HostID: identity.HostID,
				RuntimeDriver: identity.RuntimeDriver, RuntimeID: identity.RuntimeID, RuntimeGeneration: identity.RuntimeGeneration,
				FirecrackerProcessGeneration: identity.FirecrackerProcessGeneration, VsockGeneration: identity.VsockGeneration,
				WorkerJobID: identity.WorkerJobID, SubmissionID: identity.SubmissionID, PlanID: identity.PlanID,
				ActivationGeneration: identity.ActivationGeneration, CredentialGeneration: identity.CredentialGeneration,
				NetworkPlanID: identity.NetworkPlanID, PolicySnapshotID: identity.PolicySnapshotID,
				ProxySessionID: identity.ProxySessionID, ProxyGenerationID: identity.ProxyGenerationID,
				TopologyGenerationID: identity.TopologyGenerationID, RuleGenerationID: identity.RuleGenerationID,
				IssuedAt: identity.IssuedAt,
			},
			GrantID: identity.AdmissionGrantID, GrantRevision: identity.AdmissionGrantRevision, PlanID: identity.PlanID,
			TemplatePolicyID: identity.TemplatePolicyID, WorkspacePolicyID: identity.WorkspacePolicyID,
			SourceReferenceIDs: sourceIDs, Bindings: bindings,
		},
		Authorization:     l8JobCredentialRuntimeTestAuthorization{},
		AuthorizedSources: sources,
	}
}

func l8JobCredentialRuntimeAssertSafeError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	text := err.Error()
	for _, forbidden := range []string{
		"sk_live", "OPENAI_API_KEY", "/private/", "secret-bytes", "tmpfs-canary",
		"provider-secret", "helper-generation-runtime",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("error leaked %q: %v", forbidden, err)
		}
	}
}

func bytesReaderForTest() io.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{0x11}, 512))
}

type l8JobCredentialRuntimeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *l8JobCredentialRuntimeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

type l8JobCredentialRuntimeTestAuthorization struct{}

type l8JobCredentialRuntimeSecretSource struct{ payload []byte }

func (source l8JobCredentialRuntimeSecretSource) FillSecret(_ context.Context, sink sandboxruntime.JobCredentialSecretSink) error {
	if len(source.payload) > sink.MaxCredentialBytes() {
		return ErrL8JobCredentialRuntimeInvalid
	}
	return sink.WriteCredential(source.payload)
}

type l8JobCredentialGuestSessionOpenerFake struct {
	session    l8JobCredentialGuestSession
	err        error
	panicValue any
	calls      int
}

func (opener *l8JobCredentialGuestSessionOpenerFake) Open(_ context.Context, _ sandboxruntime.JobCredentialIdentitySeed) (l8JobCredentialGuestSession, error) {
	opener.calls++
	if opener.panicValue != nil {
		panic(opener.panicValue)
	}
	return opener.session, opener.err
}

type l8JobCredentialGuestSessionFake struct {
	sessionGeneration string
	helperGeneration  string
	sessionID         [32]byte
	hardExpiry        time.Time
	loss              chan struct{}
	lossOnce          sync.Once

	mu                sync.Mutex
	prepares          int
	renews            int
	revokes           int
	closed            int
	lastManifests     []l8JobCredentialGuestBindingManifest
	prepareErr        error
	renewErr          error
	revokeErr         error
	omitActiveProofID bool
	omitRenewProofID  bool
	omitRevokeProofID bool
	activeProofID     string
	renewProofID      string
	revokeProofID     string
}

func l8JobCredentialGuestSessionFakeForTest(t *testing.T, now time.Time) *l8JobCredentialGuestSessionFake {
	t.Helper()
	var sessionID [32]byte
	copy(sessionID[:], bytes.Repeat([]byte{0x7a}, 32))
	return &l8JobCredentialGuestSessionFake{
		sessionGeneration: l8JobCredentialRuntimeGuestSessionGeneration(),
		helperGeneration:  "helper-generation-runtime",
		sessionID:         sessionID,
		hardExpiry:        now.Add(30 * time.Minute),
		loss:              make(chan struct{}),
	}
}

func (session *l8JobCredentialGuestSessionFake) GuestSessionGeneration() string {
	return session.sessionGeneration
}
func (session *l8JobCredentialGuestSessionFake) GuestHelperGeneration() string {
	return session.helperGeneration
}
func (session *l8JobCredentialGuestSessionFake) SessionID() [32]byte { return session.sessionID }
func (session *l8JobCredentialGuestSessionFake) HardExpiry() time.Time {
	return session.hardExpiry
}
func (session *l8JobCredentialGuestSessionFake) Prepare(_ context.Context, _ sandboxruntime.JobCredentialIdentity, _ time.Time, manifests []l8JobCredentialGuestBindingManifest) (l8JobCredentialGuestPrepareResult, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.prepares++
	session.lastManifests = append([]l8JobCredentialGuestBindingManifest(nil), manifests...)
	if session.prepareErr != nil {
		return l8JobCredentialGuestPrepareResult{}, session.prepareErr
	}
	proofs := make([]l8JobCredentialGuestBindingProof, len(manifests))
	for index, manifest := range manifests {
		proofs[index] = l8JobCredentialGuestBindingProof{BindingID: manifest.BindingID, Mode: manifest.Mode, ProofID: "guest-" + manifest.BindingID}
	}
	activeProofID := session.activeProofID
	if session.omitActiveProofID {
		activeProofID = ""
	} else if activeProofID == "" {
		activeProofID = "guest-active-1"
	}
	return l8JobCredentialGuestPrepareResult{ActiveProofID: activeProofID, ExecBindingID: "exec-binding-1", BindingProofs: proofs}, nil
}
func (session *l8JobCredentialGuestSessionFake) Renew(context.Context, sandboxruntime.JobCredentialIdentity, uint64, time.Time, string) (string, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.renews++
	if session.renewErr != nil {
		return "", session.renewErr
	}
	if session.omitRenewProofID {
		return "", nil
	}
	if session.renewProofID != "" {
		return session.renewProofID, nil
	}
	return "guest-active-2", nil
}
func (session *l8JobCredentialGuestSessionFake) Revoke(context.Context, sandboxruntime.JobCredentialIdentity, uint64, sandboxruntime.JobCredentialRevokeReason) (string, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.revokes++
	if session.revokeErr != nil {
		return "", session.revokeErr
	}
	if session.omitRevokeProofID {
		return "", nil
	}
	if session.revokeProofID != "" {
		return session.revokeProofID, nil
	}
	return "guest-cleanup-1", nil
}
func (session *l8JobCredentialGuestSessionFake) Loss() <-chan struct{} { return session.loss }
func (session *l8JobCredentialGuestSessionFake) Close() error {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.closed++
	return nil
}
func (session *l8JobCredentialGuestSessionFake) emitLoss() {
	session.lossOnce.Do(func() { close(session.loss) })
}

type l8JobCredentialHTTPProxyFake struct {
	mu        sync.Mutex
	activates int
	renews    int
	revokes   int
	err       error
	revokeErr error
	handles   map[string]*l8JobCredentialHTTPProxyHandleFake
}

func (fake *l8JobCredentialHTTPProxyFake) Activate(_ context.Context, _ sandboxruntime.JobCredentialIdentity, binding sandboxruntime.JobCredentialBindingRequest, _ sandboxruntime.LiveSecretSource) (l8JobCredentialHTTPProxyHandle, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.activates++
	if fake.err != nil {
		return nil, fake.err
	}
	handle := &l8JobCredentialHTTPProxyHandleFake{parent: fake, bindingID: binding.ID, serviceID: binding.ServiceID}
	if fake.handles == nil {
		fake.handles = map[string]*l8JobCredentialHTTPProxyHandleFake{}
	}
	fake.handles[binding.ID] = handle
	return handle, nil
}

func (fake *l8JobCredentialHTTPProxyFake) RevokeStored(ctx context.Context, _ sandboxruntime.JobCredentialIdentity, binding l8JobCredentialStoredBindingV1) error {
	fake.mu.Lock()
	handle := fake.handles[binding.BindingID]
	fake.mu.Unlock()
	if handle == nil {
		return nil
	}
	return handle.Revoke(ctx)
}

type l8JobCredentialHTTPProxyHandleFake struct {
	parent    *l8JobCredentialHTTPProxyFake
	bindingID string
	serviceID string
}

func (handle *l8JobCredentialHTTPProxyHandleFake) ServiceID() string { return handle.serviceID }
func (handle *l8JobCredentialHTTPProxyHandleFake) Renew(context.Context) error {
	handle.parent.mu.Lock()
	defer handle.parent.mu.Unlock()
	handle.parent.renews++
	return nil
}
func (handle *l8JobCredentialHTTPProxyHandleFake) Revoke(context.Context) error {
	handle.parent.mu.Lock()
	defer handle.parent.mu.Unlock()
	handle.parent.revokes++
	if handle.parent.revokeErr != nil {
		return handle.parent.revokeErr
	}
	if handle.parent.handles != nil {
		delete(handle.parent.handles, handle.bindingID)
	}
	return nil
}

type l8JobCredentialFileTmpfsFake struct {
	mu           sync.Mutex
	payload      []byte
	materializes int
	revokes      int
	err          error
	revokeErr    error
	handles      map[string]*l8JobCredentialFileHandleFake
}

func (fake *l8JobCredentialFileTmpfsFake) Materialize(ctx context.Context, identity sandboxruntime.JobCredentialIdentity, binding sandboxruntime.JobCredentialBindingRequest, source sandboxruntime.LiveSecretSource) (l8JobCredentialFileHandle, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.materializes++
	if fake.err != nil {
		return nil, fake.err
	}
	payload := fake.payload
	if source != nil {
		sink := &l8JobCredentialRuntimeTestSink{max: 64 * 1024}
		if err := source.FillSecret(ctx, sink); err != nil {
			return nil, err
		}
		if len(sink.written) > 0 {
			payload = append([]byte(nil), sink.written...)
		}
	}
	sum := sha256.Sum256(payload)
	_ = identity
	handle := &l8JobCredentialFileHandleFake{
		parent: fake, bindingID: binding.ID, targetPath: binding.ID, size: uint32(len(payload)), digest: hex.EncodeToString(sum[:]),
	}
	if fake.handles == nil {
		fake.handles = map[string]*l8JobCredentialFileHandleFake{}
	}
	fake.handles[binding.ID] = handle
	return handle, nil
}

func (fake *l8JobCredentialFileTmpfsFake) RevokeStored(ctx context.Context, _ sandboxruntime.JobCredentialIdentity, binding l8JobCredentialStoredBindingV1) error {
	fake.mu.Lock()
	handle := fake.handles[binding.BindingID]
	fake.mu.Unlock()
	if handle == nil {
		return nil
	}
	return handle.Revoke(ctx)
}

type l8JobCredentialFileHandleFake struct {
	parent     *l8JobCredentialFileTmpfsFake
	bindingID  string
	targetPath string
	size       uint32
	digest     string
}

func (handle *l8JobCredentialFileHandleFake) TargetPath() string        { return handle.targetPath }
func (handle *l8JobCredentialFileHandleFake) DeclaredFileBytes() uint32 { return handle.size }
func (handle *l8JobCredentialFileHandleFake) FileSHA256() string        { return handle.digest }
func (handle *l8JobCredentialFileHandleFake) Revoke(context.Context) error {
	handle.parent.mu.Lock()
	defer handle.parent.mu.Unlock()
	handle.parent.revokes++
	if handle.parent.revokeErr != nil {
		return handle.parent.revokeErr
	}
	if handle.parent.handles != nil {
		delete(handle.parent.handles, handle.bindingID)
	}
	return nil
}

type l8JobCredentialSSHRelayFake struct {
	mu             sync.Mutex
	policyID       string
	policyRevision uint64
	activates      int
	renews         int
	revokes        int
	err            error
	revokeErr      error
	handles        map[string]*l8JobCredentialSSHRelayHandleFake
}

func (fake *l8JobCredentialSSHRelayFake) Activate(_ context.Context, _ sandboxruntime.JobCredentialIdentity, binding sandboxruntime.JobCredentialBindingRequest) (l8JobCredentialSSHRelayHandle, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.activates++
	if fake.err != nil {
		return nil, fake.err
	}
	handle := &l8JobCredentialSSHRelayHandleFake{parent: fake, bindingID: binding.ID, policyID: fake.policyID, policyRevision: fake.policyRevision}
	if fake.handles == nil {
		fake.handles = map[string]*l8JobCredentialSSHRelayHandleFake{}
	}
	fake.handles[binding.ID] = handle
	return handle, nil
}

func (fake *l8JobCredentialSSHRelayFake) RevokeStored(ctx context.Context, _ sandboxruntime.JobCredentialIdentity, binding l8JobCredentialStoredBindingV1) error {
	fake.mu.Lock()
	handle := fake.handles[binding.BindingID]
	fake.mu.Unlock()
	if handle == nil {
		return nil
	}
	return handle.Revoke(ctx)
}

type l8JobCredentialSSHRelayHandleFake struct {
	parent         *l8JobCredentialSSHRelayFake
	bindingID      string
	policyID       string
	policyRevision uint64
}

func (handle *l8JobCredentialSSHRelayHandleFake) PolicyID() string { return handle.policyID }
func (handle *l8JobCredentialSSHRelayHandleFake) PolicyRevision() uint64 {
	return handle.policyRevision
}
func (handle *l8JobCredentialSSHRelayHandleFake) Renew(context.Context) error {
	handle.parent.mu.Lock()
	defer handle.parent.mu.Unlock()
	handle.parent.renews++
	return nil
}
func (handle *l8JobCredentialSSHRelayHandleFake) Revoke(context.Context) error {
	handle.parent.mu.Lock()
	defer handle.parent.mu.Unlock()
	handle.parent.revokes++
	if handle.parent.revokeErr != nil {
		return handle.parent.revokeErr
	}
	if handle.parent.handles != nil {
		delete(handle.parent.handles, handle.bindingID)
	}
	return nil
}

type l8JobCredentialRuntimeTestSink struct {
	max     int
	written []byte
}

func (sink *l8JobCredentialRuntimeTestSink) MaxCredentialBytes() int { return sink.max }
func (sink *l8JobCredentialRuntimeTestSink) WriteCredential(value []byte) error {
	sink.written = append([]byte(nil), value...)
	return nil
}
