package sandboxworker

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8D6WorkerPrepareTransfersSessionInsteadOfAbort(t *testing.T) {
	harness := newL8D6LifecycleHarness(t, l8D6LifecycleHarnessOptions{})
	response := harness.service.HandleAuthenticatedRequest(context.Background(), harness.principal, harness.request)
	if !response.OK || response.Error != nil || response.JobV2 == nil {
		t.Fatalf("authenticated job start = %#v, want successful JobV2 after session transfer", response)
	}
	if response.JobV2.ID != harness.seed.WorkerJobID || response.JobV2.State != JobStateQueued {
		t.Fatalf("public job = %#v, want queued %s", response.JobV2, harness.seed.WorkerJobID)
	}
	if harness.preflight.prepareCallCount() != 1 || harness.preflight.abortCallCount() != 0 || harness.session.revokeCallCount() != 0 {
		t.Fatalf("ownership calls = prepare:%d abort:%d revoke:%d, want 1/0/0", harness.preflight.prepareCallCount(), harness.preflight.abortCallCount(), harness.session.revokeCallCount())
	}
	stored, err := harness.service.jobs.store.load(harness.seed.WorkerJobID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CredentialState == nil || stored.CredentialState.Identity == nil || stored.CredentialState.Revision != 1 {
		t.Fatalf("durable credential state = %#v, want complete identity at revision 1", stored.CredentialState)
	}
	publicJSON, err := json.Marshal(response.JobV2)
	if err != nil {
		t.Fatal(err)
	}
	l8D6AssertNoLiveCredentialLeak(t, publicJSON)
}

func TestL8D6WorkerPersistsActivatedCredentialRevision(t *testing.T) {
	harness := newL8D6LifecycleHarness(t, l8D6LifecycleHarnessOptions{activeRevision: 7})
	response := harness.service.HandleAuthenticatedRequest(context.Background(), harness.principal, harness.request)
	if !response.OK || response.JobV2 == nil {
		t.Fatalf("authenticated job start = %#v, want success", response)
	}
	stored, err := harness.service.jobs.store.load(harness.seed.WorkerJobID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CredentialState == nil || stored.CredentialState.Revision != 7 {
		t.Fatalf("durable credential revision = %#v, want activated revision 7", stored.CredentialState)
	}
}

func TestL8D6WorkerPrepareFailureAbortsPreflightAndDoesNotTransfer(t *testing.T) {
	harness := newL8D6LifecycleHarness(t, l8D6LifecycleHarnessOptions{prepareErr: errors.New("token=prepare-secret path=/private/prepare.sock")})
	response := harness.service.HandleAuthenticatedRequest(context.Background(), harness.principal, harness.request)
	if response.OK || response.Error == nil || response.Error.Code != ErrorCodeInternal || response.JobV2 != nil {
		t.Fatalf("failed prepare = %#v, want retained internal failure", response)
	}
	if harness.preflight.prepareCallCount() != 1 || harness.preflight.abortCallCount() != 1 {
		t.Fatalf("failed prepare ownership = prepare:%d abort:%d, want 1/1", harness.preflight.prepareCallCount(), harness.preflight.abortCallCount())
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	l8D6AssertNoLiveCredentialLeak(t, encoded)
	for _, forbidden := range []string{"prepare-secret", "/private", "token="} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("prepare failure leaked %q: %s", forbidden, encoded)
		}
	}
	stored, err := harness.service.jobs.store.load(harness.seed.WorkerJobID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CredentialState != nil || stored.JobV2.State != JobStateFailed {
		t.Fatalf("proved prepare abort retained live credential ownership: %#v", stored)
	}
}

func TestL8D6WorkerCancelRevokesTransferredSession(t *testing.T) {
	harness := newL8D6LifecycleHarness(t, l8D6LifecycleHarnessOptions{})
	start := harness.service.HandleAuthenticatedRequest(context.Background(), harness.principal, harness.request)
	if !start.OK || start.JobV2 == nil {
		t.Fatalf("start before cancel = %#v", start)
	}
	cancel := Request{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "request-cancel-v2",
		Operation:       OperationJobCancelV2,
		JobCancelV2:     &JobCancelRequestV2{ContractVersion: JobContractVersionV2, JobID: harness.seed.WorkerJobID},
	}
	response := harness.service.HandleAuthenticatedRequest(context.Background(), harness.principal, cancel)
	if !response.OK || response.JobV2 == nil || response.JobV2.State != JobStateCanceled {
		t.Fatalf("cancel = %#v, want canceled JobV2", response)
	}
	if harness.session.revokeCallCount() != 1 || harness.preflight.abortCallCount() != 0 {
		t.Fatalf("cancel ownership = revoke:%d abort:%d, want 1/0", harness.session.revokeCallCount(), harness.preflight.abortCallCount())
	}
	stored, err := harness.service.jobs.store.load(harness.seed.WorkerJobID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CredentialState != nil {
		t.Fatalf("canceled job retained credential state: %#v", stored.CredentialState)
	}
}

func TestL8D6WorkerCancelRetainsOwnershipUntilRevokeIsProved(t *testing.T) {
	harness := newL8D6LifecycleHarness(t, l8D6LifecycleHarnessOptions{revokeErr: errors.New("token=cleanup-secret path=/private/revoke.sock")})
	if start := harness.service.HandleAuthenticatedRequest(context.Background(), harness.principal, harness.request); !start.OK {
		t.Fatalf("start before cancel = %#v", start)
	}
	cancel := Request{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "request-cancel-retry-v2",
		Operation:       OperationJobCancelV2,
		JobCancelV2:     &JobCancelRequestV2{ContractVersion: JobContractVersionV2, JobID: harness.seed.WorkerJobID},
	}
	if response := harness.service.HandleAuthenticatedRequest(context.Background(), harness.principal, cancel); response.OK || response.Error == nil {
		t.Fatalf("failed revoke cancel = %#v, want internal failure", response)
	}
	stored, err := harness.service.jobs.store.load(harness.seed.WorkerJobID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CredentialState == nil {
		t.Fatal("failed revoke cleared durable credential ownership")
	}
	harness.session.setRevokeError(nil)
	response := harness.service.HandleAuthenticatedRequest(context.Background(), harness.principal, cancel)
	if !response.OK || response.JobV2 == nil || response.JobV2.State != JobStateCanceled {
		t.Fatalf("retry cancel = %#v, want canceled JobV2", response)
	}
	if harness.session.revokeCallCount() != 2 {
		t.Fatalf("retry revoke calls = %d, want 2", harness.session.revokeCallCount())
	}
}

func TestL8D6WorkerLossRevokesTransferredSession(t *testing.T) {
	harness := newL8D6LifecycleHarness(t, l8D6LifecycleHarnessOptions{})
	start := harness.service.HandleAuthenticatedRequest(context.Background(), harness.principal, harness.request)
	if !start.OK {
		t.Fatalf("start before loss = %#v", start)
	}
	revoked := make(chan struct{})
	harness.session.onRevoke = func() { close(revoked) }
	harness.innerLoss <- sandboxruntime.JobCredentialLoss{
		Identity: harness.identity,
		Revision: 1,
		Code:     sandboxruntime.JobCredentialFailureGuestHelperUnavailable,
	}
	select {
	case <-revoked:
	case <-time.After(2 * time.Second):
		t.Fatal("loss did not revoke the transferred session")
	}
	if harness.session.revokeCallCount() != 1 {
		t.Fatalf("loss revoke calls = %d, want 1", harness.session.revokeCallCount())
	}
}

func TestL8D6WorkerLossRetainsOwnershipWhenRevokeFails(t *testing.T) {
	harness := newL8D6LifecycleHarness(t, l8D6LifecycleHarnessOptions{revokeErr: errors.New("cleanup unavailable")})
	if start := harness.service.HandleAuthenticatedRequest(context.Background(), harness.principal, harness.request); !start.OK {
		t.Fatalf("start before loss = %#v", start)
	}
	revoked := make(chan struct{})
	harness.session.setOnRevoke(func() { close(revoked) })
	harness.innerLoss <- sandboxruntime.JobCredentialLoss{
		Identity: harness.identity,
		Revision: 1,
		Code:     sandboxruntime.JobCredentialFailureGuestHelperUnavailable,
	}
	select {
	case <-revoked:
	case <-time.After(2 * time.Second):
		t.Fatal("loss did not attempt to revoke the transferred session")
	}
	time.Sleep(50 * time.Millisecond)
	stored, err := harness.service.jobs.store.load(harness.seed.WorkerJobID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CredentialState == nil {
		t.Fatal("failed loss revoke cleared durable credential ownership")
	}
	harness.session.setOnRevoke(nil)
	harness.session.setRevokeError(nil)
	cancel := Request{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "request-loss-cleanup-retry-v2",
		Operation:       OperationJobCancelV2,
		JobCancelV2:     &JobCancelRequestV2{ContractVersion: JobContractVersionV2, JobID: harness.seed.WorkerJobID},
	}
	if response := harness.service.HandleAuthenticatedRequest(context.Background(), harness.principal, cancel); !response.OK {
		t.Fatalf("cleanup retry after loss = %#v, want success", response)
	}
}

func TestL8D6WorkerConcurrentStartPreparesExactlyOnce(t *testing.T) {
	harness := newL8D6LifecycleHarness(t, l8D6LifecycleHarnessOptions{})
	const callers = 24
	responses := make(chan Response, callers)
	var start sync.WaitGroup
	start.Add(1)
	var callersWG sync.WaitGroup
	for index := 0; index < callers; index++ {
		callersWG.Add(1)
		go func() {
			defer callersWG.Done()
			start.Wait()
			responses <- harness.service.HandleAuthenticatedRequest(context.Background(), harness.principal, harness.request)
		}()
	}
	start.Done()
	callersWG.Wait()
	close(responses)
	successes := 0
	for response := range responses {
		if !response.OK || response.JobV2 == nil {
			t.Fatalf("concurrent response = %#v, want idempotent JobV2", response)
		}
		successes++
	}
	if successes != callers {
		t.Fatalf("concurrent successes = %d, want %d", successes, callers)
	}
	if harness.runtime.preflightCallCount() != 1 || harness.preflight.prepareCallCount() != 1 || harness.preflight.abortCallCount() != 0 {
		t.Fatalf("concurrent ownership = preflight:%d prepare:%d abort:%d, want 1/1/0", harness.runtime.preflightCallCount(), harness.preflight.prepareCallCount(), harness.preflight.abortCallCount())
	}
}

func TestL8D6WorkerTypedNilRecoveryProviderFailsClosed(t *testing.T) {
	request := l8D6WorkerStartRequest(t)
	seed := l8D6WorkerSeed(t, request)
	binder, err := sandboxruntime.NewJobCredentialRuntimeBinder(&l8D6WorkerProvider{seed: seed, runtime: &l8D6WorkerRuntime{}})
	if err != nil {
		t.Fatal(err)
	}
	authority, _ := l8D6WorkerPrincipal(t)
	var typedNil *l8D6RecoveryProvider
	service, err := NewL8DurableService(L8DurableServiceOptions{
		WorkerID: seed.WorkerID, DaemonGeneration: l8WorkerV2DaemonGeneration,
		StateDir: t.TempDir() + "/jobs-v2", Binder: binder, PrincipalAuthority: authority,
		RecoveryProvider: typedNil,
	})
	if service != nil || !errors.Is(err, ErrL8ServiceUnavailable) {
		t.Fatalf("typed-nil recovery provider = %#v, %v; want unavailable", service, err)
	}
}

func TestL8D6WorkerMissingRecoveryProviderStillFailsClosedOnRetainedState(t *testing.T) {
	stateDir := t.TempDir() + "/jobs-v2"
	manager, err := newJobManagerV2(jobManagerV2Options{
		StateDir: stateDir, WorkerID: "worker-l8-neutral", DaemonGeneration: l8WorkerV2DaemonGeneration,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := l8D6WorkerStartRequest(t).JobStartV2
	seed := l8D6RecentLifecycleSeed(t, Request{DriverID: RuntimeDriverMicroVM, JobStartV2: request})
	if _, existing, err := manager.acceptCredentialSeed(RuntimeDriverMicroVM, "principal-l8-worker", *request, seed); err != nil || existing {
		t.Fatalf("accept seed = %t, %v", existing, err)
	}
	manager.close()

	binder, err := sandboxruntime.NewJobCredentialRuntimeBinder(&l8D6WorkerProvider{seed: seed, runtime: &l8D6WorkerRuntime{}})
	if err != nil {
		t.Fatal(err)
	}
	authority, _ := l8D6WorkerPrincipal(t)
	service, err := NewL8DurableService(L8DurableServiceOptions{
		WorkerID: seed.WorkerID, DaemonGeneration: l8WorkerV2DaemonGeneration,
		StateDir: stateDir, Binder: binder, PrincipalAuthority: authority,
	})
	if service != nil || !errors.Is(err, ErrL8RecoveryDependency) {
		t.Fatalf("missing recovery provider restart = %#v, %v, want recovery dependency", service, err)
	}
}

func TestL8D6WorkerSeedOnlyRestartSkipsRecoverAndStopReaps(t *testing.T) {
	stateDir := t.TempDir() + "/jobs-v2"
	manager, err := newJobManagerV2(jobManagerV2Options{
		StateDir: stateDir, WorkerID: "worker-l8-neutral", DaemonGeneration: l8WorkerV2DaemonGeneration,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := l8D6WorkerStartRequest(t).JobStartV2
	seed := l8D6RecentLifecycleSeed(t, Request{DriverID: RuntimeDriverMicroVM, JobStartV2: request})
	if _, existing, err := manager.acceptCredentialSeed(RuntimeDriverMicroVM, "principal-l8-worker", *request, seed); err != nil || existing {
		t.Fatalf("accept seed = %t, %v", existing, err)
	}
	manager.close()

	recovery := l8D6NewRecoveryProvider(t, seed, sandboxruntime.JobCredentialIdentity{})
	binder, err := sandboxruntime.NewJobCredentialRuntimeBinder(&l8D6WorkerProvider{seed: seed, runtime: &l8D6WorkerRuntime{}})
	if err != nil {
		t.Fatal(err)
	}
	authority, _ := l8D6WorkerPrincipal(t)
	service, err := NewL8DurableService(L8DurableServiceOptions{
		WorkerID: seed.WorkerID, DaemonGeneration: l8WorkerV2DaemonGeneration,
		StateDir: stateDir, Binder: binder, PrincipalAuthority: authority,
		RecoveryProvider: recovery,
	})
	if err != nil {
		t.Fatalf("seed-only restart with recovery provider: %v", err)
	}
	t.Cleanup(service.Close)
	if got, want := recovery.order.snapshot(), []string{"stop-reap", "finalize", "commit"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("seed-only recovery order = %v, want %v", got, want)
	}
	if recovery.recoverCallCount() != 0 {
		t.Fatalf("seed-only restart called RecoverJobCredentials %d times", recovery.recoverCallCount())
	}
	stored, err := service.jobs.store.load(seed.WorkerJobID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CredentialState != nil || stored.JobV2.State != JobStateInterrupted {
		t.Fatalf("seed-only restart retained live credential ownership: %#v", stored)
	}
}

func TestL8D6WorkerCompleteIdentityRestartRecoversThenAlwaysStopReaps(t *testing.T) {
	for _, name := range []string{"valid-recover", "failed-recover"} {
		t.Run(name, func(t *testing.T) {
			stateDir := t.TempDir() + "/jobs-v2"
			manager, err := newJobManagerV2(jobManagerV2Options{
				StateDir: stateDir, WorkerID: "worker-l8-neutral", DaemonGeneration: l8WorkerV2DaemonGeneration,
			})
			if err != nil {
				t.Fatal(err)
			}
			request := l8D6WorkerStartRequest(t).JobStartV2
			seed := l8D6RecentLifecycleSeed(t, Request{DriverID: RuntimeDriverMicroVM, JobStartV2: request})
			job, existing, err := manager.acceptCredentialSeed(RuntimeDriverMicroVM, "principal-l8-worker", *request, seed)
			if err != nil || existing {
				t.Fatalf("accept seed = %t, %v", existing, err)
			}
			identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, l8WorkerGuestSessionGeneration(), "helper-generation-worker")
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.persistCredentialIdentity(job.ID, "principal-l8-worker", identity); err != nil {
				t.Fatal(err)
			}
			manager.close()

			recovery := l8D6NewRecoveryProvider(t, seed, identity)
			if name == "failed-recover" {
				recovery.recoverErr = errors.New("token=recover-secret path=/private/recover.sock")
			}
			binder, err := sandboxruntime.NewJobCredentialRuntimeBinder(&l8D6WorkerProvider{seed: seed, runtime: &l8D6WorkerRuntime{}})
			if err != nil {
				t.Fatal(err)
			}
			authority, _ := l8D6WorkerPrincipal(t)
			service, err := NewL8DurableService(L8DurableServiceOptions{
				WorkerID: seed.WorkerID, DaemonGeneration: l8WorkerV2DaemonGeneration,
				StateDir: stateDir, Binder: binder, PrincipalAuthority: authority,
				RecoveryProvider: recovery,
			})
			if err != nil {
				t.Fatalf("complete-identity restart: %v", err)
			}
			t.Cleanup(service.Close)
			if got, want := recovery.order.snapshot(), []string{"recover", "stop-reap", "finalize", "commit"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("complete-identity recovery order = %v, want %v", got, want)
			}
			stored, err := service.jobs.store.load(seed.WorkerJobID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.CredentialState != nil || stored.JobV2.State != JobStateInterrupted {
				t.Fatalf("complete-identity restart retained live credential ownership: %#v", stored)
			}
			publicJSON, err := json.Marshal(stored.JobV2)
			if err != nil {
				t.Fatal(err)
			}
			l8D6AssertNoLiveCredentialLeak(t, publicJSON)
		})
	}
}

func TestL8D6WorkerReceiptOnlyRestartReplaysFinalizeAndCommit(t *testing.T) {
	stateDir := t.TempDir() + "/jobs-v2"
	manager, err := newJobManagerV2(jobManagerV2Options{
		StateDir: stateDir, WorkerID: "worker-l8-neutral", DaemonGeneration: l8WorkerV2DaemonGeneration,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := l8D6WorkerStartRequest(t).JobStartV2
	seed := l8D6RecentLifecycleSeed(t, Request{DriverID: RuntimeDriverMicroVM, JobStartV2: request})
	if _, existing, err := manager.acceptCredentialSeed(RuntimeDriverMicroVM, "principal-l8-worker", *request, seed); err != nil || existing {
		t.Fatalf("accept seed = %t, %v", existing, err)
	}
	manager.close()

	binder, err := sandboxruntime.NewJobCredentialRuntimeBinder(&l8D6WorkerProvider{seed: seed, runtime: &l8D6WorkerRuntime{}})
	if err != nil {
		t.Fatal(err)
	}
	authority, _ := l8D6WorkerPrincipal(t)
	firstRecovery := l8D6NewRecoveryProvider(t, seed, sandboxruntime.JobCredentialIdentity{})
	firstRecovery.commitErr = errors.New("commit unavailable")
	service, err := NewL8DurableService(L8DurableServiceOptions{
		WorkerID: seed.WorkerID, DaemonGeneration: l8WorkerV2DaemonGeneration,
		StateDir: stateDir, Binder: binder, PrincipalAuthority: authority, RecoveryProvider: firstRecovery,
	})
	if service != nil || !errors.Is(err, ErrL8RecoveryDependency) {
		t.Fatalf("first commit failure = %#v, %v; want retained recovery dependency", service, err)
	}
	store, err := newJobStoreV2(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := store.load(seed.WorkerJobID)
	if err != nil {
		t.Fatal(err)
	}
	if retained.CredentialState != nil || retained.CredentialRecoveryReceipt == nil {
		t.Fatalf("commit failure state = %#v, want receipt-only replay state", retained)
	}

	secondRecovery := l8D6NewRecoveryProvider(t, seed, sandboxruntime.JobCredentialIdentity{})
	service, err = NewL8DurableService(L8DurableServiceOptions{
		WorkerID: seed.WorkerID, DaemonGeneration: l8WorkerV2DaemonGeneration,
		StateDir: stateDir, Binder: binder, PrincipalAuthority: authority, RecoveryProvider: secondRecovery,
	})
	if err != nil {
		t.Fatalf("receipt-only recovery replay: %v", err)
	}
	t.Cleanup(service.Close)
	if got, want := secondRecovery.order.snapshot(), []string{"stop-reap", "finalize", "commit"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("receipt-only recovery order = %v, want %v", got, want)
	}
	stored, err := service.jobs.store.load(seed.WorkerJobID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CredentialState != nil || stored.CredentialRecoveryReceipt != nil || stored.JobV2.State != JobStateInterrupted {
		t.Fatalf("receipt-only replay did not retire durable ownership: %#v", stored)
	}
}

func TestL8D6WorkerIdentityMismatchFailsClosedBeforePrepare(t *testing.T) {
	harness := newL8D6LifecycleHarness(t, l8D6LifecycleHarnessOptions{})
	harness.provider.seed.WorkerID = "worker-neighbor"
	response := harness.service.HandleAuthenticatedRequest(context.Background(), harness.principal, harness.request)
	if response.OK || response.Error == nil || response.Error.Code != ErrorCodeInternal || harness.preflight.prepareCallCount() != 0 {
		t.Fatalf("mismatched seed = %#v, prepare calls %d", response, harness.preflight.prepareCallCount())
	}
}

func TestL8D6WorkerProtocolHasNoRenewOrRevokeOperations(t *testing.T) {
	for _, operation := range []string{"job_renew_v2", "job_revoke_v2", "job_recover_v2"} {
		if validOperation(operation) || isWorkerV2Operation(operation) {
			t.Fatalf("worker protocol reserved %s; this slice must not invent unreserved operations", operation)
		}
	}
}

func TestL8D6WorkerNeutralServiceStillAbortsWithoutPrepare(t *testing.T) {
	harness := newL8D6LifecycleHarness(t, l8D6LifecycleHarnessOptions{neutral: true})
	response := harness.neutral.HandleRequest(context.Background(), harness.request)
	if response.OK || response.Error == nil || response.Error.Code != ErrorCodeUnsupportedOp {
		t.Fatalf("neutral L8 service = %#v, want fail-closed unsupported", response)
	}
	if harness.preflight.prepareCallCount() != 0 || harness.preflight.abortCallCount() != 1 {
		t.Fatalf("neutral ownership = prepare:%d abort:%d, want 0/1", harness.preflight.prepareCallCount(), harness.preflight.abortCallCount())
	}
}

func l8D6AssertNoLiveCredentialLeak(t *testing.T, payload []byte) {
	t.Helper()
	lower := strings.ToLower(string(payload))
	for _, forbidden := range []string{
		"credentialstate", "guestsessiongeneration", "guesthelpergeneration",
		"commitid", "token=", "secret=", "/private", "unix:", "ssh_auth_sock",
		"livehandle", "execbinding", "rawvalue",
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("payload leaked %q: %s", forbidden, payload)
		}
	}
}

type l8D6LifecycleHarnessOptions struct {
	prepareErr     error
	revokeErr      error
	activeRevision uint64
	neutral        bool
}

type l8D6LifecycleHarness struct {
	service   *L8Service
	neutral   *L8Service
	principal sandboxruntime.AuthenticatedWorkerPrincipal
	request   Request
	seed      sandboxruntime.JobCredentialIdentitySeed
	identity  sandboxruntime.JobCredentialIdentity
	provider  *l8D6WorkerProvider
	runtime   *l8D6WorkerRuntime
	preflight *l8D6LifecyclePreflight
	session   *l8D6LifecycleSession
	innerLoss chan sandboxruntime.JobCredentialLoss
}

func newL8D6LifecycleHarness(t *testing.T, options l8D6LifecycleHarnessOptions) *l8D6LifecycleHarness {
	t.Helper()
	request := l8D6WorkerStartRequest(t)
	seed := l8D6RecentLifecycleSeed(t, request)
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, l8WorkerGuestSessionGeneration(), "helper-generation-worker")
	if err != nil {
		t.Fatal(err)
	}
	innerLoss := make(chan sandboxruntime.JobCredentialLoss, 1)
	revision := options.activeRevision
	if revision == 0 {
		revision = 1
	}
	session := &l8D6LifecycleSession{
		proof:     l8D6LifecycleActiveProof(t, identity, revision),
		cleanup:   l8D6LifecycleCleanupProof(t, identity, revision+1),
		revokeErr: options.revokeErr,
		loss:      innerLoss,
	}
	preflight := &l8D6LifecyclePreflight{
		identity:   identity,
		loss:       innerLoss,
		cleanup:    l8WorkerCleanupProof(t, identity),
		session:    session,
		prepareErr: options.prepareErr,
	}
	runtime := &l8D6WorkerRuntime{preflight: preflight}
	provider := &l8D6WorkerProvider{seed: seed, runtime: runtime}
	binder, err := sandboxruntime.NewJobCredentialRuntimeBinder(provider)
	if err != nil {
		t.Fatal(err)
	}
	harness := &l8D6LifecycleHarness{
		request: request, seed: seed, identity: identity,
		provider: provider, runtime: runtime, preflight: preflight, session: session, innerLoss: innerLoss,
	}
	if options.neutral {
		neutral, err := NewL8Service(binder)
		if err != nil {
			t.Fatal(err)
		}
		harness.neutral = neutral
		return harness
	}
	authority, principal := l8D6WorkerPrincipal(t)
	service, err := NewL8DurableService(L8DurableServiceOptions{
		WorkerID: seed.WorkerID, DaemonGeneration: l8WorkerV2DaemonGeneration,
		StateDir: t.TempDir() + "/jobs-v2", Binder: binder, PrincipalAuthority: authority,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	harness.service = service
	harness.principal = principal
	return harness
}

func l8D6RecentLifecycleSeed(t *testing.T, request Request) sandboxruntime.JobCredentialIdentitySeed {
	t.Helper()
	seed := l8D6WorkerSeed(t, request)
	seed.IssuedAt = time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	return seed
}

func l8D6LifecycleActiveProof(t *testing.T, identity sandboxruntime.JobCredentialIdentity, revision uint64) sandboxruntime.JobCredentialActiveProof {
	t.Helper()
	proof, err := sandboxruntime.NewJobCredentialActiveProof(sandboxruntime.JobCredentialActiveProofInput{
		ProofID:   "active-l8-worker",
		Identity:  identity,
		Revision:  revision,
		IssuedAt:  identity.IssuedAt.Add(time.Second),
		ExpiresAt: identity.IssuedAt.Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func l8D6LifecycleCleanupProof(t *testing.T, identity sandboxruntime.JobCredentialIdentity, revision uint64) sandboxruntime.JobCredentialCleanupProof {
	t.Helper()
	proof, err := sandboxruntime.NewJobCredentialCleanupProof(sandboxruntime.JobCredentialCleanupProofInput{
		ProofID:            "cleanup-l8-worker-session",
		Identity:           identity,
		Revision:           revision,
		RevokedAt:          identity.IssuedAt.Add(2 * time.Second),
		AbsenceInspectedAt: identity.IssuedAt.Add(3 * time.Second),
		AuthorityAbsent:    true,
		ResourcesAbsent:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

type l8D6LifecyclePreflight struct {
	mu           sync.Mutex
	identity     sandboxruntime.JobCredentialIdentity
	loss         chan sandboxruntime.JobCredentialLoss
	cleanup      sandboxruntime.JobCredentialCleanupProof
	session      sandboxruntime.JobCredentialSession
	prepareErr   error
	prepareCalls int
	abortCalls   int
}

func (preflight *l8D6LifecyclePreflight) Identity() sandboxruntime.JobCredentialIdentity {
	return preflight.identity
}

func (preflight *l8D6LifecyclePreflight) PrepareJobCredentials(context.Context, sandboxruntime.JobCredentialPrepareRequest) (sandboxruntime.JobCredentialSession, error) {
	preflight.mu.Lock()
	defer preflight.mu.Unlock()
	preflight.prepareCalls++
	if preflight.prepareErr != nil {
		return nil, preflight.prepareErr
	}
	return preflight.session, nil
}

func (preflight *l8D6LifecyclePreflight) Abort(context.Context) (sandboxruntime.JobCredentialCleanupProof, error) {
	preflight.mu.Lock()
	defer preflight.mu.Unlock()
	preflight.abortCalls++
	return preflight.cleanup, nil
}

func (preflight *l8D6LifecyclePreflight) Loss() <-chan sandboxruntime.JobCredentialLoss {
	return preflight.loss
}

func (preflight *l8D6LifecyclePreflight) prepareCallCount() int {
	preflight.mu.Lock()
	defer preflight.mu.Unlock()
	return preflight.prepareCalls
}

func (preflight *l8D6LifecyclePreflight) abortCallCount() int {
	preflight.mu.Lock()
	defer preflight.mu.Unlock()
	return preflight.abortCalls
}

type l8D6LifecycleSession struct {
	mu          sync.Mutex
	proof       sandboxruntime.JobCredentialActiveProof
	cleanup     sandboxruntime.JobCredentialCleanupProof
	loss        <-chan sandboxruntime.JobCredentialLoss
	revokeCalls int
	onRevoke    func()
	revokeErr   error
}

func (*l8D6LifecycleSession) ExecBinding() sandboxruntime.JobCredentialExecBinding { return nil }

func (session *l8D6LifecycleSession) ActiveProof() sandboxruntime.JobCredentialActiveProof {
	return session.proof
}

func (session *l8D6LifecycleSession) Renew(context.Context) (sandboxruntime.JobCredentialActiveProof, error) {
	return session.proof, errors.New("renew is not a worker-v2 protocol operation")
}

func (session *l8D6LifecycleSession) Revoke(context.Context, sandboxruntime.JobCredentialRevokeReason) (sandboxruntime.JobCredentialCleanupProof, error) {
	session.mu.Lock()
	session.revokeCalls++
	onRevoke := session.onRevoke
	revokeErr := session.revokeErr
	session.mu.Unlock()
	if onRevoke != nil {
		onRevoke()
	}
	return session.cleanup, revokeErr
}

func (session *l8D6LifecycleSession) Loss() <-chan sandboxruntime.JobCredentialLoss {
	return session.loss
}

func (session *l8D6LifecycleSession) revokeCallCount() int {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.revokeCalls
}

func (session *l8D6LifecycleSession) setRevokeError(err error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.revokeErr = err
}

func (session *l8D6LifecycleSession) setOnRevoke(onRevoke func()) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.onRevoke = onRevoke
}

type l8D6RecoveryProvider struct {
	mu           sync.Mutex
	seed         sandboxruntime.JobCredentialIdentitySeed
	identity     sandboxruntime.JobCredentialIdentity
	cleanup      sandboxruntime.JobCredentialCleanupProof
	order        *l8D6OrderRecorder
	recoverErr   error
	commitErr    error
	binding      *l8D6RecoveryBinding
	recoverCalls int
}

func l8D6NewRecoveryProvider(t *testing.T, seed sandboxruntime.JobCredentialIdentitySeed, identity sandboxruntime.JobCredentialIdentity) *l8D6RecoveryProvider {
	t.Helper()
	inspectedAt := time.Now().UTC()
	proof, err := sandboxruntime.NewJobCredentialRuntimeAbsenceProof(sandboxruntime.JobCredentialRuntimeAbsenceProofInput{
		Seed: seed, AbsenceInspectedAt: inspectedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	provider := &l8D6RecoveryProvider{seed: seed, identity: identity, order: &l8D6OrderRecorder{}}
	if identity.WorkerJobID != "" {
		provider.cleanup = l8D6LifecycleCleanupProof(t, identity, 2)
	}
	provider.binding = &l8D6RecoveryBinding{
		provider: provider,
		proof:    proof,
		receipt: sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt{
			CommitID:          l8WorkerGuestSessionGeneration(),
			FinalizedRevision: 1,
		},
	}
	return provider
}

func (provider *l8D6RecoveryProvider) BindJobCredentialRuntimeRecovery(_ context.Context, seed sandboxruntime.JobCredentialIdentitySeed) (sandboxruntime.JobCredentialRuntimeRecoveryBinding, error) {
	if seed.WorkerJobID != provider.seed.WorkerJobID || seed.WorkerID != provider.seed.WorkerID {
		return nil, errors.New("recovery seed identity mismatch")
	}
	return provider.binding, nil
}

func (provider *l8D6RecoveryProvider) recoverCallCount() int {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.recoverCalls
}

type l8D6RecoveryBinding struct {
	provider *l8D6RecoveryProvider
	proof    sandboxruntime.JobCredentialRuntimeAbsenceProof
	receipt  sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt
}

func (binding *l8D6RecoveryBinding) RecoverJobCredentials(context.Context, sandboxruntime.JobCredentialRecoveryRequest) (sandboxruntime.JobCredentialCleanupProof, error) {
	binding.provider.mu.Lock()
	binding.provider.recoverCalls++
	binding.provider.mu.Unlock()
	binding.provider.order.add("recover")
	if binding.provider.recoverErr != nil {
		return sandboxruntime.JobCredentialCleanupProof{}, binding.provider.recoverErr
	}
	if binding.provider.identity.WorkerJobID == "" {
		return sandboxruntime.JobCredentialCleanupProof{}, errors.New("seed-only recovery must not call RecoverJobCredentials")
	}
	return binding.provider.cleanup, nil
}

func (binding *l8D6RecoveryBinding) StopReapJobCredentialRuntime(context.Context) (sandboxruntime.JobCredentialRuntimeAbsenceProof, error) {
	binding.provider.order.add("stop-reap")
	return binding.proof, nil
}

func (binding *l8D6RecoveryBinding) FinalizeJobCredentialRuntimeRecovery(context.Context, sandboxruntime.JobCredentialRuntimeAbsenceProof) (sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt, error) {
	binding.provider.order.add("finalize")
	return binding.receipt, nil
}

func (binding *l8D6RecoveryBinding) CommitJobCredentialRuntimeRecovery(context.Context, sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) error {
	binding.provider.order.add("commit")
	return binding.provider.commitErr
}

func (binding *l8D6RecoveryBinding) Close(context.Context) error { return nil }
