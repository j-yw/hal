package credentialhelper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type servicePrepareTestCore struct {
	preparation   *servicePrepareTestPreparation
	beginCalls    int
	beginRequest  CorePrepareRequest
	renewCalls    int
	renewRequest  CoreRenewRequest
	renewErr      error
	revokeCalls   int
	revokeRequest CoreRevokeRequest
	revokeErr     error
}

func (core *servicePrepareTestCore) BeginPrepare(_ context.Context, request CorePrepareRequest) (CorePreparation, error) {
	core.beginCalls++
	core.beginRequest = request
	core.preparation.cleanup = request.cleanup
	return core.preparation, nil
}

func (*servicePrepareTestCore) BeginExec(context.Context, CoreExecRequest, credentialmemory.BorrowedView) (CoreExecution, error) {
	return nil, errors.New("unexpected BeginExec")
}

func (core *servicePrepareTestCore) Renew(_ context.Context, request CoreRenewRequest) error {
	core.renewCalls++
	core.renewRequest = request
	return core.renewErr
}

func (core *servicePrepareTestCore) Revoke(_ context.Context, request CoreRevokeRequest) (CoreCleanupResult, error) {
	core.revokeCalls++
	core.revokeRequest = request
	if core.revokeErr != nil {
		return CoreCleanupResult{}, core.revokeErr
	}
	return NewCoreCleanupResult(request.cleanup, CoreCleanupComplete, true, true)
}

func (*servicePrepareTestCore) Inspect(context.Context, CoreInspectRequest) (CoreInspection, error) {
	return CoreInspection{}, errors.New("unexpected Inspect")
}

func (*servicePrepareTestCore) Close(context.Context) error { return nil }

type servicePrepareTestPreparation struct {
	completeGenerations CoreGenerations
	expiresUnixNano     int64
	bindingCount        uint16
	cleanup             CoreCleanupCapability
	stageCalls          int
	stageRequest        CoreFileRequest
	stageErr            error
	commitCalls         int
	commitRequest       CoreCommitRequest
	commitErr           error
	rollbackCalls       int
}

func (preparation *servicePrepareTestPreparation) StageFile(_ context.Context, request CoreFileRequest, view credentialmemory.BorrowedView) error {
	preparation.stageCalls++
	preparation.stageRequest = request
	if preparation.stageErr != nil {
		return preparation.stageErr
	}
	if view.Len() != int(request.fileLength) {
		return ErrContractResultMatrix
	}
	return nil
}

type servicePrepareDestroyFailureBody struct {
	transportTestBody
	err error
}

func (body servicePrepareDestroyFailureBody) Destroy(context.Context) error {
	return body.err
}

func (preparation *servicePrepareTestPreparation) Commit(_ context.Context, request CoreCommitRequest) (CorePreparedResult, error) {
	preparation.commitCalls++
	preparation.commitRequest = request
	if preparation.commitErr != nil {
		return CorePreparedResult{}, preparation.commitErr
	}
	return NewCorePreparedResult(request.prepared, preparation.completeGenerations, preparation.expiresUnixNano, preparation.bindingCount, request.manifestSHA256, request.transactionSHA256)
}

func (preparation *servicePrepareTestPreparation) Rollback(context.Context) (CoreCleanupResult, error) {
	preparation.rollbackCalls++
	return NewCoreCleanupResult(preparation.cleanup, CoreCleanupComplete, true, true)
}

type servicePrepareTestRuntime struct {
	bootstrap    ServiceBootstrap
	observations []ServiceJobObservation
	observeErrs  map[int]error
	observeCalls int
	requests     []ServiceJobObservationRequest
}

func (runtime *servicePrepareTestRuntime) Bootstrap(context.Context) (ServiceBootstrap, error) {
	return runtime.bootstrap, nil
}

func (*servicePrepareTestRuntime) BindAgent(context.Context, ServiceAgentBindingRequest, ReceivedCapability) error {
	return errors.New("unexpected BindAgent")
}

func (runtime *servicePrepareTestRuntime) ObserveJob(_ context.Context, request ServiceJobObservationRequest) (ServiceJobObservation, error) {
	call := runtime.observeCalls
	runtime.observeCalls++
	runtime.requests = append(runtime.requests, request)
	if err := runtime.observeErrs[call]; err != nil {
		return ServiceJobObservation{}, err
	}
	if call >= len(runtime.observations) {
		return ServiceJobObservation{}, errors.New("unexpected ObserveJob")
	}
	return runtime.observations[call], nil
}

func (*servicePrepareTestRuntime) Loss() <-chan ServiceLoss { return nil }
func (*servicePrepareTestRuntime) BeginCleanup() (ServiceCleanupBudget, error) {
	return nil, errors.New("unexpected BeginCleanup")
}
func (*servicePrepareTestRuntime) Close(context.Context) error { return nil }

type servicePrepareTestFixture struct {
	service      *Service
	core         *servicePrepareTestCore
	preparation  *servicePrepareTestPreparation
	runtime      *servicePrepareTestRuntime
	header       credentialprotocol.HelperPacketHeader
	manifest     ManifestCapability
	begin        credentialprotocol.HelperPrepareBeginBody
	transaction  *credentialprotocol.HelperPrepareTransaction
	payload      []byte
	payloadSHA   [32]byte
	complete     CoreGenerations
	expires      int64
	hardExpiry   int64
	observedBase int64
}

func newServicePrepareTestFixture(t *testing.T) *servicePrepareTestFixture {
	t.Helper()
	payload := []byte("prepared credential")
	payloadSHA := sha256.Sum256(payload)
	binding := credentialprotocol.HelperBindingManifestRecord{
		BindingID:         "binding-a",
		Mode:              credentialprotocol.DeliveryModeFileTmpfs,
		TargetPath:        "run/credential",
		DeclaredFileBytes: uint32(len(payload)),
		FileSHA256:        payloadSHA,
	}
	manifest, err := NewManifestCapability([]credentialprotocol.HelperBindingManifestRecord{binding})
	if err != nil {
		t.Fatalf("NewManifestCapability: %v", err)
	}
	header := credentialprotocol.HelperPacketHeader{
		RequestID:                     [16]byte{1},
		GuestCredentialIdentityDigest: sha256.Sum256([]byte("identity")),
		BootNonce:                     sha256.Sum256([]byte("boot nonce")),
	}
	expires := int64(80)
	begin := credentialprotocol.HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: expires, Bindings: []credentialprotocol.HelperBindingManifestRecord{binding}}
	correlation, err := credentialprotocol.NewHelperPrepareTransactionCorrelation(header.RequestID, header.GuestCredentialIdentityDigest, begin.Revision, begin.ExpiryUnixNano)
	if err != nil {
		t.Fatalf("NewHelperPrepareTransactionCorrelation: %v", err)
	}
	transaction, err := credentialprotocol.NewHelperPrepareTransaction(correlation, begin, manifest.SHA256())
	if err != nil {
		t.Fatalf("NewHelperPrepareTransaction: %v", err)
	}
	complete, err := NewCoreGenerations("boot-a", "helper-a", "job-a", "monitor-a", "mount-a", "cgroup-a")
	if err != nil {
		t.Fatalf("NewCoreGenerations: %v", err)
	}
	bootstrap, err := NewServiceBootstrap(header.BootNonce, complete.boot, complete.helper)
	if err != nil {
		t.Fatalf("NewServiceBootstrap: %v", err)
	}
	observations := make([]ServiceJobObservation, 3)
	for index, observed := range []int64{10, 20, 30} {
		observations[index], err = NewServiceJobObservation(complete, observed, 100)
		if err != nil {
			t.Fatalf("NewServiceJobObservation(%d): %v", observed, err)
		}
	}
	preparation := &servicePrepareTestPreparation{completeGenerations: complete, expiresUnixNano: expires, bindingCount: manifest.Count()}
	core := &servicePrepareTestCore{preparation: preparation}
	runtime := &servicePrepareTestRuntime{bootstrap: bootstrap, observations: observations, observeErrs: make(map[int]error)}
	return &servicePrepareTestFixture{
		service: &Service{state: &serviceState{}, core: core, runtime: runtime},
		core:    core, preparation: preparation, runtime: runtime, header: header,
		manifest: manifest, begin: begin, transaction: transaction, payload: payload,
		payloadSHA: payloadSHA, complete: complete, expires: expires, hardExpiry: 100, observedBase: 10,
	}
}

func (fixture *servicePrepareTestFixture) packet(packetType credentialprotocol.PacketType, arm receivedPacketArm, body []byte) (ReceivedPacket, transportTestBody) {
	header := fixture.header
	header.Type = packetType
	header.BodyLength = uint32(len(body))
	receivedBody := newTransportTestBody(body, len(body))
	return ReceivedPacket{header: header, arm: arm, body: receivedBody}, receivedBody
}

func (fixture *servicePrepareTestFixture) beginPacket(t *testing.T) (ReceivedPacket, transportTestBody) {
	t.Helper()
	return fixture.packet(credentialprotocol.PacketTypePrepareBegin, ReceivedPrepareBegin{
		revision: fixture.begin.Revision, expiryUnixNano: fixture.begin.ExpiryUnixNano,
		manifest: fixture.manifest, transaction: fixture.transaction,
	}, []byte("begin"))
}

func (fixture *servicePrepareTestFixture) filePacket() (ReceivedPacket, transportTestBody) {
	return fixture.packet(credentialprotocol.PacketTypePrepareFile, ReceivedPrepareFile{
		revision: 1, bindingIndex: 0, fileLength: uint32(len(fixture.payload)), fileSHA256: fixture.payloadSHA,
	}, fixture.payload)
}

func (fixture *servicePrepareTestFixture) commitPacket() (ReceivedPacket, transportTestBody) {
	return fixture.packet(credentialprotocol.PacketTypePrepareCommit, ReceivedPrepareCommit{
		revision: 1, manifestSHA256: fixture.manifest.SHA256(),
	}, []byte("commit"))
}

func (fixture *servicePrepareTestFixture) renewPacket(proof credentialprotocol.SafeID) (ReceivedPacket, transportTestBody) {
	header := fixture.header
	header.RequestID = [16]byte{2}
	fixture.header = header
	packet, body := fixture.packet(credentialprotocol.PacketTypeRenew, ReceivedRenew{
		revision: 2, expiryUnixNano: 90, priorProofSHA256: hashOpaqueToken(renewProofDomain, proof),
	}, []byte("renew"))
	fixture.header.RequestID = [16]byte{1}
	return packet, body
}

func (fixture *servicePrepareTestFixture) prepareThroughFile(t *testing.T) {
	t.Helper()
	beginPacket, _ := fixture.beginPacket(t)
	if err := fixture.service.handlePrepareBegin(context.Background(), beginPacket); err != nil {
		t.Fatalf("handlePrepareBegin: %v", err)
	}
	filePacket, _ := fixture.filePacket()
	if err := fixture.service.handlePrepareFile(context.Background(), filePacket); err != nil {
		t.Fatalf("handlePrepareFile: %v", err)
	}
}

func (fixture *servicePrepareTestFixture) prepareThroughCommit(t *testing.T) {
	t.Helper()
	fixture.prepareThroughFile(t)
	commitPacket, _ := fixture.commitPacket()
	if err := fixture.service.handlePrepareCommit(context.Background(), commitPacket); err != nil {
		t.Fatalf("handlePrepareCommit: %v", err)
	}
}

func TestServiceCoreCapabilityDigestExactVectorAndKindSeparation(t *testing.T) {
	t.Parallel()

	var requestID [16]byte
	for index := range requestID {
		requestID[index] = byte(index + 1)
	}
	var identityDigest [32]byte
	var bootNonce [32]byte
	for index := range identityDigest {
		identityDigest[index] = byte(index + 33)
		bootNonce[index] = byte(index + 65)
	}
	generations, err := NewCoreGenerations("boot-a", "helper-a", "job-a", "", "", "")
	if err != nil {
		t.Fatalf("NewCoreGenerations: %v", err)
	}
	correlation := requestCorrelation{
		requestID:      requestID,
		identityDigest: identityDigest,
		revision:       7,
	}
	wantHex := map[serviceCoreCapabilityKind]string{
		serviceCoreCapabilityPreparation: "ba89b4239a78185be3e15bceebeac8bd51d6f6b9af543f4a5892d870a5432c0a",
		serviceCoreCapabilityPrepared:    "d234eeca44707c30eb12407242551e6c1e90f7b20915f3b65dc06055e8955b22",
		serviceCoreCapabilityExecution:   "0775c24ab8bc3ec967356dfe59372f2c6931459200526f63b0553e7a9766e1a9",
		serviceCoreCapabilityCleanup:     "a071de2b1c59ab44342a686cfa8aecaad605985063285db10d67841ec15b4aa3",
	}
	seen := make(map[[32]byte]serviceCoreCapabilityKind, len(wantHex))
	for kind, encoded := range wantHex {
		wantBytes, decodeErr := hex.DecodeString(encoded)
		if decodeErr != nil {
			t.Fatalf("decode vector for kind %d: %v", kind, decodeErr)
		}
		var want [32]byte
		copy(want[:], wantBytes)
		got, digestErr := newServiceCoreCapabilityDigest(kind, correlation, generations, bootNonce)
		if digestErr != nil {
			t.Fatalf("newServiceCoreCapabilityDigest(%d): %v", kind, digestErr)
		}
		if got != want {
			t.Fatalf("newServiceCoreCapabilityDigest(%d) = %x, want %x", kind, got, want)
		}
		if prior, duplicate := seen[got]; duplicate {
			t.Fatalf("kind %d aliases kind %d", kind, prior)
		}
		seen[got] = kind
	}

	if _, err := newServiceCoreCapabilityDigest(0, correlation, generations, bootNonce); !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("invalid kind error = %v, want %v", err, ErrContractInvalidArgument)
	}
	if _, err := newServiceCoreCapabilityDigest(serviceCoreCapabilityPreparation, requestCorrelation{}, generations, bootNonce); !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("invalid correlation error = %v, want %v", err, ErrContractInvalidArgument)
	}
	if _, err := newServiceCoreCapabilityDigest(serviceCoreCapabilityPreparation, correlation, CoreGenerations{}, bootNonce); !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("invalid generations error = %v, want %v", err, ErrContractInvalidArgument)
	}
	if _, err := newServiceCoreCapabilityDigest(serviceCoreCapabilityPreparation, correlation, generations, [32]byte{}); !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("zero nonce error = %v, want %v", err, ErrContractInvalidArgument)
	}
}

func TestServicePrepareCapabilityTupleUsesPartialGenerations(t *testing.T) {
	t.Parallel()

	partial, err := NewCoreGenerations("boot-a", "helper-a", "job-a", "", "", "")
	if err != nil {
		t.Fatalf("NewCoreGenerations(partial): %v", err)
	}
	complete, err := NewCoreGenerations("boot-a", "helper-a", "job-a", "monitor-a", "mount-a", "cgroup-a")
	if err != nil {
		t.Fatalf("NewCoreGenerations(complete): %v", err)
	}
	correlation := requestCorrelation{
		requestID:      [16]byte{1},
		identityDigest: [32]byte{1},
		revision:       1,
	}
	bootNonce := [32]byte{1}

	capabilities, err := newServicePrepareCapabilities(correlation, partial, bootNonce)
	if err != nil {
		t.Fatalf("newServicePrepareCapabilities(partial): %v", err)
	}
	if !validCoreCapabilityDigest(capabilities.preparation.digest) ||
		!validCoreCapabilityDigest(capabilities.prepared.digest) ||
		!validCoreCapabilityDigest(capabilities.cleanup.digest) {
		t.Fatal("prepare capability tuple contains an empty digest")
	}
	if _, err := newServicePrepareCapabilities(correlation, complete, bootNonce); !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("complete generations error = %v, want %v", err, ErrContractInvalidArgument)
	}
}

func TestServicePrepareFileCommitRenewLifecycle(t *testing.T) {
	t.Parallel()
	fixture := newServicePrepareTestFixture(t)

	beginPacket, beginBody := fixture.beginPacket(t)
	if err := fixture.service.handlePrepareBegin(context.Background(), beginPacket); err != nil {
		t.Fatalf("handlePrepareBegin: %v", err)
	}
	if fixture.core.beginCalls != 1 {
		t.Fatalf("BeginPrepare calls = %d, want 1", fixture.core.beginCalls)
	}
	if !validPartialCoreGenerations(fixture.core.beginRequest.generations) || fixture.core.beginRequest.generations.monitor != "" {
		t.Fatalf("BeginPrepare generations = %#v, want exact partial tuple", fixture.core.beginRequest.generations)
	}
	if !beginBody.state.destroyed {
		t.Fatal("PrepareBegin body was not destroyed")
	}
	if !fixture.service.state.preparing.active || fixture.service.state.preparing.beginTaken {
		t.Fatalf("preparing state after Begin = %#v", fixture.service.state.preparing)
	}

	filePacket, fileBody := fixture.filePacket()
	if err := fixture.service.handlePrepareFile(context.Background(), filePacket); err != nil {
		t.Fatalf("handlePrepareFile: %v", err)
	}
	if fixture.preparation.stageCalls != 1 || fixture.preparation.stageRequest.bindingIndex != 0 {
		t.Fatalf("StageFile calls/request = %d/%#v", fixture.preparation.stageCalls, fixture.preparation.stageRequest)
	}
	if snapshot := fixture.transaction.Snapshot(); snapshot.AcceptedFileCount != 1 || snapshot.PendingFile || snapshot.Terminal {
		t.Fatalf("transaction after File = %#v", snapshot)
	}
	if !fileBody.state.destroyed || fixture.service.state.preparing.fileTaken {
		t.Fatalf("file cleanup/latch = destroyed %v, taken %v", fileBody.state.destroyed, fixture.service.state.preparing.fileTaken)
	}

	commitPacket, commitBody := fixture.commitPacket()
	if err := fixture.service.handlePrepareCommit(context.Background(), commitPacket); err != nil {
		t.Fatalf("handlePrepareCommit: %v", err)
	}
	if fixture.preparation.commitCalls != 1 || fixture.preparation.rollbackCalls != 0 || fixture.core.revokeCalls != 0 {
		t.Fatalf("commit/rollback/revoke calls = %d/%d/%d", fixture.preparation.commitCalls, fixture.preparation.rollbackCalls, fixture.core.revokeCalls)
	}
	if !commitBody.state.destroyed || !fixture.transaction.Committed() {
		t.Fatalf("commit body/transaction = destroyed %v, committed %v", commitBody.state.destroyed, fixture.transaction.Committed())
	}
	preparedBeforeRenew := fixture.service.state.prepared
	if !preparedBeforeRenew.active || fixture.service.state.preparing.active || preparedBeforeRenew.manifest != fixture.manifest || preparedBeforeRenew.bindingCount != fixture.manifest.Count() {
		t.Fatalf("prepared activation = %#v", preparedBeforeRenew)
	}

	renewPacket, renewBody := fixture.renewPacket(preparedBeforeRenew.activeProofID)
	if err := fixture.service.handleRenew(context.Background(), renewPacket); err != nil {
		t.Fatalf("handleRenew: %v", err)
	}
	preparedAfterRenew := fixture.service.state.prepared
	if fixture.core.renewCalls != 1 || fixture.core.renewRequest.Revision() != 2 || preparedAfterRenew.revision != 2 || preparedAfterRenew.expiresUnixNano != 90 || preparedAfterRenew.observedUnixNano != 30 {
		t.Fatalf("renew request/state = calls %d, request %#v, state %#v", fixture.core.renewCalls, fixture.core.renewRequest, preparedAfterRenew)
	}
	if preparedAfterRenew.issuingCorrelation != preparedBeforeRenew.issuingCorrelation || preparedAfterRenew.manifest != preparedBeforeRenew.manifest || preparedAfterRenew.cleanup != preparedBeforeRenew.cleanup || preparedAfterRenew.generations != preparedBeforeRenew.generations {
		t.Fatal("Renew changed immutable prepared activation ownership")
	}
	if !renewBody.state.destroyed {
		t.Fatal("Renew body was not destroyed")
	}
}

func TestServicePrepareBeginReservationRejectsDuplicateBeforeCore(t *testing.T) {
	t.Parallel()
	fixture := newServicePrepareTestFixture(t)
	first, _ := fixture.beginPacket(t)
	if err := fixture.service.handlePrepareBegin(context.Background(), first); err != nil {
		t.Fatalf("first handlePrepareBegin: %v", err)
	}

	correlation, err := credentialprotocol.NewHelperPrepareTransactionCorrelation(fixture.header.RequestID, fixture.header.GuestCredentialIdentityDigest, fixture.begin.Revision, fixture.begin.ExpiryUnixNano)
	if err != nil {
		t.Fatal(err)
	}
	duplicateTransaction, err := credentialprotocol.NewHelperPrepareTransaction(correlation, fixture.begin, fixture.manifest.SHA256())
	if err != nil {
		t.Fatal(err)
	}
	duplicate, duplicateBody := fixture.packet(credentialprotocol.PacketTypePrepareBegin, ReceivedPrepareBegin{
		revision: fixture.begin.Revision, expiryUnixNano: fixture.begin.ExpiryUnixNano,
		manifest: fixture.manifest, transaction: duplicateTransaction,
	}, []byte("duplicate"))
	if err := fixture.service.handlePrepareBegin(context.Background(), duplicate); !errors.Is(err, ErrContractTransition) {
		t.Fatalf("duplicate handlePrepareBegin error = %v, want %v", err, ErrContractTransition)
	}
	if fixture.core.beginCalls != 1 {
		t.Fatalf("BeginPrepare calls = %d, want 1", fixture.core.beginCalls)
	}
	if !duplicateTransaction.Terminal() || !duplicateBody.state.destroyed {
		t.Fatalf("duplicate cleanup = transaction terminal %v, body destroyed %v", duplicateTransaction.Terminal(), duplicateBody.state.destroyed)
	}
}

func TestServicePrepareCommitFailureRevokesWithoutRollback(t *testing.T) {
	t.Parallel()
	fixture := newServicePrepareTestFixture(t)
	fixture.prepareThroughFile(t)
	commitFailure := errors.New("commit failed after call began")
	fixture.preparation.commitErr = commitFailure
	packet, body := fixture.commitPacket()
	if err := fixture.service.handlePrepareCommit(context.Background(), packet); !errors.Is(err, commitFailure) {
		t.Fatalf("handlePrepareCommit error = %v, want %v", err, commitFailure)
	}
	if fixture.preparation.commitCalls != 1 || fixture.preparation.rollbackCalls != 0 || fixture.core.revokeCalls != 1 {
		t.Fatalf("commit/rollback/revoke calls = %d/%d/%d", fixture.preparation.commitCalls, fixture.preparation.rollbackCalls, fixture.core.revokeCalls)
	}
	if fixture.core.revokeRequest.correlation.requestID != fixture.header.RequestID || fixture.core.revokeRequest.correlation.revision != 1 {
		t.Fatalf("revoke correlation = %#v", fixture.core.revokeRequest.correlation)
	}
	if fixture.service.state.preparing.active || fixture.service.state.prepared.active || !body.state.destroyed {
		t.Fatalf("post-failure ownership = preparing %v, prepared %v, body destroyed %v", fixture.service.state.preparing.active, fixture.service.state.prepared.active, body.state.destroyed)
	}
}

func TestServicePrepareCommitRejectsObservationDrift(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		observation func(*testing.T, *servicePrepareTestFixture) ServiceJobObservation
	}{
		{
			name: "generation tuple",
			observation: func(t *testing.T, fixture *servicePrepareTestFixture) ServiceJobObservation {
				t.Helper()
				generations, err := NewCoreGenerations(fixture.complete.boot, fixture.complete.helper, "job-b", "monitor-b", "mount-b", "cgroup-b")
				if err != nil {
					t.Fatal(err)
				}
				observation, err := NewServiceJobObservation(generations, 20, fixture.hardExpiry)
				if err != nil {
					t.Fatal(err)
				}
				fixture.preparation.completeGenerations = generations
				return observation
			},
		},
		{
			name: "hard expiry horizon",
			observation: func(t *testing.T, fixture *servicePrepareTestFixture) ServiceJobObservation {
				t.Helper()
				observation, err := NewServiceJobObservation(fixture.complete, 20, 200)
				if err != nil {
					t.Fatal(err)
				}
				return observation
			},
		},
		{
			name: "regressed observed time",
			observation: func(t *testing.T, fixture *servicePrepareTestFixture) ServiceJobObservation {
				t.Helper()
				observation, err := NewServiceJobObservation(fixture.complete, 5, fixture.hardExpiry)
				if err != nil {
					t.Fatal(err)
				}
				return observation
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newServicePrepareTestFixture(t)
			fixture.prepareThroughFile(t)
			fixture.runtime.observations[1] = test.observation(t, fixture)
			packet, body := fixture.commitPacket()
			if err := fixture.service.handlePrepareCommit(context.Background(), packet); !errors.Is(err, ErrContractCorrelation) {
				t.Fatalf("handlePrepareCommit error = %v, want %v", err, ErrContractCorrelation)
			}
			if fixture.preparation.commitCalls != 1 || fixture.preparation.rollbackCalls != 0 || fixture.core.revokeCalls != 1 {
				t.Fatalf("commit/rollback/revoke calls = %d/%d/%d", fixture.preparation.commitCalls, fixture.preparation.rollbackCalls, fixture.core.revokeCalls)
			}
			if fixture.service.state.preparing.active || fixture.service.state.prepared.active || !body.state.destroyed {
				t.Fatalf("drift cleanup = preparing %v, prepared %v, body destroyed %v", fixture.service.state.preparing.active, fixture.service.state.prepared.active, body.state.destroyed)
			}
		})
	}
}

func TestServiceRenewDependencyFailureRevokesIssuingActivation(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		configure   func(*servicePrepareTestFixture, error)
		wantRenew   int
		wantObserve int
	}{
		{
			name: "runtime observation",
			configure: func(fixture *servicePrepareTestFixture, failure error) {
				fixture.runtime.observeErrs[2] = failure
			},
			wantRenew: 0, wantObserve: 3,
		},
		{
			name: "core renew",
			configure: func(fixture *servicePrepareTestFixture, failure error) {
				fixture.core.renewErr = failure
			},
			wantRenew: 1, wantObserve: 3,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newServicePrepareTestFixture(t)
			fixture.prepareThroughCommit(t)
			activation := fixture.service.state.prepared
			failure := errors.New("trusted dependency failed")
			test.configure(fixture, failure)
			packet, body := fixture.renewPacket(activation.activeProofID)
			if err := fixture.service.handleRenew(context.Background(), packet); !errors.Is(err, ErrContractOwnership) {
				t.Fatalf("handleRenew error = %v, want %v", err, ErrContractOwnership)
			}
			if fixture.core.renewCalls != test.wantRenew || fixture.runtime.observeCalls != test.wantObserve || fixture.core.revokeCalls != 1 {
				t.Fatalf("renew/observe/revoke calls = %d/%d/%d, want %d/%d/1", fixture.core.renewCalls, fixture.runtime.observeCalls, fixture.core.revokeCalls, test.wantRenew, test.wantObserve)
			}
			if fixture.core.revokeRequest.correlation.requestID != activation.issuingCorrelation.requestID || fixture.core.revokeRequest.correlation.identityDigest != activation.issuingCorrelation.identityDigest || fixture.core.revokeRequest.correlation.revision != activation.revision {
				t.Fatalf("revoke correlation = %#v, issuing = %#v", fixture.core.revokeRequest.correlation, activation.issuingCorrelation)
			}
			if fixture.service.state.prepared.active || !body.state.destroyed {
				t.Fatalf("renew failure cleanup = active %v, body destroyed %v", fixture.service.state.prepared.active, body.state.destroyed)
			}
		})
	}
}

func TestServiceRenewRejectsStaleProofBeforeDependencies(t *testing.T) {
	t.Parallel()
	fixture := newServicePrepareTestFixture(t)
	fixture.prepareThroughCommit(t)
	activation := fixture.service.state.prepared
	packet, body := fixture.renewPacket("foreign-proof")
	if err := fixture.service.handleRenew(context.Background(), packet); !errors.Is(err, ErrContractCorrelation) {
		t.Fatalf("handleRenew error = %v, want %v", err, ErrContractCorrelation)
	}
	if fixture.runtime.observeCalls != 2 || fixture.core.renewCalls != 0 || fixture.core.revokeCalls != 0 {
		t.Fatalf("observe/renew/revoke calls = %d/%d/%d, want 2/0/0", fixture.runtime.observeCalls, fixture.core.renewCalls, fixture.core.revokeCalls)
	}
	if fixture.service.state.prepared != activation || !body.state.destroyed {
		t.Fatalf("stale renew changed activation or leaked body: active=%#v destroyed=%v", fixture.service.state.prepared, body.state.destroyed)
	}
}

func TestServicePrepareFileStageFailureAbortsOwnedPreparation(t *testing.T) {
	t.Parallel()
	fixture := newServicePrepareTestFixture(t)
	beginPacket, _ := fixture.beginPacket(t)
	if err := fixture.service.handlePrepareBegin(context.Background(), beginPacket); err != nil {
		t.Fatalf("handlePrepareBegin: %v", err)
	}
	stageFailure := errors.New("stage failed")
	fixture.preparation.stageErr = stageFailure
	filePacket, body := fixture.filePacket()
	if err := fixture.service.handlePrepareFile(context.Background(), filePacket); !errors.Is(err, stageFailure) {
		t.Fatalf("handlePrepareFile error = %v, want %v", err, stageFailure)
	}
	if fixture.preparation.stageCalls != 1 || fixture.preparation.rollbackCalls != 1 || fixture.core.revokeCalls != 0 {
		t.Fatalf("stage/rollback/revoke calls = %d/%d/%d", fixture.preparation.stageCalls, fixture.preparation.rollbackCalls, fixture.core.revokeCalls)
	}
	if !fixture.transaction.Terminal() || fixture.service.state.preparing.active || !body.state.destroyed {
		t.Fatalf("stage failure cleanup = terminal %v, active %v, body destroyed %v", fixture.transaction.Terminal(), fixture.service.state.preparing.active, body.state.destroyed)
	}
}

func TestServicePacketCleanupFailureConvergesOwnedCoreState(t *testing.T) {
	t.Parallel()
	cleanupFailure := errors.New("packet cleanup failed")

	t.Run("prepare begin rolls back", func(t *testing.T) {
		t.Parallel()
		fixture := newServicePrepareTestFixture(t)
		packet, body := fixture.beginPacket(t)
		packet.body = servicePrepareDestroyFailureBody{transportTestBody: body, err: cleanupFailure}
		if err := fixture.service.handlePrepareBegin(context.Background(), packet); !errors.Is(err, ErrContractOwnership) {
			t.Fatalf("handlePrepareBegin error = %v, want %v", err, ErrContractOwnership)
		}
		if fixture.preparation.rollbackCalls != 1 || fixture.core.revokeCalls != 0 || !fixture.transaction.Terminal() || fixture.service.state.preparing.active {
			t.Fatalf("begin cleanup = rollback %d, revoke %d, terminal %v, active %v", fixture.preparation.rollbackCalls, fixture.core.revokeCalls, fixture.transaction.Terminal(), fixture.service.state.preparing.active)
		}
	})

	t.Run("prepare commit revokes", func(t *testing.T) {
		t.Parallel()
		fixture := newServicePrepareTestFixture(t)
		fixture.prepareThroughFile(t)
		packet, body := fixture.commitPacket()
		packet.body = servicePrepareDestroyFailureBody{transportTestBody: body, err: cleanupFailure}
		if err := fixture.service.handlePrepareCommit(context.Background(), packet); !errors.Is(err, ErrContractOwnership) {
			t.Fatalf("handlePrepareCommit error = %v, want %v", err, ErrContractOwnership)
		}
		if fixture.preparation.commitCalls != 1 || fixture.preparation.rollbackCalls != 0 || fixture.core.revokeCalls != 1 || fixture.service.state.prepared.active {
			t.Fatalf("commit cleanup = commit %d, rollback %d, revoke %d, active %v", fixture.preparation.commitCalls, fixture.preparation.rollbackCalls, fixture.core.revokeCalls, fixture.service.state.prepared.active)
		}
	})

	t.Run("successful renew revokes current revision", func(t *testing.T) {
		t.Parallel()
		fixture := newServicePrepareTestFixture(t)
		fixture.prepareThroughCommit(t)
		activation := fixture.service.state.prepared
		packet, body := fixture.renewPacket(activation.activeProofID)
		packet.body = servicePrepareDestroyFailureBody{transportTestBody: body, err: cleanupFailure}
		if err := fixture.service.handleRenew(context.Background(), packet); !errors.Is(err, ErrContractOwnership) {
			t.Fatalf("handleRenew error = %v, want %v", err, ErrContractOwnership)
		}
		if fixture.core.renewCalls != 1 || fixture.core.revokeCalls != 1 || fixture.core.revokeRequest.Revision() != 2 || fixture.service.state.prepared.active {
			t.Fatalf("renew cleanup = renew %d, revoke %d, revision %d, active %v", fixture.core.renewCalls, fixture.core.revokeCalls, fixture.core.revokeRequest.Revision(), fixture.service.state.prepared.active)
		}
		if fixture.core.revokeRequest.RequestID() != activation.issuingCorrelation.requestID {
			t.Fatalf("renew cleanup request ID = %x, want issuing %x", fixture.core.revokeRequest.RequestID(), activation.issuingCorrelation.requestID)
		}
	})
}
