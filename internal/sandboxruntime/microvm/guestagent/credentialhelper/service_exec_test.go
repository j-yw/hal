package credentialhelper

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type serviceExecTestMode uint8

const (
	serviceExecPrivateSuccess serviceExecTestMode = iota + 1
	serviceExecPrivateInvalidCore
	serviceExecPrivatePanic
	serviceExecStdinSuccess
	serviceExecStdinFailure
	serviceExecMultiRecordOutput
)

type serviceExecTestCore struct {
	scenario         *serviceExecTestScenario
	beginExecCalls   int
	writeStdinCalls  int
	planDestroyCalls int
	wipeCalls        int
	revokeCalls      int
}

func (core *serviceExecTestCore) BeginPrepare(_ context.Context, request CorePrepareRequest) (CorePreparation, error) {
	if err := core.scenario.ensureConfigured(); err != nil {
		return nil, err
	}
	core.scenario.preparation.cleanup = request.cleanup
	return core.scenario.preparation, nil
}

func (core *serviceExecTestCore) BeginExec(_ context.Context, request CoreExecRequest, _ credentialmemory.BorrowedView) (CoreExecution, error) {
	core.beginExecCalls++
	switch core.scenario.mode {
	case serviceExecPrivateInvalidCore:
		return nil, nil
	case serviceExecPrivatePanic:
		panic("service exec test core panic")
	default:
		return &serviceExecTestExecution{core: core, execution: request.execution, cleanup: request.cleanup}, nil
	}
}

func (*serviceExecTestCore) Renew(context.Context, CoreRenewRequest) error {
	return errors.New("unexpected Renew")
}

func (core *serviceExecTestCore) Revoke(_ context.Context, request CoreRevokeRequest) (CoreCleanupResult, error) {
	core.revokeCalls++
	core.scenario.plan.mu.Lock()
	planDestroyed := core.scenario.plan.destroyed
	core.scenario.plan.mu.Unlock()
	if planDestroyed {
		core.planDestroyCalls++
	}
	transactionTerminated := core.scenario.transaction != nil && core.scenario.transaction.Snapshot().Terminal
	if core.scenario.mode == serviceExecPrivatePanic && transactionTerminated && core.beginExecCalls == 1 {
		core.wipeCalls++
	}
	return NewCoreCleanupResult(request.cleanup, CoreCleanupComplete, true, true)
}

func (*serviceExecTestCore) Inspect(context.Context, CoreInspectRequest) (CoreInspection, error) {
	return CoreInspection{}, errors.New("unexpected Inspect")
}

func (*serviceExecTestCore) Close(context.Context) error { return nil }

type serviceExecTestExecution struct {
	core      *serviceExecTestCore
	execution CoreExecutionCapability
	cleanup   CoreCleanupCapability
	request   CoreOutputRequest
	outputs   int
}

func (execution *serviceExecTestExecution) WriteStdin(context.Context, credentialmemory.BorrowedView, uint64, bool) error {
	execution.core.writeStdinCalls++
	if execution.core.scenario.mode == serviceExecStdinFailure {
		return errors.New("stdin rejected")
	}
	return nil
}

func (execution *serviceExecTestExecution) GrantOutput(_ context.Context, request CoreOutputRequest) error {
	execution.request = request
	return nil
}

func (execution *serviceExecTestExecution) Next(ctx context.Context) (CoreExecutionEvent, error) {
	if execution.core.scenario.mode == serviceExecMultiRecordOutput && execution.outputs < 3 {
		var payload []byte
		eof := true
		switch {
		case execution.request.kind == credentialprotocol.HelperExecStreamStdout && execution.request.offset == 0:
			payload = []byte("x")
			eof = false
		case execution.request.kind == credentialprotocol.HelperExecStreamStdout && execution.request.offset == 1:
		case execution.request.kind == credentialprotocol.HelperExecStreamStderr && execution.request.offset == 0:
		default:
			return CoreExecutionEvent{}, errors.New("unexpected multi-record output request")
		}
		output, outputErr := NewCoreOutputResult(execution.execution, execution.request.kind, execution.request.offset, uint32(len(payload)), sha256.Sum256(payload), eof, false)
		if outputErr != nil {
			return CoreExecutionEvent{}, outputErr
		}
		wire := canonicalCoreOutputBody(1, execution.request.kind, execution.request.offset, payload, eof)
		body := newTransportTestBody(wire, len(wire))
		event, eventErr := NewCoreExecutionOutputEvent(ctx, output, body)
		if eventErr != nil {
			return CoreExecutionEvent{}, eventErr
		}
		execution.outputs++
		return event, nil
	}
	if execution.outputs < 2 {
		emptySHA256 := sha256.Sum256(nil)
		output, outputErr := NewCoreOutputResult(execution.execution, execution.request.kind, execution.request.offset, 0, emptySHA256, true, false)
		if outputErr != nil {
			return CoreExecutionEvent{}, outputErr
		}
		wire := canonicalCoreOutputBody(1, execution.request.kind, execution.request.offset, nil, true)
		body := newTransportTestBody(wire, len(wire))
		event, eventErr := NewCoreExecutionOutputEvent(ctx, output, body)
		if eventErr != nil {
			return CoreExecutionEvent{}, eventErr
		}
		execution.outputs++
		return event, nil
	}
	if execution.core.scenario.transaction == nil {
		return CoreExecutionEvent{}, errors.New("missing exec transaction")
	}
	snapshot := execution.core.scenario.transaction.Snapshot()
	stdoutBytes := uint64(0)
	stdoutSHA256 := sha256.Sum256(nil)
	if execution.core.scenario.mode == serviceExecMultiRecordOutput {
		stdoutBytes = 1
		stdoutSHA256 = sha256.Sum256([]byte("x"))
	}
	complete, completeErr := NewCoreExecResult(execution.execution, CoreExecExitExited, 0, snapshot.StdinBytes, snapshot.StdinSHA256, snapshot.StdinTranscriptSHA256, stdoutBytes, stdoutSHA256, false, 0, sha256.Sum256(nil), false, snapshot.ExecTransactionSHA256)
	if completeErr != nil {
		return CoreExecutionEvent{}, completeErr
	}
	return NewCoreExecutionCompleteEvent(complete)
}

func (execution *serviceExecTestExecution) Cancel(context.Context) (CoreCleanupResult, error) {
	return NewCoreCleanupResult(execution.cleanup, CoreCleanupComplete, true, true)
}

type serviceExecTestRuntime struct {
	scenario     *serviceExecTestScenario
	observeIndex int
}

func (runtime *serviceExecTestRuntime) Bootstrap(context.Context) (ServiceBootstrap, error) {
	if err := runtime.scenario.ensureConfigured(); err != nil {
		return ServiceBootstrap{}, err
	}
	return runtime.scenario.bootstrap, nil
}

func (*serviceExecTestRuntime) BindAgent(context.Context, ServiceAgentBindingRequest, ReceivedCapability) error {
	return errors.New("unexpected BindAgent")
}

func (runtime *serviceExecTestRuntime) ObserveJob(context.Context, ServiceJobObservationRequest) (ServiceJobObservation, error) {
	if err := runtime.scenario.ensureConfigured(); err != nil {
		return ServiceJobObservation{}, err
	}
	if runtime.observeIndex >= len(runtime.scenario.observations) {
		return ServiceJobObservation{}, errors.New("unexpected ObserveJob")
	}
	observation := runtime.scenario.observations[runtime.observeIndex]
	runtime.observeIndex++
	return observation, nil
}

func (*serviceExecTestRuntime) Loss() <-chan ServiceLoss { return nil }

func (*serviceExecTestRuntime) BeginCleanup() (ServiceCleanupBudget, error) {
	return nil, errors.New("unexpected BeginCleanup")
}

func (*serviceExecTestRuntime) Close(context.Context) error { return nil }

type serviceExecTestTransport struct {
	scenario           *serviceExecTestScenario
	service            *Service
	core               *serviceExecTestCore
	receiveIndex       int
	dependencyCalls    int
	serveCalls         int
	takeCalls          int
	commitCalls        int
	wipeCalls          int
	bodyDestroyCalls   int
	firstOutputVisible chan struct{}
	releaseFirstOutput chan struct{}
}

type serviceExecTestScenario struct {
	mode              serviceExecTestMode
	configured        bool
	configureErr      error
	preparation       *servicePrepareTestPreparation
	bootstrap         ServiceBootstrap
	observations      []ServiceJobObservation
	packets           []ReceivedPacket
	plan              *execPlanCapabilityState
	transaction       *credentialprotocol.HelperExecTransaction
	countOutcome      bool
	receiveFaultIndex int
	receiveFaultPanic bool
}

func (scenario *serviceExecTestScenario) ensureConfigured() error {
	if scenario.configured {
		return scenario.configureErr
	}
	scenario.configured = true
	scenario.configureErr = configureServiceExecTest(scenario)
	return scenario.configureErr
}

func (transport *serviceExecTestTransport) Receive(ctx context.Context, request ReceiveRequest) (ReceivedPacket, error) {
	if err := transport.scenario.ensureConfigured(); err != nil {
		return ReceivedPacket{}, err
	}
	if transport.core == nil && transport.service != nil {
		core, ok := transport.service.core.(*serviceExecTestCore)
		if !ok {
			return ReceivedPacket{}, errors.New("unexpected Core dependency")
		}
		transport.core = core
	}
	if transport.scenario.receiveFaultIndex > 0 && transport.receiveIndex == transport.scenario.receiveFaultIndex {
		if transport.scenario.receiveFaultPanic {
			panic("service exec test receive panic")
		}
		return ReceivedPacket{}, errors.New("service exec test receive failure")
	}
	if transport.receiveIndex >= len(transport.scenario.packets) {
		<-ctx.Done()
		return ReceivedPacket{}, ctx.Err()
	}
	if request.NextSequence() != uint64(transport.receiveIndex) {
		return ReceivedPacket{}, errors.New("unexpected Receive")
	}
	transport.dependencyCalls++
	transport.serveCalls++
	packet := transport.scenario.packets[transport.receiveIndex]
	if credit, ok := packet.ExecCredit(); ok && credit.StreamKind() == credentialprotocol.HelperExecStreamStdout && credit.NextOffset() == 1 && transport.firstOutputVisible != nil {
		select {
		case <-transport.firstOutputVisible:
		case <-ctx.Done():
			return ReceivedPacket{}, ctx.Err()
		}
		go func() {
			time.Sleep(100 * time.Millisecond)
			close(transport.releaseFirstOutput)
		}()
	}
	if packet.body != nil {
		packet.body.(*serviceExecTestBody).transport = transport
	}
	transport.receiveIndex++
	if packet.Type() == credentialprotocol.PacketTypeExecPrivate || packet.Type() == credentialprotocol.PacketTypeExecStream {
		transport.takeCalls++
	}
	return packet, nil
}

func (transport *serviceExecTestTransport) Send(ctx context.Context, packet SendPacket) error {
	sink := &transportTestSink{maximum: int(packet.EncodedBodyLength())}
	writeErr := packet.WriteCanonicalBody(ctx, sink)
	destroyErr := packet.destroyBody(ctx)
	if writeErr != nil {
		return writeErr
	}
	if destroyErr != nil {
		return destroyErr
	}
	if arm, ok := packet.arm.(*sealedSendPacketArm); ok {
		if stream, streamOK := arm.arm.(sendExecStreamArm); streamOK && stream.streamKind == credentialprotocol.HelperExecStreamStdout && stream.offset == 0 && stream.payloadLength == 1 && transport.firstOutputVisible != nil {
			close(transport.firstOutputVisible)
			select {
			case <-transport.releaseFirstOutput:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}

func (*serviceExecTestTransport) Close(context.Context) error { return nil }

type serviceExecTestBody struct {
	transportTestBody
	transport    *serviceExecTestTransport
	countOutcome bool
}

func (body *serviceExecTestBody) Borrow(ctx context.Context, callback func(credentialmemory.BorrowedView) error) error {
	if !body.countOutcome {
		return body.transportTestBody.Borrow(ctx, callback)
	}
	body.transport.service.state.mu.Lock()
	transaction := body.transport.service.state.transaction
	body.transport.service.state.mu.Unlock()
	if transaction == nil || body.transport.core == nil {
		return ErrContractTransition
	}
	body.transport.scenario.transaction = transaction
	before := transaction.Snapshot()
	beginExecCalls := body.transport.core.beginExecCalls
	writeStdinCalls := body.transport.core.writeStdinCalls
	borrowErr := body.transportTestBody.Borrow(ctx, callback)
	after := transaction.Snapshot()
	beginExecDelta := body.transport.core.beginExecCalls - beginExecCalls
	writeStdinDelta := body.transport.core.writeStdinCalls - writeStdinCalls
	privateCommit := !before.Terminal && !before.Completed && !before.PrivateComplete && !before.PendingPayload && !before.StdinCreditOutstanding && !before.StdinEOF && !after.Terminal && !after.Completed && after.PrivateComplete && !after.PendingPayload && !after.StdinCreditOutstanding && !after.StdinEOF && after.ComparisonOnly == before.ComparisonOnly && after.StdinOffset == before.StdinOffset && after.StdinBytes == before.StdinBytes && after.StdinRecordCount == before.StdinRecordCount && after.StdinSHA256 == before.StdinSHA256 && after.StdinTranscriptSHA256 == before.StdinTranscriptSHA256
	stdinCommit := !before.Terminal && !before.Completed && before.PrivateComplete && !before.PendingPayload && before.StdinCreditOutstanding && !before.StdinEOF && !after.Terminal && !after.Completed && after.PrivateComplete && !after.PendingPayload && !after.StdinCreditOutstanding && after.ComparisonOnly == before.ComparisonOnly && after.StdinOffset >= before.StdinOffset && after.StdinBytes >= before.StdinBytes && after.StdinRecordCount == before.StdinRecordCount+1
	privateCore := before.ComparisonOnly && beginExecDelta == 0 && writeStdinDelta == 0 || !before.ComparisonOnly && beginExecDelta == 1 && writeStdinDelta == 0
	stdinCore := before.ComparisonOnly && beginExecDelta == 0 && writeStdinDelta == 0 || !before.ComparisonOnly && beginExecDelta == 0 && writeStdinDelta == 1
	if borrowErr == nil && (privateCommit && privateCore || stdinCommit && stdinCore) {
		body.transport.commitCalls++
	}
	privateWipe := !before.PrivateComplete && beginExecDelta == 1 && writeStdinDelta == 0
	stdinWipe := before.PrivateComplete && beginExecDelta == 0 && writeStdinDelta == 1
	if borrowErr != nil && !before.Terminal && after.Terminal && (privateWipe || stdinWipe) {
		body.transport.wipeCalls++
	}
	return borrowErr
}

func (body *serviceExecTestBody) Destroy(ctx context.Context) error {
	err := body.transportTestBody.Destroy(ctx)
	if err == nil {
		body.transport.bodyDestroyCalls++
	}
	return err
}

func configureServiceExecTest(scenario *serviceExecTestScenario) error {
	payload := []byte("prepared credential")
	payloadSHA256 := sha256.Sum256(payload)
	binding := credentialprotocol.HelperBindingManifestRecord{
		BindingID:         "binding-a",
		Mode:              credentialprotocol.DeliveryModeFileTmpfs,
		TargetPath:        "run/credential",
		DeclaredFileBytes: uint32(len(payload)),
		FileSHA256:        payloadSHA256,
	}
	manifest, manifestErr := NewManifestCapability([]credentialprotocol.HelperBindingManifestRecord{binding})
	if manifestErr != nil {
		return manifestErr
	}
	header := credentialprotocol.HelperPacketHeader{
		RequestID:                     [16]byte{1},
		GuestCredentialIdentityDigest: sha256.Sum256([]byte("identity")),
		BootNonce:                     sha256.Sum256([]byte("boot nonce")),
	}
	begin := credentialprotocol.HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: 80, Bindings: []credentialprotocol.HelperBindingManifestRecord{binding}}
	prepareCorrelation, prepareCorrelationErr := credentialprotocol.NewHelperPrepareTransactionCorrelation(header.RequestID, header.GuestCredentialIdentityDigest, begin.Revision, begin.ExpiryUnixNano)
	if prepareCorrelationErr != nil {
		return prepareCorrelationErr
	}
	prepareTransaction, prepareTransactionErr := credentialprotocol.NewHelperPrepareTransaction(prepareCorrelation, begin, manifest.SHA256())
	if prepareTransactionErr != nil {
		return prepareTransactionErr
	}
	complete, generationsErr := NewCoreGenerations("boot-a", "helper-a", "job-a", "monitor-a", "mount-a", "cgroup-a")
	if generationsErr != nil {
		return generationsErr
	}
	bootstrap, bootstrapErr := NewServiceBootstrap(header.BootNonce, complete.boot, complete.helper)
	if bootstrapErr != nil {
		return bootstrapErr
	}
	observations := make([]ServiceJobObservation, 3)
	for index, observed := range []int64{10, 20, 30} {
		observation, observationErr := NewServiceJobObservation(complete, observed, 100)
		if observationErr != nil {
			return observationErr
		}
		observations[index] = observation
	}
	scenario.preparation = &servicePrepareTestPreparation{completeGenerations: complete, expiresUnixNano: begin.ExpiryUnixNano, bindingCount: manifest.Count()}
	scenario.bootstrap = bootstrap
	scenario.observations = observations

	appendPacket := func(packetType credentialprotocol.PacketType, arm receivedPacketArm, payload []byte, countOutcome bool) {
		packetHeader := header
		packetHeader.Type = packetType
		packetHeader.BodyLength = uint32(len(payload))
		body := newTransportTestBody(payload, len(payload))
		packet := ReceivedPacket{header: packetHeader, arm: arm}
		packet.body = &serviceExecTestBody{transportTestBody: body, countOutcome: countOutcome}
		scenario.packets = append(scenario.packets, packet)
	}
	appendPacket(credentialprotocol.PacketTypePrepareBegin, ReceivedPrepareBegin{
		revision: begin.Revision, expiryUnixNano: begin.ExpiryUnixNano, manifest: manifest, transaction: prepareTransaction,
	}, []byte("begin"), false)
	appendPacket(credentialprotocol.PacketTypePrepareFile, ReceivedPrepareFile{
		revision: 1, bindingIndex: 0, fileLength: uint32(len(payload)), fileSHA256: payloadSHA256,
	}, payload, false)
	appendPacket(credentialprotocol.PacketTypePrepareCommit, ReceivedPrepareCommit{
		revision: 1, manifestSHA256: manifest.SHA256(),
	}, []byte("commit"), false)

	privatePayload := []byte("private")
	privateLength := uint32(0)
	privateSHA256 := [32]byte{}
	if scenario.mode == serviceExecPrivateSuccess || scenario.mode == serviceExecPrivateInvalidCore || scenario.mode == serviceExecPrivatePanic {
		privateLength = uint32(len(privatePayload))
		privateSHA256 = sha256.Sum256(privatePayload)
	}
	planValue := validCoreExecPlan()
	execBody := credentialprotocol.HelperExecBody{
		Revision:             1,
		ExecBindingID:        "exec-a",
		PrivateBindingLength: privateLength,
		PrivateBindingSHA256: privateSHA256,
		Plan:                 planValue,
	}
	canonicalExec, err := credentialprotocol.EncodeHelperExecBody(execBody)
	if err != nil {
		return err
	}
	plan, err := NewExecPlanCapability(planValue)
	if err != nil {
		return err
	}
	claimed := false
	if err := plan.claimAndMatch(planValue, &claimed); err != nil || !claimed {
		if err != nil {
			return err
		}
		return errors.New("exec plan was not claimed")
	}
	scenario.plan = plan.state
	execHeader := header
	execHeader.Type = credentialprotocol.PacketTypeExec
	execHeader.RequestID = [16]byte{2}
	execHeader.BodyLength = uint32(len(canonicalExec))
	correlation, err := credentialprotocol.NewHelperExecTransactionCorrelation(execHeader.RequestID, execHeader.GuestCredentialIdentityDigest, 1)
	if err != nil {
		return err
	}
	transactionSeed, err := credentialprotocol.NewHelperExecTransactionSeed(correlation, execBody)
	if err != nil {
		return err
	}
	execPacket := ReceivedPacket{header: execHeader, arm: ReceivedExec{
		revision: 1, execBindingID: "exec-a", privateLength: privateLength, privateSHA256: privateSHA256,
		plan: plan, transactionSeed: transactionSeed,
	}}
	execPacket.body = &serviceExecTestBody{transportTestBody: newTransportTestBody(canonicalExec, len(canonicalExec))}
	scenario.packets = append(scenario.packets, execPacket)

	continuationHeader := execHeader
	if privateLength != 0 {
		observation, observationErr := credentialprotocol.NewHelperExecPrivateObservation(1, privateLength, privateSHA256, privateSHA256)
		if observationErr != nil {
			return observationErr
		}
		continuationHeader.Type = credentialprotocol.PacketTypeExecPrivate
		continuationHeader.BodyLength = privateLength
		packet := ReceivedPacket{header: continuationHeader, arm: ReceivedExecPrivate{
			revision: 1, privateBindingLength: privateLength, privateBindingSHA256: privateSHA256, observation: observation,
		}}
		packet.body = &serviceExecTestBody{transportTestBody: newTransportTestBody(privatePayload, len(privatePayload)), countOutcome: scenario.countOutcome}
		scenario.packets = append(scenario.packets, packet)
	}
	emptySHA256 := sha256.Sum256(nil)
	observation, observationErr := credentialprotocol.NewHelperExecStreamObservation(1, credentialprotocol.HelperExecStreamStdin, credentialprotocol.HelperExecStreamFlagEOF, 0, 0, emptySHA256, emptySHA256)
	if observationErr != nil {
		return observationErr
	}
	continuationHeader.Type = credentialprotocol.PacketTypeExecStream
	continuationHeader.BodyLength = 0
	packet := ReceivedPacket{header: continuationHeader, arm: ReceivedExecStream{
		revision: 1, streamKind: credentialprotocol.HelperExecStreamStdin, flags: credentialprotocol.HelperExecStreamFlagEOF,
		offset: 0, payloadLength: 0, payloadSHA256: emptySHA256, observation: observation,
	}}
	packet.body = &serviceExecTestBody{transportTestBody: newTransportTestBody(nil, 1), countOutcome: scenario.countOutcome}
	scenario.packets = append(scenario.packets, packet)
	if !scenario.countOutcome {
		mirror, mirrorErr := credentialprotocol.NewHelperExecTransaction(correlation, execBody)
		if mirrorErr != nil {
			return mirrorErr
		}
		if privateLength != 0 {
			privateObservation, privateObservationErr := credentialprotocol.NewHelperExecPrivateObservation(1, privateLength, privateSHA256, privateSHA256)
			if privateObservationErr != nil {
				return privateObservationErr
			}
			proposal, proposalErr := mirror.ProposeObservedPrivate(correlation, privateObservation)
			if proposalErr != nil {
				return proposalErr
			}
			if commitErr := proposal.Commit(); commitErr != nil {
				return commitErr
			}
		}
		credit := credentialprotocol.HelperExecCreditBody{Revision: 1, StreamKind: credentialprotocol.HelperExecStreamStdin, NextOffset: 0}
		if creditErr := mirror.GrantStdinCredit(correlation, credit); creditErr != nil {
			return creditErr
		}
		mirrorObservation, mirrorObservationErr := credentialprotocol.NewHelperExecStreamObservation(1, credentialprotocol.HelperExecStreamStdin, credentialprotocol.HelperExecStreamFlagEOF, 0, 0, emptySHA256, emptySHA256)
		if mirrorObservationErr != nil {
			return mirrorObservationErr
		}
		mirrorBody := newTransportTestBody(nil, 1)
		mirrorErr = mirrorBody.Borrow(context.Background(), func(view credentialmemory.BorrowedView) error {
			proposal, proposalErr := mirror.ProposeObservedStdin(context.Background(), correlation, mirrorObservation, view)
			if proposalErr != nil {
				return proposalErr
			}
			return proposal.Commit()
		})
		if mirrorErr != nil {
			return mirrorErr
		}
		scenario.transaction = mirror
	}
	credits := []struct {
		kind   credentialprotocol.HelperExecStreamKind
		offset uint64
	}{{credentialprotocol.HelperExecStreamStdout, 0}, {credentialprotocol.HelperExecStreamStderr, 0}}
	if scenario.mode == serviceExecMultiRecordOutput {
		credits = []struct {
			kind   credentialprotocol.HelperExecStreamKind
			offset uint64
		}{{credentialprotocol.HelperExecStreamStdout, 0}, {credentialprotocol.HelperExecStreamStdout, 1}, {credentialprotocol.HelperExecStreamStderr, 0}}
	}
	for _, credit := range credits {
		creditHeader := execHeader
		creditHeader.Type = credentialprotocol.PacketTypeExecCredit
		creditHeader.BodyLength = credentialprotocol.HelperExecCreditBodyBytes
		scenario.packets = append(scenario.packets, ReceivedPacket{header: creditHeader, arm: ReceivedExecCredit{revision: 1, streamKind: credit.kind, nextOffset: credit.offset}})
	}
	return nil
}

func TestServiceAcceptsCausalSameStreamCreditBeforeSendReturns(t *testing.T) {
	scenario := &serviceExecTestScenario{mode: serviceExecMultiRecordOutput, countOutcome: true}
	core := &serviceExecTestCore{scenario: scenario}
	transport := &serviceExecTestTransport{scenario: scenario, firstOutputVisible: make(chan struct{}), releaseFirstOutput: make(chan struct{})}
	runtime := &serviceExecTestRuntime{scenario: scenario}
	service, err := NewService(ServiceOptions{Core: core, Transport: transport, Policy: NewHelperPolicy(), Host: serviceTestHost{}, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	transport.service = service
	result, serveErr := service.Serve(context.Background())
	if serveErr != nil || result.Disposition() != ServiceClosed {
		t.Fatalf("causal same-stream continuation = %v, %v", result.Disposition(), serveErr)
	}
}

func TestServiceReceiveFailureConvergesOwnedState(t *testing.T) {
	for _, test := range []struct {
		name       string
		faultIndex int
		panic      bool
		rollback   int
		revoke     int
	}{
		{name: "preparing error", faultIndex: 1, rollback: 1},
		{name: "prepared error", faultIndex: 3, revoke: 1},
		{name: "exec private panic", faultIndex: 4, panic: true, revoke: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			scenario := &serviceExecTestScenario{mode: serviceExecPrivateSuccess, countOutcome: true, receiveFaultIndex: test.faultIndex, receiveFaultPanic: test.panic}
			core := &serviceExecTestCore{scenario: scenario}
			transport := &serviceExecTestTransport{scenario: scenario}
			runtime := &serviceExecTestRuntime{scenario: scenario}
			service, err := NewService(ServiceOptions{Core: core, Transport: transport, Policy: NewHelperPolicy(), Host: serviceTestHost{}, Runtime: runtime})
			if err != nil {
				t.Fatal(err)
			}
			transport.service = service
			result, serveErr := service.Serve(context.Background())
			if serveErr == nil || result.Disposition() != ServiceStopVMRequired {
				t.Fatalf("Receive failure result = %v, %v", result.Disposition(), serveErr)
			}
			if scenario.preparation.rollbackCalls != test.rollback || core.revokeCalls != test.revoke {
				t.Fatalf("Receive cleanup = rollback %d, revoke %d", scenario.preparation.rollbackCalls, core.revokeCalls)
			}
			service.state.mu.Lock()
			ownersRemain := service.state.preparing.authority.transaction != nil || service.state.prepared.active || service.state.transaction != nil || service.state.revision != 0
			service.state.mu.Unlock()
			planLive := scenario.plan != nil && !scenario.plan.destroyed && test.faultIndex == 4
			if ownersRemain || planLive {
				t.Fatalf("Receive failure retained service owners: state=%t plan=%t", ownersRemain, planLive)
			}
		})
	}
}

func TestServiceDestroysClaimedExecPlanOnEveryDispatchPath(t *testing.T) {
	for _, test := range []struct {
		name string
		mode serviceExecTestMode
	}{{"success", serviceExecPrivateSuccess}, {"invalid core", serviceExecPrivateInvalidCore}, {"panic", serviceExecPrivatePanic}, {"stdin failure", serviceExecStdinFailure}, {"multi-record output", serviceExecMultiRecordOutput}} {
		t.Run(test.name, func(t *testing.T) {
			mode := test.mode
			scenario := &serviceExecTestScenario{mode: mode, countOutcome: true}
			core := &serviceExecTestCore{scenario: scenario}
			transport := &serviceExecTestTransport{scenario: scenario}
			if mode == serviceExecMultiRecordOutput {
				transport.firstOutputVisible = make(chan struct{})
				transport.releaseFirstOutput = make(chan struct{})
			}
			runtime := &serviceExecTestRuntime{scenario: scenario}
			service, err := NewService(ServiceOptions{Core: core, Transport: transport, Policy: NewHelperPolicy(), Host: serviceTestHost{}, Runtime: runtime})
			if err != nil {
				t.Fatal(err)
			}
			transport.service = service
			_, _ = service.Serve(context.Background())
			if scenario.plan == nil || !scenario.plan.destroyed || core.planDestroyCalls != 1 {
				t.Fatal("claimed plan cleanup count changed")
			}
		})
	}
}

func TestServiceConstructorDependenciesSnapshotAndServeOneShot(t *testing.T) {
	scenario := &serviceExecTestScenario{mode: serviceExecPrivateSuccess}
	core := &serviceExecTestCore{scenario: scenario}
	transport := &serviceExecTestTransport{scenario: scenario}
	runtime := &serviceExecTestRuntime{scenario: scenario}
	registry := &ExtensionRegistry{entries: []extensionEntry{{}}}
	service, err := NewService(ServiceOptions{Core: core, Transport: transport, Policy: NewHelperPolicy(), Extensions: registry, Host: serviceTestHost{}, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	_, serveErr := service.Serve(context.Background())
	if serveErr != nil {
		t.Fatal(serveErr)
	}
	if len(service.extensions) != 1 {
		t.Fatal("owned extension snapshot count changed")
	}
	if transport.dependencyCalls != 8 {
		t.Fatal("dependency call count changed")
	}
	if transport.serveCalls != 8 {
		t.Fatal("serve call count changed")
	}
}

func TestServiceServeContextPreconditionBeforeOneShotLatch(t *testing.T) {
	scenario := &serviceExecTestScenario{mode: serviceExecPrivateSuccess}
	core := &serviceExecTestCore{scenario: scenario}
	transport := &serviceExecTestTransport{scenario: scenario}
	runtime := &serviceExecTestRuntime{scenario: scenario}
	var ctx context.Context
	service, err := NewService(ServiceOptions{Core: core, Transport: transport, Policy: NewHelperPolicy(), Host: serviceTestHost{}, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = service.Serve(ctx)
	if transport.dependencyCalls != 0 {
		t.Fatal("nil context reached a dependency")
	}
	if transport.serveCalls != 0 {
		t.Fatal("nil context consumed the one-shot serve latch")
	}
}

func TestServiceObservedInputsTakenOnceBeforeDispatch(t *testing.T) {
	scenario := &serviceExecTestScenario{mode: serviceExecPrivateSuccess, countOutcome: true}
	core := &serviceExecTestCore{scenario: scenario}
	transport := &serviceExecTestTransport{scenario: scenario}
	runtime := &serviceExecTestRuntime{scenario: scenario}
	service, err := NewService(ServiceOptions{Core: core, Transport: transport, Policy: NewHelperPolicy(), Host: serviceTestHost{}, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	transport.service = service
	_, serveErr := service.Serve(context.Background())
	if serveErr != nil {
		t.Fatal(serveErr)
	}
	if transport.takeCalls != 2 {
		t.Fatal("dispatch take count changed")
	}
}

func TestServiceObservedPrivateCoreCommitCleanupMatrix(t *testing.T) {
	scenario := &serviceExecTestScenario{mode: serviceExecPrivateSuccess, countOutcome: true}
	core := &serviceExecTestCore{scenario: scenario}
	transport := &serviceExecTestTransport{scenario: scenario}
	runtime := &serviceExecTestRuntime{scenario: scenario}
	service, err := NewService(ServiceOptions{Core: core, Transport: transport, Policy: NewHelperPolicy(), Host: serviceTestHost{}, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	transport.service = service
	_, serveErr := service.Serve(context.Background())
	if serveErr != nil {
		t.Fatal(serveErr)
	}
	if core.beginExecCalls != 1 {
		t.Fatal("private core call count changed")
	}
	if transport.commitCalls != 2 {
		t.Fatal("private commit count changed")
	}
	if transport.bodyDestroyCalls != 6 {
		t.Fatal("private body cleanup count changed")
	}
	if core.planDestroyCalls != 1 {
		t.Fatal("private plan cleanup count changed")
	}
}

func TestServiceObservedPrivateCommitRequiresValidCoreExecution(t *testing.T) {
	scenario := &serviceExecTestScenario{mode: serviceExecPrivateInvalidCore, countOutcome: true}
	core := &serviceExecTestCore{scenario: scenario}
	transport := &serviceExecTestTransport{scenario: scenario}
	runtime := &serviceExecTestRuntime{scenario: scenario}
	service, err := NewService(ServiceOptions{Core: core, Transport: transport, Policy: NewHelperPolicy(), Host: serviceTestHost{}, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	transport.service = service
	_, _ = service.Serve(context.Background())
	if core.beginExecCalls != 1 {
		t.Fatal("private invalid-core call count changed")
	}
	if transport.commitCalls != 0 {
		t.Fatal("private proposal committed after invalid Core execution")
	}
	if transport.wipeCalls != 1 {
		t.Fatal("private proposal wipe count changed")
	}
}

func TestServiceObservedStdinCoreCommitCleanupMatrix(t *testing.T) {
	scenario := &serviceExecTestScenario{mode: serviceExecStdinSuccess, countOutcome: true}
	core := &serviceExecTestCore{scenario: scenario}
	transport := &serviceExecTestTransport{scenario: scenario}
	runtime := &serviceExecTestRuntime{scenario: scenario}
	service, err := NewService(ServiceOptions{Core: core, Transport: transport, Policy: NewHelperPolicy(), Host: serviceTestHost{}, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	transport.service = service
	_, serveErr := service.Serve(context.Background())
	if serveErr != nil {
		t.Fatal(serveErr)
	}
	if core.writeStdinCalls != 1 {
		t.Fatal("stdin core call count changed")
	}
	if transport.commitCalls != 1 {
		t.Fatal("stdin commit count changed")
	}
	if transport.bodyDestroyCalls != 5 {
		t.Fatal("stdin body cleanup count changed")
	}
}

func TestServiceObservedStdinCommitRequiresNilCoreError(t *testing.T) {
	scenario := &serviceExecTestScenario{mode: serviceExecStdinFailure, countOutcome: true}
	core := &serviceExecTestCore{scenario: scenario}
	transport := &serviceExecTestTransport{scenario: scenario}
	runtime := &serviceExecTestRuntime{scenario: scenario}
	service, err := NewService(ServiceOptions{Core: core, Transport: transport, Policy: NewHelperPolicy(), Host: serviceTestHost{}, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	transport.service = service
	_, _ = service.Serve(context.Background())
	if core.writeStdinCalls != 1 {
		t.Fatal("stdin error call count changed")
	}
	if transport.commitCalls != 0 {
		t.Fatal("stdin proposal committed after Core error")
	}
	if transport.wipeCalls != 1 {
		t.Fatal("stdin proposal wipe count changed")
	}
}

func TestServiceObservedComparisonNeverCallsCore(t *testing.T) {
	scenario := &serviceExecTestScenario{mode: serviceExecPrivateSuccess}
	core := &serviceExecTestCore{scenario: scenario}
	transport := &serviceExecTestTransport{scenario: scenario}
	runtime := &serviceExecTestRuntime{scenario: scenario}
	service, err := NewService(ServiceOptions{Core: core, Transport: transport, Policy: NewHelperPolicy(), Host: serviceTestHost{}, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	privatePayload := []byte("private")
	privateSHA256 := sha256.Sum256(privatePayload)
	body := credentialprotocol.HelperExecBody{Revision: 1, ExecBindingID: "exec-a", PrivateBindingLength: uint32(len(privatePayload)), PrivateBindingSHA256: privateSHA256, Plan: validCoreExecPlan()}
	correlation, err := credentialprotocol.NewHelperExecTransactionCorrelation([16]byte{1}, sha256.Sum256([]byte("identity")), 1)
	if err != nil {
		t.Fatal(err)
	}
	normal, err := credentialprotocol.NewHelperExecTransaction(correlation, body)
	if err != nil {
		t.Fatal(err)
	}
	privateBody, err := credentialprotocol.NewHelperExecPrivateBody(1, privateSHA256, privatePayload)
	if err != nil {
		t.Fatal(err)
	}
	privateProposal, err := normal.ProposePrivate(correlation, privateBody)
	if err != nil {
		t.Fatal(err)
	}
	privateCopy := make([]byte, len(privatePayload))
	if _, err = privateProposal.CopyPayload(privateCopy); err != nil {
		t.Fatal(err)
	}
	if err = privateProposal.Commit(); err != nil {
		t.Fatal(err)
	}
	stdinCredit := credentialprotocol.HelperExecCreditBody{Revision: 1, StreamKind: credentialprotocol.HelperExecStreamStdin, NextOffset: 0}
	if err = normal.GrantStdinCredit(correlation, stdinCredit); err != nil {
		t.Fatal(err)
	}
	emptySHA256 := sha256.Sum256(nil)
	stdinBody, err := credentialprotocol.NewHelperExecStreamBody(1, credentialprotocol.HelperExecStreamStdin, credentialprotocol.HelperExecStreamFlagEOF, 0, emptySHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	stdinProposal, err := normal.ProposeStdin(correlation, stdinBody)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stdinProposal.CopyPayload(nil); err != nil {
		t.Fatal(err)
	}
	if err = stdinProposal.Commit(); err != nil {
		t.Fatal(err)
	}
	normalSnapshot := normal.Snapshot()
	response := credentialprotocol.HelperResponseBody{RequestType: credentialprotocol.PacketTypeExec, Disposition: credentialprotocol.ResponseDispositionAccepted, Revision: 1, FailureCode: credentialprotocol.FailureCodeNone, Exec: &credentialprotocol.HelperExecResponseResult{ExitCode: 0, StdinBytes: normalSnapshot.StdinBytes, StdinSHA256: normalSnapshot.StdinSHA256, StdoutSHA256: emptySHA256, StderrSHA256: emptySHA256, ExecTransactionSHA256: normalSnapshot.ExecTransactionSHA256}}
	cached, err := normal.Complete(response)
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := credentialprotocol.NewHelperExecComparisonTransaction(correlation, body, cached)
	if err != nil {
		t.Fatal(err)
	}
	privateObservation, err := credentialprotocol.NewHelperExecPrivateObservation(1, uint32(len(privatePayload)), privateSHA256, privateSHA256)
	if err != nil {
		t.Fatal(err)
	}
	comparisonPrivate := newTransportTestBody(privatePayload, len(privatePayload))
	if _, err = service.private(context.Background(), comparisonPrivate, comparison, correlation, privateObservation, true); err != nil {
		t.Fatal(err)
	}
	if err = comparison.GrantStdinCredit(correlation, stdinCredit); err != nil {
		t.Fatal(err)
	}
	stdinObservation, err := credentialprotocol.NewHelperExecStreamObservation(1, credentialprotocol.HelperExecStreamStdin, credentialprotocol.HelperExecStreamFlagEOF, 0, 0, emptySHA256, emptySHA256)
	if err != nil {
		t.Fatal(err)
	}
	comparisonStdin := newTransportTestBody(nil, 1)
	if _, err = service.stdin(context.Background(), comparisonStdin, comparison, correlation, stdinObservation, 0, true, true); err != nil {
		t.Fatal(err)
	}
	if replay, replayErr := comparison.ReplayResult(); replayErr != nil || replay.Exec == nil || replay.Exec.ExecTransactionSHA256 != response.Exec.ExecTransactionSHA256 {
		t.Fatal("comparison replay result changed")
	}
	if core.beginExecCalls != 0 {
		t.Fatal("comparison private called Core")
	}
	if core.writeStdinCalls != 0 {
		t.Fatal("comparison stdin called Core")
	}
}

func TestServiceObservedBodiesDestroyedExactlyOnce(t *testing.T) {
	scenario := &serviceExecTestScenario{mode: serviceExecPrivateSuccess, countOutcome: true}
	core := &serviceExecTestCore{scenario: scenario}
	transport := &serviceExecTestTransport{scenario: scenario}
	runtime := &serviceExecTestRuntime{scenario: scenario}
	service, err := NewService(ServiceOptions{Core: core, Transport: transport, Policy: NewHelperPolicy(), Host: serviceTestHost{}, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	transport.service = service
	_, serveErr := service.Serve(context.Background())
	if serveErr != nil {
		t.Fatal(serveErr)
	}
	if transport.bodyDestroyCalls != 6 {
		t.Fatal("received body cleanup count changed")
	}
}

func TestServiceObservedFailureAndPanicCleanupIsExhaustive(t *testing.T) {
	scenario := &serviceExecTestScenario{mode: serviceExecPrivatePanic, countOutcome: true}
	core := &serviceExecTestCore{scenario: scenario}
	transport := &serviceExecTestTransport{scenario: scenario}
	runtime := &serviceExecTestRuntime{scenario: scenario}
	service, err := NewService(ServiceOptions{Core: core, Transport: transport, Policy: NewHelperPolicy(), Host: serviceTestHost{}, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	transport.service = service
	_, _ = service.Serve(context.Background())
	if core.wipeCalls != 1 {
		t.Fatal("panic proposal wipe count changed")
	}
	if transport.bodyDestroyCalls != 5 {
		t.Fatal("panic body cleanup count changed")
	}
	if core.planDestroyCalls != 1 {
		t.Fatal("panic plan cleanup count changed")
	}
}
