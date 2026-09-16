//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"golang.org/x/sys/unix"
)

func minimalSupervisorWorkClient(t *testing.T, f *minimalSupervisorJointFixture) (*guestagent.Client, *minimalControlWorkCandidate) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	candidate, err := f.producer.awaitWork(ctx)
	if err != nil || candidate == nil {
		t.Fatal("actual original producer did not adopt its candidate", err)
	}
	client, err := guestagent.NewClient(guestagent.ClientOptions{Transport: candidate})
	if err != nil {
		t.Fatal(err)
	}
	return client, candidate
}

func minimalSupervisorWorkJoined(t *testing.T, f *minimalSupervisorJointFixture) {
	t.Helper()
	serving := f.serving(t)
	minimalJointAwait(t, serving.controllerDone, "original work controller joined")
	minimalJointAwait(t, serving.lifecycleDone, "separate original loss lifecycle joined")
	serving.mu.Lock()
	controller, pair := serving.controller, serving.server
	serving.mu.Unlock()
	if controller != nil {
		minimalControllerRequireJoined(t, controller, f.admission.controllerKey)
	}
	if pair != nil && pair.started {
		minimalJointAwait(t, pair.reader, "work request reader joined")
		minimalJointAwait(t, pair.worker, "work backend/response writer joined")
		minimalJointAwait(t, pair.watcher, "work lifetime watcher joined")
	}
	f.producer.close()
}

func TestMinimalSupervisorWorkSequentialAndMaximumCopy(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		backend, verifier, _, rescue := f.guest(t, nil)
		defer rescue()
		data := bytes.Repeat([]byte{0, 1, 127, 255}, int(server.DefaultCopyBytes)/4)
		digest := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
		backend.copyIn = func(_ context.Context, plan server.CopyInPlan) (server.CopyResult, error) {
			if plan.DestinationPath != "/workspace/payload.bin" || plan.Digest != digest || plan.MaxBytes != server.DefaultCopyBytes || !bytes.Equal(plan.Data, data) {
				return server.CopyResult{}, errors.New("unexpected bounded copy plan")
			}
			return server.CopyResult{Published: true, SizeBytes: int64(len(data)), Digest: digest}, nil
		}
		backend.copyOut = func(_ context.Context, plan server.CopyOutPlan) (server.CopyResult, error) {
			if plan.SourcePath != "/workspace/payload.bin" || plan.MaxBytes != server.DefaultCopyBytes {
				return server.CopyResult{}, errors.New("unexpected bounded copy plan")
			}
			return server.CopyResult{Data: data, SizeBytes: int64(len(data)), Digest: digest}, nil
		}
		client, candidate := minimalSupervisorWorkClient(t, f)
		for index := 0; index < 50; index++ {
			response, err := client.Exec(context.Background(), minimalJointExecRequest())
			if err != nil || response.ExitCode != 7 {
				t.Fatalf("paired sequential work %d failed: %v", index, err)
			}
		}
		copied, err := client.CopyIn(context.Background(), guestagent.CopyInRequest{DestinationPath: "/workspace/payload.bin",
			Payload: guestagent.PayloadMetadata{Data: base64.StdEncoding.EncodeToString(data), Encoding: guestagent.PayloadEncodingBase64,
				SizeBytes: int64(len(data)), MaxBytes: server.DefaultCopyBytes, Digest: digest}})
		if err != nil || copied.Written.Digest != digest || copied.Written.SizeBytes != int64(len(data)) {
			t.Fatal("paired maximum CopyIn acknowledgement failed", err)
		}
		out, err := client.CopyOut(context.Background(), guestagent.CopyOutRequest{SourcePath: "/workspace/payload.bin",
			Payload: guestagent.PayloadMetadata{MaxBytes: server.DefaultCopyBytes, Encoding: guestagent.PayloadEncodingBase64}})
		if err != nil || out.Payload.Digest != digest || out.Payload.Data != base64.StdEncoding.EncodeToString(data) {
			t.Fatal("paired maximum CopyOut response failed", err)
		}
		if backend.calls.Load() != 52 || verifier.calls.Load() != 53 || candidate.launch.ordinal != 52 || !f.owned.minimalPreparation.workCurrent() {
			t.Fatal("work was retried, lacked a fresh guest proof, or lost its original owner")
		}
		f.producer.close()
		minimalSupervisorWorkJoined(t, f)
	})
}

func TestMinimalSupervisorWorkBusyAndBlockedBackendLoss(t *testing.T) {
	for _, loss := range []string{"caller", "work-endpoint", "original-channel", "authenticated-cleanup"} {
		t.Run(loss, func(t *testing.T) {
			withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
				backend, verifier, guestDone, rescue := f.guest(t, nil)
				defer rescue()
				entered, canceled := make(chan struct{}), make(chan struct{})
				backend.exec = func(ctx context.Context, _ server.ExecPlan) (server.ExecResult, error) {
					close(entered)
					<-ctx.Done()
					close(canceled)
					return server.ExecResult{}, ctx.Err()
				}
				client, candidate := minimalSupervisorWorkClient(t, f)
				caller, cancel := context.WithCancel(context.Background())
				finished := make(chan struct{})
				var callErr error
				go func() { defer close(finished); _, callErr = client.Exec(caller, minimalJointExecRequest()) }()
				defer func() { cancel(); minimalJointAwait(t, finished, "explicit pending-call rescue") }()
				minimalJointAwait(t, entered, "actual paired guest backend entered")
				_, busy := candidate.RoundTrip(context.Background(), guestagent.TransportRequest{ProtocolVersion: guestagent.ProtocolVersionV1,
					Operation: guestagent.OperationExec, Encoded: []byte(`{}`), MaxResponseBytes: 512})
				var protocol *guestagent.ProtocolError
				if !errors.As(busy, &protocol) || protocol.Code != guestagent.ErrorCodeServerBusy {
					t.Fatal("second paired call did not remain bounded busy", busy)
				}
				preCanceled, stop := context.WithCancel(context.Background())
				stop()
				if _, err := client.Exec(preCanceled, minimalJointExecRequest()); err == nil || backend.calls.Load() != 1 ||
					verifier.calls.Load() != 2 || !f.owned.minimalPreparation.workCurrent() {
					t.Fatal("unadmitted loser poisoned the original active operation")
				}
				switch loss {
				case "caller":
					cancel()
				case "work-endpoint":
					raw, err := f.producer.conn.SyscallConn()
					if err != nil {
						t.Fatal(err)
					}
					var shutdown error
					if raw.Control(func(fd uintptr) { shutdown = unix.Shutdown(int(fd), unix.SHUT_RDWR) }) != nil || shutdown != nil {
						t.Fatal("actual owned work endpoint shutdown failed")
					}
				case "original-channel":
					if unix.Shutdown(int(f.producer.original.Fd()), unix.SHUT_RDWR) != nil {
						t.Fatal("actual original channel shutdown failed")
					}
				case "authenticated-cleanup":
					fd, session := f.cleanup(t)
					defer unix.Close(fd)
					response, err := minimalSupervisorJointExchange(fd, session, 1, l8RuntimeOwnerOpcodeStopReap)
					closeL8RuntimeOwnerFiles(response.Files)
					if err != nil || response.Packet.Status != l8RuntimeOwnerStatusOK || response.Packet.Opcode != l8RuntimeOwnerOpcodeStopReap {
						t.Fatal("actual cleanup did not join the blocked work scope", err)
					}
				}
				minimalJointAwait(t, canceled, "guest backend cancellation without a release channel")
				minimalJointAwait(t, finished, "original paired call joined")
				minimalSupervisorWorkJoined(t, f)
				minimalJointAwait(t, guestDone, "paired guest joined after loss")
				if callErr == nil || f.owned.minimalPreparation.workCurrent() || backend.calls.Load() != 1 || verifier.calls.Load() != 2 {
					t.Fatal("lost paired work succeeded, retried or retained work authority", callErr)
				}
				if _, err := client.Exec(context.Background(), minimalJointExecRequest()); err == nil || backend.calls.Load() != 1 {
					t.Fatal("spent original candidate was reused")
				}
			})
		})
	}
}

func TestMinimalSupervisorWorkSurvivesOriginalPreparationDeadline(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		backend, verifier, _, rescue := f.guest(t, nil)
		defer rescue()
		client, _ := minimalSupervisorWorkClient(t, f)
		prep := f.owned.minimalPreparation
		originalP := prep.deadline
		starter := f.owned.selected.starter
		window, ok := starter.minimalGate.releaseWindow()
		if !ok || !time.Now().Before(originalP) {
			t.Fatal("original admission window was not reached")
		}
		if _, err := client.Exec(context.Background(), minimalJointExecRequest()); err != nil {
			t.Fatal("actual first work did not pass publication gate", err)
		}
		minimalJointAwait(t, prep.observerDone, "successful admission observer stop joined")
		// The immutable accepted original-manager fixture uses a real one-minute
		// P. Wait for that original deadline; no timer/clock/config rewrite.
		timer := time.NewTimer(time.Until(originalP) + time.Millisecond)
		defer timer.Stop()
		select {
		case <-prep.ctx.Done():
			t.Fatal("published owner died at spent admission deadline")
		case <-timer.C:
		}
		current, currentOK := starter.minimalGate.releaseWindow()
		if prep.current() || !prep.workCurrent() || prep.deadline != originalP || !currentOK || current != window {
			t.Fatal("publication weakened launch guards or rebased original P/R/D")
		}
		if _, err := client.Exec(context.Background(), minimalJointExecRequest()); err != nil || backend.calls.Load() != 2 || verifier.calls.Load() != 3 {
			t.Fatal("actual work did not survive spent original P", err)
		}
		f.producer.close()
		minimalSupervisorWorkJoined(t, f)
		fd, session := f.cleanup(t)
		defer unix.Close(fd)
		minimalSupervisorJointInspect(t, fd, session)
	})
}
