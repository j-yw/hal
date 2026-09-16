//go:build linux

package firecrackerhost

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"golang.org/x/sys/unix"
)

func minimalSupervisorJointController(t *testing.T, serving *minimalControlSupervisorServing) *minimalControlController {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		serving.mu.Lock()
		controller := serving.controller
		serving.mu.Unlock()
		if controller != nil {
			return controller
		}
		select {
		case <-timer.C:
			t.Fatal("new serving entry did not construct its original-manager controller")
		case <-tick.C:
		}
	}
}

func minimalSupervisorJointInspect(t *testing.T, fd int, session string) {
	t.Helper()
	response, err := minimalSupervisorJointExchange(fd, session, 1, l8RuntimeOwnerOpcodeInspect)
	defer closeL8RuntimeOwnerFiles(response.Files)
	if err != nil || response.Packet.Opcode != l8RuntimeOwnerOpcodeInspect || response.Packet.Status != l8RuntimeOwnerStatusOK || len(response.Files) != 0 {
		t.Fatal("ordinary authenticated cleanup Inspect was not serviceable", err)
	}
}

func TestMinimalSupervisorJointAuthenticatedWorkHandoff(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		backend, verifier, _, rescueGuest := f.guest(t, nil)
		defer rescueGuest()
		serving := f.serving(t)
		controller := minimalSupervisorJointController(t, serving)
		minimalJointAwait(t, controller.readyDone, "original controller transcript")
		controller.mu.Lock()
		authenticated, stream := controller.authenticated, controller.stream
		controller.mu.Unlock()
		if !authenticated || stream == nil || controller.transport.manager != f.manager || verifier.calls.Load() != 1 || backend.calls.Load() != 0 {
			t.Fatal("new entry did not reach the actual original-manager shared authentication")
		}
		f.owned.selected.coordinator.mu.Lock()
		generation := f.owned.selected.coordinator.generation
		process := generation.process
		f.owned.selected.coordinator.mu.Unlock()
		handle, streamGeneration := stream.Correlation()
		if handle != process.handle || streamGeneration == 0 || f.lifecycle.manager != f.manager || f.owned.selected.lifecycle != f.lifecycle {
			t.Fatal("authenticated stream did not retain the original launched process/manager")
		}
		// Even the unavailable publisher must not dispose of the cleanup listener.
		fd, session := f.cleanup(t)
		defer unix.Close(fd)
		minimalSupervisorJointInspect(t, fd, session)
		t.Log("reached original bootstrap revision 2, shared authenticated controller, and live cleanup Inspect")
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		candidate, err := f.producer.awaitWork(ctx)
		if err != nil || candidate == nil {
			t.Fatal("authenticated supervisor has no adopted original-channel work candidate", err)
		}
		// Deliberately unreached in this compiling RED: no endpoint publisher,
		// receiver or bridge exists yet. These are not claimed IPC coverage.
		client, err := guestagent.NewClient(guestagent.ClientOptions{Transport: candidate})
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Exec(ctx, minimalJointExecRequest())
		if err != nil || response.ExitCode != 7 || response.Stdout.Data != base64.StdEncoding.EncodeToString([]byte("same supervisor work pair\n")) ||
			backend.calls.Load() != 1 || verifier.calls.Load() != 2 {
			t.Fatal("Client to private work IPC to original authenticated controller did not reach the guest backend", err)
		}
	})
}

func TestMinimalSupervisorJointBlockedHandshakeCleanupInspect(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		fault := &minimalControllerPeerFault{stage: 1, effect: "cancel", reached: make(chan struct{})}
		backend, verifier, _, rescueGuest := f.guest(t, fault)
		defer rescueGuest()
		minimalJointAwait(t, fault.reached, "actual shared guest hello write")
		serving := f.serving(t)
		controller := minimalSupervisorJointController(t, serving)
		fd, session := f.cleanup(t)
		defer unix.Close(fd)
		minimalSupervisorJointInspect(t, fd, session)
		controller.mu.Lock()
		authenticated := controller.authenticated
		controller.mu.Unlock()
		select {
		case <-serving.controllerDone:
			t.Fatal("blocked handshake ended before concurrent cleanup Inspect")
		default:
		}
		if authenticated || backend.calls.Load() != 0 || verifier.calls.Load() != 0 || f.contained.Load() != 0 {
			t.Fatal("blocked-handshake control inferred work or cleanup authority")
		}
	})
}

func TestMinimalSupervisorJointBlockedHandshakeCleanupBarrier(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		fault := &minimalControllerPeerFault{stage: 1, effect: "cancel", reached: make(chan struct{})}
		backend, _, guestDone, rescueGuest := f.guest(t, fault)
		defer rescueGuest()
		minimalJointAwait(t, fault.reached, "actual shared guest hello write")
		serving := f.serving(t)
		controller := minimalSupervisorJointController(t, serving)
		fd, session := f.cleanup(t)
		defer unix.Close(fd)
		minimalSupervisorJointInspect(t, fd, session)
		if backend.calls.Load() != 0 || f.contained.Load() != 0 {
			t.Fatal("cleanup barrier prerequisite already performed work/containment")
		}
		t.Log("reached blocked real guest hello and same-FSM authenticated cleanup Inspect before StopReap")
		response, err := minimalSupervisorJointExchange(fd, session, 2, l8RuntimeOwnerOpcodeStopReap)
		defer closeL8RuntimeOwnerFiles(response.Files)
		if err != nil || response.Packet.Opcode != l8RuntimeOwnerOpcodeStopReap || response.Packet.Status != l8RuntimeOwnerStatusOK {
			t.Fatalf("authenticated StopReap cannot join blocked selected I/O: opcode=%d status=%d containment=%d error=%v", response.Packet.Opcode, response.Packet.Status, f.contained.Load(), err)
		}
		// Unreached until the actual selected cleanup barrier is implemented.
		minimalJointAwait(t, serving.controllerDone, "selected controller cleanup barrier")
		minimalJointAwait(t, guestDone, "guest from selected stream interruption")
		minimalControllerRequireJoined(t, controller, f.admission.controllerKey)
		if f.contained.Load() != 1 {
			t.Fatal("StopReap did not enter existing containment exactly once after I/O join")
		}
	})
}
