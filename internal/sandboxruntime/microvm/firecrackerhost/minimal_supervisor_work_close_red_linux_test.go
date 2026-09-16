//go:build linux

package firecrackerhost

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Rescue owns only the captured original listener/connection, and runs after
// the whole Close task joins. Its shutdown is not intended service cleanup.
func minimalSupervisorOuterCloseRescue(t *testing.T, f *minimalSupervisorJointFixture, closed <-chan struct{}, controllerFD int) func() {
	t.Helper()
	listenerFD := f.owned.listenerFD
	var identity unix.Stat_t
	if unix.Fstat(listenerFD, &identity) != nil {
		t.Fatal("original listener rescue identity")
	}
	return func() {
		minimalJointAwait(t, closed, "whole original owner close joined")
		var current unix.Stat_t
		if f.owned.listenerFD == listenerFD && unix.Fstat(listenerFD, &current) == nil && current.Dev == identity.Dev && current.Ino == identity.Ino {
			_ = unix.Shutdown(listenerFD, unix.SHUT_RDWR)
		}
		_ = unix.Close(controllerFD)
		minimalJointAwait(t, f.done, "original serving after explicit listener rescue")
		minimalSupervisorWorkJoined(t, f)
	}
}

func TestMinimalSupervisorWorkOuterCloseJoinsPairBeforeContainment(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		_, _, _, rescueGuest := f.guest(t, nil)
		defer rescueGuest()
		client, _ := minimalSupervisorWorkClient(t, f)
		if _, err := client.Exec(context.Background(), minimalJointExecRequest()); err != nil {
			t.Fatal("actual original work prerequisite", err)
		}
		// Keep the existing accept service inside an authenticated connection.
		// After whole Close joins, closing this exact client joins the service
		// without reopening a listener whose lifetime has already ended.
		fd, session := f.cleanup(t)
		minimalSupervisorJointInspect(t, fd, session)
		serving := f.serving(t)
		serving.mu.Lock()
		pair := serving.server
		serving.mu.Unlock()
		if pair == nil || !pair.started || !f.owned.minimalPreparation.workCurrent() {
			_ = unix.Close(fd)
			t.Fatal("actual published pair prerequisite")
		}
		pair.mu.Lock() // Real owned close bookkeeping; no injected observer.
		closed := make(chan struct{})
		rescue := minimalSupervisorOuterCloseRescue(t, f, closed, fd)
		go func() { defer close(closed); f.owned.close() }()
		defer func() {
			pair.mu.Unlock()
			rescue()
		}()
		minimalJointAwait(t, f.owned.minimalPreparation.ctx.Done(), "whole Close cancellation reached")
		select {
		case <-serving.controllerDone:
			t.Fatal("pair lock did not hold the actual compound controller join")
		default:
		}
		timer := time.NewTimer(75 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-f.tracked.process.Done():
			t.Error("whole owner Close entered original process containment before pair/controller join")
		case <-timer.C:
		}
	})
}

func TestMinimalSupervisorWorkOuterCloseRetainsCleanupService(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		_, _, _, rescueGuest := f.guest(t, nil)
		defer rescueGuest()
		client, _ := minimalSupervisorWorkClient(t, f)
		if _, err := client.Exec(context.Background(), minimalJointExecRequest()); err != nil {
			t.Fatal("actual original work prerequisite", err)
		}
		fd, session := f.cleanup(t)
		minimalSupervisorJointInspect(t, fd, session)
		closed := make(chan struct{})
		rescue := minimalSupervisorOuterCloseRescue(t, f, closed, fd)
		defer rescue()
		go func() { defer close(closed); f.owned.close() }()
		minimalJointAwait(t, closed, "concurrent original owner Close")
		response, err := minimalSupervisorJointExchange(fd, session, 2, l8RuntimeOwnerOpcodeInspect)
		defer closeL8RuntimeOwnerFiles(response.Files)
		if f.owned.listenerFD < 0 || err != nil || response.Packet.Opcode != l8RuntimeOwnerOpcodeInspect || response.Packet.Status != l8RuntimeOwnerStatusOK {
			t.Error("concurrent owner Close disposed the original still-serving cleanup authority")
		}
	})
}

func TestMinimalSupervisorWorkPairCloseErrorBlocksCleanupSuccess(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		_, _, _, rescueGuest := f.guest(t, nil)
		defer rescueGuest()
		client, _ := minimalSupervisorWorkClient(t, f)
		if _, err := client.Exec(context.Background(), minimalJointExecRequest()); err != nil {
			t.Fatal("actual original work prerequisite", err)
		}
		serving := f.serving(t)
		serving.mu.Lock()
		pair := serving.server
		serving.mu.Unlock()
		if pair == nil || !pair.started {
			t.Fatal("actual owned pair prerequisite")
		}
		pair.mu.Lock()
		// Lose a genuine retained original alias while its pollable duplicate
		// stays open. Later Close returns a real error, not an injected syscall.
		closeErr := pair.files[0].Close()
		pair.mu.Unlock()
		if closeErr != nil {
			t.Fatal("actual retained pair alias loss prerequisite", closeErr)
		}
		fd, session := f.cleanup(t)
		defer unix.Close(fd)
		response, err := minimalSupervisorJointExchange(fd, session, 1, l8RuntimeOwnerOpcodeStopReap)
		defer closeL8RuntimeOwnerFiles(response.Files)
		minimalJointAwait(t, serving.controllerDone, "actual pair close error reached enclosing scope")
		minimalJointAwait(t, serving.closeDone, "compound I/O barrier completion")
		if serving.closeErr == nil {
			t.Error("compound I/O barrier discarded its actual owned pair Close error")
		}
		if err == nil && response.Packet.Opcode == l8RuntimeOwnerOpcodeStopReap && response.Packet.Status == l8RuntimeOwnerStatusOK {
			t.Error("authenticated cleanup reported success despite unresolved pair Close")
		}
		if f.contained.Load() != 0 {
			t.Error("FSM containment ran after unresolved pair Close")
		}
	})
}
