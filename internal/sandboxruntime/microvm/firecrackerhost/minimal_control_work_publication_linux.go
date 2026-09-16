//go:build linux

package firecrackerhost

import (
	"context"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Derive the original release window and selected identity again. Public event
// metadata is output only, never an input to manager/process authority.
func (serving *minimalControlSupervisorServing) publicationWindow(ready *minimalControlReadiness) (minimalControlReleaseWindow, error) {
	var window minimalControlReleaseWindow
	owned, prep := serving.owned, serving.owned.minimalPreparation
	selected := owned.selected
	if !ready.Current() || !prep.matchesAdmission(serving.admission, selected.config) {
		return window, errL8RuntimeOwnerInvalid
	}
	selected.mu.Lock()
	coordinator, lifecycle, starter := selected.coordinator, selected.lifecycle, selected.starter
	if selected.minimalPreparation != prep || selected.store != owned.store || !selected.attempted || selected.terminal || coordinator == nil || lifecycle == nil || starter == nil {
		selected.mu.Unlock()
		return window, errL8RuntimeOwnerInvalid
	}
	coordinator.mu.Lock()
	generation := coordinator.generation
	valid := generation != nil && generation.state == strictJailerCoordinatorActive && generation.hasProcess &&
		selected.session.coordinator == coordinator && selected.session.generation == generation.id &&
		coordinator.deps.lifecycle == lifecycle && lifecycle.manager == ready.controller.transport.manager && generation.process.handle == ready.handle
	coordinator.mu.Unlock()
	selected.mu.Unlock()
	if !valid {
		return window, errL8RuntimeOwnerInvalid
	}
	starter.mu.Lock()
	gate := starter.minimalGate
	valid = gate != nil && gate.matches(starter, prep) && starter.released && !starter.closed && !gate.closing
	if valid {
		window = gate.window
	}
	starter.mu.Unlock()
	if !valid || window.startedAt.IsZero() || window.deadline != earlierMinimalControlTime(prep.deadline, window.startedAt.Add(minimalControlStartupTimeout)) || !prep.current() || !ready.Current() {
		return minimalControlReleaseWindow{}, errL8RuntimeOwnerInvalid
	}
	return window, nil
}

func (serving *minimalControlSupervisorServing) publishWork(ready *minimalControlReadiness) error {
	serving.mu.Lock()
	if serving.closing || serving.publicationDone != nil {
		serving.mu.Unlock()
		return errL8RuntimeOwnerInvalid
	}
	serving.publicationDone = make(chan struct{})
	serving.mu.Unlock()
	// A failed or ambiguous attempt consumes this publication forever.
	defer close(serving.publicationDone)
	defer func() {
		// The registered partial owner also survives a constructor panic before
		// assignment returns. Only this enclosing consume task closes/joins it.
		serving.mu.Lock()
		partial := serving.server
		serving.mu.Unlock()
		if partial != nil {
			_ = partial.close()
		}
	}()
	s, err := serving.newWorkServer(ready)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	s.start()
	window, err := serving.publicationWindow(ready)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	prep := serving.owned.minimalPreparation
	event := minimalControlReadinessEventV1{configSHA256: prep.correlation,
		supervisorGeneration: serving.owned.genesis.SupervisorGeneration, processGeneration: ready.handle.ID,
		transportGeneration: ready.transportGeneration, sessionID: ready.sessionID, readinessBindingSHA256: s.binding}
	wire, err := encodeMinimalWorkReady(event)
	if err != nil || serving.sendWorkEndpoint(ready, window, wire, s.files[1]) != nil {
		return errL8RuntimeOwnerInvalid
	}
	// The send and its watcher are joined before surrendering our producer alias.
	s.mu.Lock()
	err = s.files[1].Close()
	s.files[1] = nil
	s.mu.Unlock()
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	current, err := serving.publicationWindow(ready)
	if err != nil || current != window || prep.commitWorkPublication(ready, window) != nil {
		return errL8RuntimeOwnerInvalid
	}
	close(s.commit)
	// Keep the original controller/key scope through every work exchange. The
	// paired server closes and joins before that consume scope is allowed to end.
	<-s.ctx.Done()
	return errL8RuntimeOwnerInvalid
}

func (serving *minimalControlSupervisorServing) sendWorkEndpoint(ready *minimalControlReadiness, window minimalControlReleaseWindow, wire []byte, endpoint *os.File) (resultErr error) {
	prep := serving.owned.minimalPreparation
	bound := earlierMinimalControlTime(prep.deadline, earlierMinimalControlTime(window.deadline, ready.admissionDeadline))
	prep.mu.Lock()
	if prep.closing || !prep.current() || !time.Now().Before(bound) || !validMinimalWorkEndpoint(endpoint) {
		prep.mu.Unlock()
		return errL8RuntimeOwnerInvalid
	}
	originalFD := int(prep.original.Fd())
	var original unix.Stat_t
	if unix.Fstat(originalFD, &original) != nil {
		prep.mu.Unlock()
		return errL8RuntimeOwnerInvalid
	}
	fd, err := unix.FcntlInt(uintptr(originalFD), unix.F_DUPFD_CLOEXEC, 10)
	prep.mu.Unlock()
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	file := os.NewFile(uintptr(fd), "minimal-work-publication")
	var duplicate unix.Stat_t
	if unix.Fstat(fd, &duplicate) != nil || duplicate.Dev != original.Dev || duplicate.Ino != original.Ino {
		_ = file.Close()
		return errL8RuntimeOwnerInvalid
	}
	ctx, cancel := context.WithDeadline(prep.ctx, bound)
	stop, done := make(chan struct{}), make(chan struct{})
	var shutdownErr error
	go func() {
		defer close(done)
		select {
		case <-stop:
			return
		case <-ctx.Done():
		case <-ready.controller.Loss():
		}
		shutdownErr = unix.Shutdown(fd, unix.SHUT_RDWR)
	}()
	defer func() {
		close(stop)
		<-done
		cancel()
		if file.Close() != nil || shutdownErr != nil || !prep.current() || !time.Now().Before(bound) || !ready.Current() {
			resultErr = errL8RuntimeOwnerInvalid
		}
	}()
	remaining := time.Until(bound)
	if remaining < time.Microsecond || unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, minimalWorkTimeval(remaining)) != nil {
		return errL8RuntimeOwnerInvalid
	}
	current, err := serving.publicationWindow(ready)
	if err != nil || current != window || ctx.Err() != nil || !time.Now().Before(bound) {
		return errL8RuntimeOwnerInvalid
	}
	n, err := unix.SendmsgN(fd, wire, unix.UnixRights(int(endpoint.Fd())), nil, unix.MSG_NOSIGNAL)
	if err != nil || n != len(wire) {
		return errL8RuntimeOwnerInvalid // Never retry an ambiguous ancillary send.
	}
	return nil
}

func minimalWorkTimeval(remaining time.Duration) *unix.Timeval {
	value := unix.NsecToTimeval(remaining.Nanoseconds())
	return &value
}
