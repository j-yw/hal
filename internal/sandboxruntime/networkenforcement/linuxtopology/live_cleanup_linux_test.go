//go:build linux

package linuxtopology

import (
	"context"
	"errors"
	"io/fs"
	"sync"
	"time"
)

var errL7LiveCleanupIncomplete = errors.New("selected L7 topology cleanup proof incomplete")

type l7LiveCleanupTest interface {
	Helper()
	Cleanup(func())
	Errorf(string, ...any)
}

type l7LiveCleanupGuardDeps struct {
	Timeout              time.Duration
	Stop                 func(context.Context, Identity) (Metadata, error)
	ReadProcessStartTime func(int) (string, error)
}

type l7RetainedStartCleanupDeps struct {
	Timeout time.Duration
	Stop    func(context.Context, Identity) (Metadata, error)
}

type l7LiveTrackedProcess struct {
	handle    ProcessHandle
	pid       int
	startTime string
}

type l7LiveCleanupGuard struct {
	mu       sync.Mutex
	identity Identity
	deps     l7LiveCleanupGuardDeps
	keeper   l7LiveTrackedProcess
	mapper   l7LiveTrackedProcess
	stopped  bool
	metadata Metadata
}

func registerL7RetainedStartCleanup(
	test l7LiveCleanupTest,
	session *Session,
	identity Identity,
	deps l7RetainedStartCleanupDeps,
) {
	if test == nil {
		return
	}
	test.Helper()
	if session == nil || deps.Timeout <= 0 || deps.Stop == nil {
		test.Errorf("selected L7 retained-start cleanup retry failed")
		return
	}
	test.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), deps.Timeout)
		metadata, err := deps.Stop(ctx, identity)
		cancel()
		if err != nil || metadata.Status != StatusStopped || metadata.Identity != identity {
			test.Errorf("selected L7 retained-start cleanup retry failed")
		}
	})
}

func registerL7LiveCleanupGuard(
	test l7LiveCleanupTest,
	session *Session,
	identity Identity,
	deps l7LiveCleanupGuardDeps,
) (*l7LiveCleanupGuard, error) {
	if test == nil || session == nil || deps.Timeout <= 0 || deps.Stop == nil || deps.ReadProcessStartTime == nil {
		return nil, errL7LiveCleanupIncomplete
	}
	test.Helper()
	session.mu.Lock()
	keeper := session.keeper
	mapper := session.mapper
	session.mu.Unlock()
	guard := &l7LiveCleanupGuard{
		identity: identity,
		deps:     deps,
		keeper:   l7LiveTrackedProcess{handle: keeper},
		mapper:   l7LiveTrackedProcess{handle: mapper},
	}
	test.Cleanup(func() {
		if err := guard.StopAndVerify(); err != nil {
			test.Errorf("selected L7 topology registered cleanup failed: %v", err)
		}
	})
	if err := guard.captureExactProcessIdentities(); err != nil {
		return guard, err
	}
	return guard, nil
}

func (guard *l7LiveCleanupGuard) captureExactProcessIdentities() error {
	for _, tracked := range []*l7LiveTrackedProcess{&guard.mapper, &guard.keeper} {
		if tracked.handle == nil || tracked.handle.PID() <= 0 {
			return errL7LiveCleanupIncomplete
		}
		tracked.pid = tracked.handle.PID()
		startTime, err := guard.deps.ReadProcessStartTime(tracked.pid)
		if err != nil || startTime == "" || processDone(tracked.handle) {
			return errL7LiveCleanupIncomplete
		}
		tracked.startTime = startTime
	}
	return nil
}

func (guard *l7LiveCleanupGuard) Stop() (Metadata, error) {
	if guard == nil {
		return Metadata{}, errL7LiveCleanupIncomplete
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	return guard.stopLocked()
}

func (guard *l7LiveCleanupGuard) stopLocked() (Metadata, error) {
	if guard.stopped {
		return guard.metadata, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), guard.deps.Timeout)
	metadata, err := guard.deps.Stop(ctx, guard.identity)
	cancel()
	if err != nil || metadata.Status != StatusStopped || metadata.Identity != guard.identity {
		return metadata, errL7LiveCleanupIncomplete
	}
	guard.stopped = true
	guard.metadata = metadata
	return metadata, nil
}

func (guard *l7LiveCleanupGuard) VerifyAbsent() error {
	if guard == nil {
		return errL7LiveCleanupIncomplete
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	return guard.verifyAbsentLocked()
}

func (guard *l7LiveCleanupGuard) verifyAbsentLocked() error {
	if !guard.stopped {
		return errL7LiveCleanupIncomplete
	}
	for _, tracked := range []l7LiveTrackedProcess{guard.mapper, guard.keeper} {
		if tracked.handle == nil || tracked.pid <= 0 || tracked.startTime == "" || !processDone(tracked.handle) {
			return errL7LiveCleanupIncomplete
		}
		if _, err := guard.deps.ReadProcessStartTime(tracked.pid); !errors.Is(err, fs.ErrNotExist) {
			return errL7LiveCleanupIncomplete
		}
	}
	return nil
}

func (guard *l7LiveCleanupGuard) StopAndVerify() error {
	if guard == nil {
		return errL7LiveCleanupIncomplete
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if _, err := guard.stopLocked(); err != nil {
		return err
	}
	return guard.verifyAbsentLocked()
}
