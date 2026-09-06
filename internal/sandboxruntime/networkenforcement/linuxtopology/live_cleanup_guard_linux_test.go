//go:build linux

package linuxtopology

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeL7LiveCleanupTest struct {
	mu       sync.Mutex
	cleanups []func()
	errors   []string
}

func (*fakeL7LiveCleanupTest) Helper() {}

func (test *fakeL7LiveCleanupTest) Cleanup(cleanup func()) {
	test.mu.Lock()
	defer test.mu.Unlock()
	test.cleanups = append(test.cleanups, cleanup)
}

func (test *fakeL7LiveCleanupTest) Errorf(format string, arguments ...any) {
	test.mu.Lock()
	defer test.mu.Unlock()
	test.errors = append(test.errors, fmt.Sprintf(format, arguments...))
}

func TestL7LiveCleanupRegistrationIsImmediateBoundedIdempotentAndExact(t *testing.T) {
	events := make([]string, 0, 2)
	keeper := newFakeProcess(5101, ProcessRoleKeeper, &events)
	mapper := newFakeProcess(5102, ProcessRoleMapping, &events)
	session := &Session{keeper: keeper, mapper: mapper}
	identity := testIdentity("topology-gen-live-cleanup-guard")
	registrar := &fakeL7LiveCleanupTest{}
	readCounts := make(map[int]int)
	stopCalls := 0

	guard, err := registerL7LiveCleanupGuard(registrar, session, identity, l7LiveCleanupGuardDeps{
		Timeout: 250 * time.Millisecond,
		Stop: func(ctx context.Context, got Identity) (Metadata, error) {
			stopCalls++
			if got != identity {
				t.Fatal("cleanup received the wrong topology identity")
			}
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > time.Second {
				t.Fatal("cleanup did not receive an independent bounded context")
			}
			keeper.exit()
			mapper.exit()
			return Metadata{Identity: identity, Status: StatusStopped}, nil
		},
		ReadProcessStartTime: func(pid int) (string, error) {
			readCounts[pid]++
			switch pid {
			case keeper.PID():
				if processDone(keeper) {
					return "", fs.ErrNotExist
				}
				return "keeper-start", nil
			case mapper.PID():
				if processDone(mapper) {
					return "", fs.ErrNotExist
				}
				return "mapper-start", nil
			default:
				t.Fatal("cleanup inspected an untracked process")
				return "", fs.ErrNotExist
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if guard == nil || len(registrar.cleanups) != 1 {
		t.Fatal("cleanup was not registered immediately with both tracked processes")
	}
	if err := guard.StopAndVerify(); err != nil {
		t.Fatal(err)
	}
	registrar.cleanups[0]()
	if stopCalls != 1 {
		t.Fatalf("idempotent cleanup stop calls = %d, want 1", stopCalls)
	}
	if !processDone(keeper) || !processDone(mapper) {
		t.Fatal("cleanup did not finish both exact tracked child processes")
	}
	if readCounts[keeper.PID()] < 3 || readCounts[mapper.PID()] < 3 {
		t.Fatal("cleanup did not capture and independently reverify both process identities")
	}
	if len(registrar.errors) != 0 {
		t.Fatalf("registered cleanup reported errors: %v", registrar.errors)
	}
}

func TestL7RetainedFailedStartCleanupIsImmediateBoundedAndSanitized(t *testing.T) {
	identity := testIdentity("topology-gen-retained-start-cleanup")
	otherIdentity := testIdentity("topology-gen-other-retained-start-cleanup")
	testCases := []struct {
		name     string
		metadata Metadata
		err      error
		wantFail bool
	}{
		{
			name:     "stopped exact identity",
			metadata: Metadata{Identity: identity, Status: StatusStopped},
		},
		{
			name:     "stop error",
			err:      errors.New("unsafe cleanup detail credential=secret"),
			wantFail: true,
		},
		{
			name:     "wrong status",
			metadata: Metadata{Identity: identity, Status: StatusCleanupIncomplete},
			wantFail: true,
		},
		{
			name:     "wrong identity",
			metadata: Metadata{Identity: otherIdentity, Status: StatusStopped},
			wantFail: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			registrar := &fakeL7LiveCleanupTest{}
			session := &Session{metadata: Metadata{Identity: identity, Status: StatusCleanupIncomplete}}
			stopCalls := 0
			registerL7RetainedStartCleanup(registrar, session, identity, l7RetainedStartCleanupDeps{
				Timeout: 250 * time.Millisecond,
				Stop: func(ctx context.Context, got Identity) (Metadata, error) {
					stopCalls++
					if got != identity {
						t.Fatal("retained-start cleanup received the wrong topology identity")
					}
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > time.Second {
						t.Fatal("retained-start cleanup did not receive an independent bounded context")
					}
					return testCase.metadata, testCase.err
				},
			})
			if len(registrar.cleanups) != 1 {
				t.Fatal("retained failed-start cleanup was not registered immediately")
			}
			registrar.cleanups[0]()
			if stopCalls != 1 {
				t.Fatalf("retained failed-start cleanup calls = %d, want 1", stopCalls)
			}
			if testCase.wantFail {
				if len(registrar.errors) != 1 || registrar.errors[0] != "selected L7 retained-start cleanup retry failed" {
					t.Fatalf("retained failed-start cleanup errors = %v", registrar.errors)
				}
				if strings.Contains(strings.Join(registrar.errors, " "), "credential=secret") {
					t.Fatal("retained failed-start cleanup exposed unsafe error detail")
				}
				return
			}
			if len(registrar.errors) != 0 {
				t.Fatalf("retained failed-start cleanup reported errors: %v", registrar.errors)
			}
		})
	}
}
