//go:build l7_setpriv_semantics && linux

package l7profile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestParseL7GetSubIDsSelectsFirstProviderRange(t *testing.T) {
	const username = "semantic-probe-user"
	output := []byte("0: " + username + " 100001 1\n1: " + username + " 200001 32\n")

	got, err := parseL7GetSubIDs(output, username)
	if err != nil {
		t.Fatalf("parse configured provider output: %v", err)
	}
	if got != 100001 {
		t.Fatal("configured provider parser did not select the first safe subordinate ID")
	}
}

func TestParseL7GetSubIDsRejectsInvalidProviderOutput(t *testing.T) {
	const username = "semantic-probe-user"
	tests := []struct {
		name   string
		output string
	}{
		{name: "empty"},
		{name: "missing field", output: "0: " + username + " 100001\n"},
		{name: "malformed index", output: "zero: " + username + " 100001 1\n"},
		{name: "unexpected index", output: "1: " + username + " 100001 1\n"},
		{name: "wrong user", output: "0: another-user 100001 1\n"},
		{name: "malformed start", output: "0: " + username + " invalid 1\n"},
		{name: "malformed count", output: "0: " + username + " 100001 invalid\n"},
		{name: "zero range", output: "0: " + username + " 100001 0\n"},
		{name: "start overflow", output: "0: " + username + " 4294967295 1\n"},
		{name: "range overflow", output: "0: " + username + " 4294967294 2\n"},
		{name: "integer overflow", output: "0: " + username + " 18446744073709551616 1\n"},
		{name: "malformed later entry", output: "0: " + username + " 100001 1\ninvalid\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseL7GetSubIDs([]byte(tt.output), username); err == nil {
				t.Fatal("configured provider parser accepted invalid output")
			}
		})
	}
}

func TestL7SubordinateIDMapUsesOneOuterIDAtNamespaceID1000(t *testing.T) {
	const outerID = uint64(100001)
	want := fmt.Sprintf("1000:%d:1", outerID)
	if got := l7SubordinateIDMap(outerID); got != want {
		t.Fatal("subordinate ID map must map exactly one outer ID at namespace ID 1000")
	}
}

func TestL7ConfiguredProviderQueryAcceptsSuccessfulExit(t *testing.T) {
	output, err := runL7ConfiguredProviderQuery(
		context.Background(),
		5*time.Second,
		64,
		os.Args[0],
		"-test.run=^TestL7ConfiguredProviderHelperProcess$", "--", "success",
	)
	if err != nil {
		t.Fatal("configured provider query rejected a successful bounded child")
	}
	if string(output) != "provider-safe-output\n" {
		t.Fatal("configured provider query returned unexpected successful output")
	}
}

func TestL7ConfiguredProviderQueryRejectsExpiredParentBeforeStart(t *testing.T) {
	originalStart := startL7ConfiguredProviderCommand
	startCalls := 0
	startL7ConfiguredProviderCommand = func(command *exec.Cmd) error {
		startCalls++
		return originalStart(command)
	}
	t.Cleanup(func() {
		startL7ConfiguredProviderCommand = originalStart
	})

	testCases := []struct {
		name    string
		context func() (context.Context, context.CancelFunc)
	}{
		{
			name: "canceled",
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
		},
		{
			name: "deadline expired",
			context: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := testCase.context()
			defer cancel()
			output, err := runL7ConfiguredProviderQuery(
				ctx,
				time.Second,
				64,
				os.Args[0],
				"-test.run=^TestL7ConfiguredProviderHelperProcess$", "--", "success",
			)
			if !errors.Is(err, errL7ConfiguredProviderQuery) || len(output) != 0 {
				t.Fatal("expired parent did not fail with the sanitized provider sentinel")
			}
		})
	}
	if startCalls != 0 {
		t.Fatal("expired parent reached the configured provider executable side effect")
	}
}

func TestL7ConfiguredProviderQueryBoundsOversizedStdout(t *testing.T) {
	const outputLimit = 64
	output, err := runL7ConfiguredProviderQuery(
		context.Background(),
		time.Second,
		outputLimit,
		os.Args[0],
		"-test.run=^TestL7ConfiguredProviderHelperProcess$", "--", "oversized",
	)
	if err == nil {
		t.Fatal("configured provider query accepted oversized stdout")
	}
	if len(output) != outputLimit {
		t.Fatal("configured provider query did not hard-bound captured stdout")
	}
	if strings.Contains(err.Error(), "provider-sensitive") {
		t.Fatal("configured provider query error exposed child output")
	}
}

func TestL7ConfiguredProviderQueryCancelsHungChild(t *testing.T) {
	const timeout = 50 * time.Millisecond
	started := time.Now()
	output, err := runL7ConfiguredProviderQuery(
		context.Background(),
		timeout,
		64,
		os.Args[0],
		"-test.run=^TestL7ConfiguredProviderHelperProcess$", "--", "hang",
	)
	if err == nil {
		t.Fatal("configured provider query accepted a hung child")
	}
	if len(output) != 0 {
		t.Fatal("configured provider query captured unexpected hung-child output")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatal("configured provider query did not terminate its hung child by the deadline")
	}
}

func TestL7ConfiguredProviderQueryRejectsNonzeroExitWithoutStderrDisclosure(t *testing.T) {
	output, err := runL7ConfiguredProviderQuery(
		context.Background(),
		time.Second,
		64,
		os.Args[0],
		"-test.run=^TestL7ConfiguredProviderHelperProcess$", "--", "nonzero",
	)
	if err == nil {
		t.Fatal("configured provider query accepted a nonzero exit")
	}
	if len(output) != 0 {
		t.Fatal("configured provider query captured unexpected nonzero-exit stdout")
	}
	if strings.Contains(err.Error(), "provider-sensitive") {
		t.Fatal("configured provider query error exposed child stderr")
	}
}

func TestL7ConfiguredProviderQueryKillsRetainedStdoutGroupOnOverflow(t *testing.T) {
	const outputLimit = 128
	started := time.Now()
	output, err := runL7ConfiguredProviderQuery(
		context.Background(),
		300*time.Millisecond,
		outputLimit,
		os.Args[0],
		"-test.run=^TestL7ConfiguredProviderHelperProcess$", "--", "group-overflow",
	)
	if err == nil {
		t.Fatal("configured provider query accepted group-owned oversized stdout")
	}
	if len(output) != outputLimit {
		t.Fatal("configured provider query did not bound group-owned stdout")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatal("configured provider overflow cleanup exceeded the total operation budget")
	}
	parentPID, descendantPID := parseL7HelperProcessIDs(t, output)
	cleanupL7HelperProcess(t, descendantPID)
	requireL7HelperProcessAbsent(t, parentPID)
	requireL7HelperProcessAbsent(t, descendantPID)
	requireL7HelperProcessGroupAbsent(t, parentPID)
	if strings.Contains(err.Error(), "provider-sensitive") {
		t.Fatal("configured provider overflow error exposed child output")
	}
}

func TestL7ConfiguredProviderQueryKillsRetainedStdoutGroupOnParentCancellation(t *testing.T) {
	readyPath := filepath.Join(t.TempDir(), "provider-ready")
	parent, cancel := context.WithCancel(context.Background())
	type queryResult struct {
		output []byte
		err    error
	}
	result := make(chan queryResult, 1)
	go func() {
		output, err := runL7ConfiguredProviderQuery(
			parent,
			2*time.Second,
			256,
			os.Args[0],
			"-test.run=^TestL7ConfiguredProviderHelperProcess$", "--", "group-cancel", readyPath,
		)
		result <- queryResult{output: output, err: err}
	}()

	processIDs := waitForL7HelperProcessIDs(t, readyPath)
	cleanupL7HelperProcess(t, processIDs[1])
	started := time.Now()
	cancel()
	got := <-result
	if got.err == nil {
		t.Fatal("configured provider query accepted parent cancellation")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatal("configured provider cancellation cleanup exceeded the total operation budget")
	}
	parentPID, descendantPID := parseL7HelperProcessIDs(t, got.output)
	if parentPID != processIDs[0] || descendantPID != processIDs[1] {
		t.Fatal("configured provider query returned inconsistent sanitized helper metadata")
	}
	requireL7HelperProcessAbsent(t, parentPID)
	requireL7HelperProcessAbsent(t, descendantPID)
	requireL7HelperProcessGroupAbsent(t, parentPID)
	if strings.Contains(got.err.Error(), "provider-sensitive") {
		t.Fatal("configured provider cancellation error exposed child output")
	}
}

func TestL7ConfiguredProviderQueryKeepsLeaderUnreapedThroughGroupCleanup(t *testing.T) {
	originalSignal := signalL7ConfiguredProviderProcessGroup
	originalMembers := l7ConfiguredProviderProcessGroupHasOtherMembers
	originalReap := reapL7ConfiguredProviderCommand
	var reapStarted atomic.Bool
	var unsafeSignal atomic.Bool
	var absenceProved atomic.Bool
	var signalCalls atomic.Int32
	var reapCalls atomic.Int32
	signalL7ConfiguredProviderProcessGroup = func(processGroupID int, signal syscall.Signal) error {
		if reapStarted.Load() {
			unsafeSignal.Store(true)
		}
		signalCalls.Add(1)
		return originalSignal(processGroupID, signal)
	}
	l7ConfiguredProviderProcessGroupHasOtherMembers = func(processGroupID, leaderPID int) (bool, error) {
		hasMembers, err := originalMembers(processGroupID, leaderPID)
		if err == nil && !hasMembers && !reapStarted.Load() {
			absenceProved.Store(true)
		}
		return hasMembers, err
	}
	reapL7ConfiguredProviderCommand = func(command *exec.Cmd) error {
		reapCalls.Add(1)
		if !absenceProved.Load() {
			t.Error("configured provider leader reaped before process-group absence proof")
		}
		reapStarted.Store(true)
		return originalReap(command)
	}
	t.Cleanup(func() {
		signalL7ConfiguredProviderProcessGroup = originalSignal
		l7ConfiguredProviderProcessGroupHasOtherMembers = originalMembers
		reapL7ConfiguredProviderCommand = originalReap
	})

	output, err := runL7ConfiguredProviderQuery(
		context.Background(),
		time.Second,
		256,
		os.Args[0],
		"-test.run=^TestL7ConfiguredProviderHelperProcess$", "--", "parent-exit-group",
	)
	if !errors.Is(err, errL7ConfiguredProviderQuery) {
		t.Fatal("configured provider query accepted a retained process-group descendant")
	}
	parentPID, descendantPID := parseL7HelperProcessIDs(t, output)
	cleanupL7HelperProcess(t, descendantPID)
	if signalCalls.Load() == 0 || reapCalls.Load() != 1 || unsafeSignal.Load() || !absenceProved.Load() {
		t.Fatal("configured provider query did not preserve reuse-safe group cleanup ordering")
	}
	requireL7HelperProcessAbsent(t, parentPID)
	requireL7HelperProcessAbsent(t, descendantPID)
}

func TestL7ConfiguredProviderQueryReapsLeaderWhenDrainJoinStaysIncomplete(t *testing.T) {
	originalStart := startL7ConfiguredProviderCommand
	originalReap := reapL7ConfiguredProviderCommand
	originalWaitDrain := waitL7ConfiguredProviderOutputDrain
	leaderPID := 0
	reapCalls := 0
	startL7ConfiguredProviderCommand = func(command *exec.Cmd) error {
		if err := originalStart(command); err != nil {
			return err
		}
		leaderPID = command.Process.Pid
		return nil
	}
	reapL7ConfiguredProviderCommand = func(command *exec.Cmd) error {
		reapCalls++
		return originalReap(command)
	}
	waitL7ConfiguredProviderOutputDrain = func(*l7ConfiguredProviderOutputDrain, time.Time) (error, bool) {
		return nil, false
	}
	t.Cleanup(func() {
		startL7ConfiguredProviderCommand = originalStart
		reapL7ConfiguredProviderCommand = originalReap
		waitL7ConfiguredProviderOutputDrain = originalWaitDrain
		if reapCalls == 0 && leaderPID > 0 {
			_ = syscall.Kill(leaderPID, syscall.SIGKILL)
			var status syscall.WaitStatus
			_, _ = syscall.Wait4(leaderPID, &status, 0, nil)
		}
	})

	output, err := runL7ConfiguredProviderQuery(
		context.Background(),
		5*time.Second,
		64,
		os.Args[0],
		"-test.run=^TestL7ConfiguredProviderHelperProcess$", "--", "success",
	)
	if !errors.Is(err, errL7ConfiguredProviderQuery) || len(output) > 64 {
		t.Fatal("configured provider query did not fail closed on incomplete drain proof")
	}
	if reapCalls != 1 {
		t.Fatalf("configured provider leader reap calls = %d, want exactly 1", reapCalls)
	}
}

func TestL7ConfiguredProviderQueryArrangesBoundedReapWhenTerminalObservationTimesOut(t *testing.T) {
	originalStart := startL7ConfiguredProviderCommand
	originalObserve := observeL7ConfiguredProviderLeaderState
	originalSignal := signalL7ConfiguredProviderProcessGroup
	originalReap := reapL7ConfiguredProviderCommand
	releaseReap := make(chan struct{})
	reapDone := make(chan struct{})
	released := false
	var leaderPID atomic.Int32
	var reapStarted atomic.Bool
	var unsafeSignal atomic.Bool
	var signalCalls atomic.Int32
	var reapCalls atomic.Int32
	startL7ConfiguredProviderCommand = func(command *exec.Cmd) error {
		if err := originalStart(command); err != nil {
			return err
		}
		leaderPID.Store(int32(command.Process.Pid))
		return nil
	}
	observeL7ConfiguredProviderLeaderState = func(int) (bool, error) {
		return false, nil
	}
	signalL7ConfiguredProviderProcessGroup = func(processGroupID int, signal syscall.Signal) error {
		if reapStarted.Load() {
			unsafeSignal.Store(true)
		}
		signalCalls.Add(1)
		return originalSignal(processGroupID, signal)
	}
	reapL7ConfiguredProviderCommand = func(command *exec.Cmd) error {
		reapCalls.Add(1)
		reapStarted.Store(true)
		<-releaseReap
		err := originalReap(command)
		close(reapDone)
		return err
	}
	t.Cleanup(func() {
		if !released {
			close(releaseReap)
		}
		select {
		case <-reapDone:
		case <-time.After(time.Second):
		}
		startL7ConfiguredProviderCommand = originalStart
		observeL7ConfiguredProviderLeaderState = originalObserve
		signalL7ConfiguredProviderProcessGroup = originalSignal
		reapL7ConfiguredProviderCommand = originalReap
		if reapCalls.Load() == 0 && leaderPID.Load() > 0 {
			pid := int(leaderPID.Load())
			_ = syscall.Kill(pid, syscall.SIGKILL)
			var status syscall.WaitStatus
			_, _ = syscall.Wait4(pid, &status, 0, nil)
		}
	})

	started := time.Now()
	output, err := runL7ConfiguredProviderQuery(
		context.Background(),
		20*time.Millisecond,
		64,
		os.Args[0],
		"-test.run=^TestL7ConfiguredProviderHelperProcess$", "--", "success",
	)
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatal("configured provider query did not bound its arranged reap wait")
	}
	if !errors.Is(err, errL7ConfiguredProviderQuery) || len(output) > 64 {
		t.Fatal("configured provider query did not fail with the sanitized sentinel")
	}
	if signalCalls.Load() == 0 || reapCalls.Load() != 1 || !reapStarted.Load() || unsafeSignal.Load() {
		t.Fatal("configured provider query did not arrange one reuse-safe reap after signaling")
	}
	close(releaseReap)
	released = true
	select {
	case <-reapDone:
	case <-time.After(time.Second):
		t.Fatal("configured provider arranged reap did not finish after release")
	}
	requireL7HelperProcessAbsent(t, int(leaderPID.Load()))
}

func TestL7ConfiguredProviderQueryBoundsEscapedRetainedPipe(t *testing.T) {
	started := time.Now()
	output, err := runL7ConfiguredProviderQuery(
		context.Background(),
		2*time.Second,
		1024,
		os.Args[0],
		"-test.run=^TestL7ConfiguredProviderHelperProcess$", "--", "parent-exit-escaped",
	)
	if !errors.Is(err, errL7ConfiguredProviderQuery) {
		t.Fatal("configured provider query accepted an escaped retained output pipe")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatal("configured provider query did not bound escaped retained-pipe cleanup")
	}
	parentPID, descendantPID := parseL7HelperProcessIDs(t, output)
	cleanupL7HelperProcess(t, descendantPID)
	waitForL7HelperProcessAbsent(t, descendantPID)
	requireL7HelperProcessAbsent(t, parentPID)
	if strings.Contains(err.Error(), "provider-sensitive") {
		t.Fatal("configured provider retained-pipe error exposed child output")
	}
}

func TestL7ConfiguredProviderHelperProcess(t *testing.T) {
	mode := ""
	for index, argument := range os.Args {
		if argument == "--" && index+1 < len(os.Args) {
			mode = os.Args[index+1]
			break
		}
	}
	switch mode {
	case "success":
		_, _ = os.Stdout.WriteString("provider-safe-output\n")
		os.Exit(0)
	case "oversized":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("provider-sensitive-output"), 16))
		_, _ = os.Stderr.WriteString("provider-sensitive-stderr")
	case "hang":
		time.Sleep(time.Minute)
	case "nonzero":
		_, _ = os.Stderr.WriteString("provider-sensitive-stderr")
		os.Exit(7)
	case "group-overflow", "group-cancel":
		descendant := exec.Command(
			os.Args[0],
			"-test.run=^TestL7ConfiguredProviderHelperProcess$", "--", "descendant",
		)
		descendant.Stdout = os.Stdout
		descendant.Stderr = os.Stderr
		if err := descendant.Start(); err != nil {
			os.Exit(8)
		}
		metadata := fmt.Sprintf("processes:%d:%d\n", os.Getpid(), descendant.Process.Pid)
		_, _ = os.Stdout.WriteString(metadata)
		if mode == "group-cancel" && len(os.Args) > 1 {
			readyPath := os.Args[len(os.Args)-1]
			if err := os.WriteFile(readyPath, []byte(metadata), 0o600); err != nil {
				os.Exit(9)
			}
		}
		if mode == "group-overflow" {
			_, _ = os.Stdout.Write(bytes.Repeat([]byte("provider-sensitive-output"), 32))
		}
		time.Sleep(time.Minute)
	case "parent-exit-group", "parent-exit-escaped":
		descendantMode := "descendant"
		if mode == "parent-exit-escaped" {
			descendantMode = "escaped-pipe"
		}
		descendant := exec.Command(
			os.Args[0],
			"-test.run=^TestL7ConfiguredProviderHelperProcess$", "--", descendantMode,
		)
		descendant.Stdout = os.Stdout
		descendant.Stderr = os.Stderr
		if mode == "parent-exit-escaped" {
			descendant.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		}
		if err := descendant.Start(); err != nil {
			os.Exit(10)
		}
		_, _ = os.Stdout.WriteString(fmt.Sprintf("processes:%d:%d\n", os.Getpid(), descendant.Process.Pid))
	case "descendant":
		signal.Ignore(syscall.SIGTERM)
		time.Sleep(time.Minute)
	case "escaped-pipe":
		for {
			if _, err := os.Stdout.Write([]byte(".")); err != nil {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
}

func parseL7HelperProcessIDs(t *testing.T, output []byte) (int, int) {
	t.Helper()
	line := strings.SplitN(string(output), "\n", 2)[0]
	parts := strings.Split(line, ":")
	if len(parts) != 3 || parts[0] != "processes" {
		t.Fatal("configured provider query omitted sanitized helper process metadata")
	}
	parentPID, parentErr := strconv.Atoi(parts[1])
	descendantPID, descendantErr := strconv.Atoi(parts[2])
	if parentErr != nil || descendantErr != nil || parentPID <= 0 || descendantPID <= 0 {
		t.Fatal("configured provider query returned invalid sanitized helper process metadata")
	}
	return parentPID, descendantPID
}

func waitForL7HelperProcessIDs(t *testing.T, path string) [2]int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		metadata, err := os.ReadFile(path)
		if err == nil {
			parentPID, descendantPID := parseL7HelperProcessIDs(t, metadata)
			return [2]int{parentPID, descendantPID}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("configured provider helper did not reach its sanitized readiness boundary")
	return [2]int{}
}

func cleanupL7HelperProcess(t *testing.T, pid int) {
	t.Helper()
	t.Cleanup(func() {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	})
}

func requireL7HelperProcessAbsent(t *testing.T, pid int) {
	t.Helper()
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatal("configured provider query left an exact helper process behind")
	}
}

func waitForL7HelperProcessAbsent(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("configured provider retained-pipe descendant remained live")
}

func requireL7HelperProcessGroupAbsent(t *testing.T, processGroupID int) {
	t.Helper()
	hasMembers, err := scanL7ConfiguredProviderProcessGroup(processGroupID, 0)
	if err != nil || hasMembers {
		t.Fatal("configured provider query left its exact helper process group behind")
	}
}
