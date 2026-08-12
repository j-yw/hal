package credentialprotocol

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSSHAgentRelayStateLimits(t *testing.T) {
	t.Parallel()

	if SSHAgentRelayMaxConcurrentConnections != 4 || SSHAgentRelayMaxLifetimeConnections != 64 || SSHAgentRelayMaxAttemptedOperations != 4096 {
		t.Fatal("unexpected SSH-agent relay count limits")
	}
	if SSHAgentRelayIdleTimeout != 5*time.Minute || SSHAgentRelayHardLifetime != 35*time.Minute {
		t.Fatal("unexpected SSH-agent relay time limits")
	}

	startedAt := time.Unix(1_900_000_000, 0)
	state, err := NewSSHAgentRelayState(startedAt)
	if err != nil {
		t.Fatal(err)
	}
	connections := make([]*SSHAgentRelayConnection, 0, SSHAgentRelayMaxConcurrentConnections)
	for index := 0; index < SSHAgentRelayMaxConcurrentConnections; index++ {
		connection, openErr := state.OpenConnection(startedAt)
		if openErr != nil {
			t.Fatalf("OpenConnection(%d): %v", index, openErr)
		}
		connections = append(connections, connection)
	}
	if connection, openErr := state.OpenConnection(startedAt); connection != nil || !errors.Is(openErr, ErrSSHAgentRelayConcurrentConnectionLimit) {
		t.Fatalf("concurrent plus one = %#v, %v", connection, openErr)
	}
	if snapshot := state.Snapshot(); snapshot.ActiveConnections != 4 || snapshot.LifetimeConnections != 4 || snapshot.AttemptedOperations != 0 {
		t.Fatalf("concurrent snapshot = %#v", snapshot)
	}
	for _, connection := range connections {
		connection.Close()
	}

	for index := SSHAgentRelayMaxConcurrentConnections; index < SSHAgentRelayMaxLifetimeConnections; index++ {
		connection, openErr := state.OpenConnection(startedAt)
		if openErr != nil {
			t.Fatalf("lifetime OpenConnection(%d): %v", index, openErr)
		}
		connection.Close()
	}
	if connection, openErr := state.OpenConnection(startedAt); connection != nil || !errors.Is(openErr, ErrSSHAgentRelayLifetimeConnectionLimit) {
		t.Fatalf("lifetime plus one = %#v, %v", connection, openErr)
	}
	if snapshot := state.Snapshot(); snapshot.ActiveConnections != 0 || snapshot.LifetimeConnections != 64 {
		t.Fatalf("lifetime snapshot = %#v", snapshot)
	}
}

func TestSSHAgentRelayOneOutstandingAndAttemptLimit(t *testing.T) {
	t.Parallel()

	startedAt := time.Unix(1_900_000_100, 0)
	state, err := NewSSHAgentRelayState(startedAt)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := state.OpenConnection(startedAt)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	if err := connection.PermitRead(startedAt); err != nil {
		t.Fatalf("first PermitRead: %v", err)
	}
	if err := connection.PermitRead(startedAt); !errors.Is(err, ErrSSHAgentRelayRequestOutstanding) {
		t.Fatalf("second PermitRead error = %v", err)
	}
	// No second frame was read: the denied permission check is not a new wire
	// operation and must not consume another global attempt slot.
	if snapshot := state.Snapshot(); snapshot.AttemptedOperations != 1 {
		t.Fatalf("rejected second read changed attempt count: %#v", snapshot)
	}
	if err := connection.CompleteRequest(startedAt); err != nil {
		t.Fatalf("CompleteRequest: %v", err)
	}
	if err := connection.CompleteRequest(startedAt); !errors.Is(err, ErrSSHAgentRelayNoRequestOutstanding) {
		t.Fatalf("duplicate CompleteRequest error = %v", err)
	}

	for attempt := 1; attempt < SSHAgentRelayMaxAttemptedOperations; attempt++ {
		if err := connection.PermitRead(startedAt); err != nil {
			t.Fatalf("PermitRead(%d): %v", attempt+1, err)
		}
		if err := connection.CompleteRequest(startedAt); err != nil {
			t.Fatalf("CompleteRequest(%d): %v", attempt+1, err)
		}
	}
	if snapshot := state.Snapshot(); snapshot.AttemptedOperations != SSHAgentRelayMaxAttemptedOperations {
		t.Fatalf("attempt snapshot = %#v", snapshot)
	}
	if err := connection.PermitRead(startedAt); !errors.Is(err, ErrSSHAgentRelayOperationLimit) {
		t.Fatalf("operation plus one error = %v", err)
	}
	if snapshot := state.Snapshot(); snapshot.AttemptedOperations != SSHAgentRelayMaxAttemptedOperations {
		t.Fatalf("operation limit did not saturate: %#v", snapshot)
	}
}

func TestSSHAgentRelayEveryReadOutcomeConsumesAttempt(t *testing.T) {
	t.Parallel()

	startedAt := time.Unix(1_900_000_150, 0)
	state, err := NewSSHAgentRelayState(startedAt)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := state.OpenConnection(startedAt)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	// Classification happens after the reserved read. The state deliberately
	// applies identical accounting no matter how the caller classifies it.
	for _, outcome := range []string{"accepted", "rejected", "forbidden", "malformed"} {
		if err := connection.PermitRead(startedAt); err != nil {
			t.Fatalf("%s PermitRead: %v", outcome, err)
		}
		if err := connection.CompleteRequest(startedAt); err != nil {
			t.Fatalf("%s CompleteRequest: %v", outcome, err)
		}
	}
	if snapshot := state.Snapshot(); snapshot.AttemptedOperations != 4 {
		t.Fatalf("outcome accounting snapshot = %#v", snapshot)
	}
}

func TestSSHAgentRelayAttemptLimitIsGlobalAcrossConnections(t *testing.T) {
	t.Parallel()

	startedAt := time.Unix(1_900_000_160, 0)
	state, err := NewSSHAgentRelayState(startedAt)
	if err != nil {
		t.Fatal(err)
	}
	connections := make([]*SSHAgentRelayConnection, SSHAgentRelayMaxConcurrentConnections)
	for index := range connections {
		connections[index], err = state.OpenConnection(startedAt)
		if err != nil {
			t.Fatal(err)
		}
		defer connections[index].Close()
	}
	for attempt := 0; attempt < SSHAgentRelayMaxAttemptedOperations; attempt++ {
		connection := connections[attempt%len(connections)]
		if err := connection.PermitRead(startedAt); err != nil {
			t.Fatalf("PermitRead(%d): %v", attempt+1, err)
		}
		if err := connection.CompleteRequest(startedAt); err != nil {
			t.Fatalf("CompleteRequest(%d): %v", attempt+1, err)
		}
	}
	for index, connection := range connections {
		if err := connection.PermitRead(startedAt); !errors.Is(err, ErrSSHAgentRelayOperationLimit) {
			t.Errorf("connection %d operation plus one error = %v", index, err)
		}
	}
	if snapshot := state.Snapshot(); snapshot.AttemptedOperations != SSHAgentRelayMaxAttemptedOperations {
		t.Fatalf("global attempt snapshot = %#v", snapshot)
	}
}

func TestSSHAgentRelayConcurrentOpenIsAtomic(t *testing.T) {
	startedAt := time.Unix(1_900_000_175, 0)
	state, err := NewSSHAgentRelayState(startedAt)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan *SSHAgentRelayConnection, SSHAgentRelayMaxConcurrentConnections+8)
	var wait sync.WaitGroup
	for index := 0; index < cap(results); index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			connection, _ := state.OpenConnection(startedAt)
			results <- connection
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	accepted := 0
	for connection := range results {
		if connection != nil {
			accepted++
			connection.Close()
		}
	}
	if accepted != SSHAgentRelayMaxConcurrentConnections {
		t.Fatalf("accepted connections = %d, want %d", accepted, SSHAgentRelayMaxConcurrentConnections)
	}
	if snapshot := state.Snapshot(); snapshot.ActiveConnections != 0 || snapshot.LifetimeConnections != SSHAgentRelayMaxConcurrentConnections {
		t.Fatalf("concurrent result snapshot = %#v", snapshot)
	}
}

func TestSSHAgentRelayConcurrentReadPermissionIsAtomic(t *testing.T) {
	startedAt := time.Unix(1_900_000_180, 0)
	state, err := NewSSHAgentRelayState(startedAt)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := state.OpenConnection(startedAt)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	start := make(chan struct{})
	results := make(chan error, 16)
	var wait sync.WaitGroup
	for index := 0; index < cap(results); index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			results <- connection.PermitRead(startedAt)
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	admitted := 0
	for readErr := range results {
		if readErr == nil {
			admitted++
		} else if !errors.Is(readErr, ErrSSHAgentRelayRequestOutstanding) {
			t.Errorf("concurrent PermitRead error = %v", readErr)
		}
	}
	if admitted != 1 {
		t.Fatalf("admitted reads = %d, want 1", admitted)
	}
	if snapshot := state.Snapshot(); snapshot.AttemptedOperations != 1 {
		t.Fatalf("concurrent read snapshot = %#v", snapshot)
	}
}

func TestSSHAgentRelayTimeoutBoundsAndCallerTimestamps(t *testing.T) {
	t.Parallel()

	startedAt := time.Unix(1_900_000_200, 0)
	state, err := NewSSHAgentRelayState(startedAt)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := state.OpenConnection(startedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.PermitRead(startedAt); err != nil {
		t.Fatalf("initial PermitRead: %v", err)
	}
	// Completion is admitted through the instant before the request's idle
	// deadline; an outstanding request does not suspend that deadline.
	completionBeforeDeadline := startedAt.Add(SSHAgentRelayIdleTimeout - time.Nanosecond)
	if err := connection.CompleteRequest(completionBeforeDeadline); err != nil {
		t.Fatalf("completion exact-minus-one: %v", err)
	}
	if err := connection.PermitRead(completionBeforeDeadline); err != nil {
		t.Fatalf("second PermitRead: %v", err)
	}
	// Completion at the exact idle deadline is expired; equality is
	// deliberately fail-closed and releases the active connection slot.
	if err := connection.CompleteRequest(completionBeforeDeadline.Add(SSHAgentRelayIdleTimeout)); !errors.Is(err, ErrSSHAgentRelayIdleTimeout) {
		t.Fatalf("completion exact-bound error = %v", err)
	}
	if snapshot := state.Snapshot(); snapshot.ActiveConnections != 0 || snapshot.AttemptedOperations != 2 {
		t.Fatalf("idle expiry snapshot = %#v", snapshot)
	}

	idleReadState, err := NewSSHAgentRelayState(startedAt)
	if err != nil {
		t.Fatal(err)
	}
	idleReadConnection, err := idleReadState.OpenConnection(startedAt)
	if err != nil {
		t.Fatal(err)
	}
	// A caller may start a read until the instant before the idle deadline.
	if err := idleReadConnection.PermitRead(startedAt.Add(SSHAgentRelayIdleTimeout - time.Nanosecond)); err != nil {
		t.Fatalf("read idle exact-minus-one: %v", err)
	}
	idleReadConnection.Close()
	idleExactConnection, err := idleReadState.OpenConnection(startedAt.Add(SSHAgentRelayIdleTimeout - time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	if err := idleExactConnection.PermitRead(startedAt.Add(2*SSHAgentRelayIdleTimeout - time.Nanosecond)); !errors.Is(err, ErrSSHAgentRelayIdleTimeout) {
		t.Fatalf("read idle exact-bound error = %v", err)
	}

	hardState, err := NewSSHAgentRelayState(startedAt)
	if err != nil {
		t.Fatal(err)
	}
	// The hard lifetime has the same closed-bound rule: one nanosecond before is
	// admitted, while equality and every later timestamp are expired.
	hardConnection, err := hardState.OpenConnection(startedAt.Add(SSHAgentRelayHardLifetime - time.Nanosecond))
	if err != nil {
		t.Fatalf("hard exact-minus-one open: %v", err)
	}
	if err := hardConnection.PermitRead(startedAt.Add(SSHAgentRelayHardLifetime)); !errors.Is(err, ErrSSHAgentRelayHardLifetime) {
		t.Fatalf("hard exact-bound error = %v", err)
	}
	if connection, openErr := hardState.OpenConnection(startedAt.Add(SSHAgentRelayHardLifetime - time.Nanosecond)); connection != nil || !errors.Is(openErr, ErrSSHAgentRelayHardLifetime) {
		t.Fatalf("hard expiry earlier-time resurrection = %#v, %v", connection, openErr)
	}
	if connection, openErr := hardState.OpenConnection(startedAt.Add(SSHAgentRelayHardLifetime + time.Nanosecond)); connection != nil || !errors.Is(openErr, ErrSSHAgentRelayHardLifetime) {
		t.Fatalf("hard plus-one open = %#v, %v", connection, openErr)
	}
	if snapshot := hardState.Snapshot(); snapshot.ActiveConnections != 0 {
		t.Fatalf("hard expiry did not release active slots: %#v", snapshot)
	}

	hardOpenState, err := NewSSHAgentRelayState(startedAt)
	if err != nil {
		t.Fatal(err)
	}
	if connection, openErr := hardOpenState.OpenConnection(startedAt.Add(SSHAgentRelayHardLifetime)); connection != nil || !errors.Is(openErr, ErrSSHAgentRelayHardLifetime) {
		t.Fatalf("hard exact-bound open = %#v, %v", connection, openErr)
	}
	if connection, openErr := hardOpenState.OpenConnection(startedAt.Add(time.Second)); connection != nil || !errors.Is(openErr, ErrSSHAgentRelayHardLifetime) {
		t.Fatalf("hard-open earlier-time resurrection = %#v, %v", connection, openErr)
	}

	regressionState, err := NewSSHAgentRelayState(startedAt)
	if err != nil {
		t.Fatal(err)
	}
	if connection, openErr := regressionState.OpenConnection(startedAt.Add(-time.Nanosecond)); connection != nil || !errors.Is(openErr, ErrSSHAgentRelayTimestamp) {
		t.Fatalf("state timestamp regression = %#v, %v", connection, openErr)
	}
	regressionConnection, err := regressionState.OpenConnection(startedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := regressionConnection.PermitRead(startedAt.Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := regressionConnection.CompleteRequest(startedAt.Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := regressionConnection.PermitRead(startedAt.Add(2 * time.Second)); !errors.Is(err, ErrSSHAgentRelayTimestamp) {
		t.Fatalf("last-activity timestamp regression error = %v", err)
	}
	regressionConnection.Close()
}

func TestSSHAgentRelayHandlesAreCopySafe(t *testing.T) {
	t.Parallel()

	startedAt := time.Unix(1_900_000_250, 0)
	state, err := NewSSHAgentRelayState(startedAt)
	if err != nil {
		t.Fatal(err)
	}
	stateCopy := *state
	connection, err := stateCopy.OpenConnection(startedAt)
	if err != nil {
		t.Fatal(err)
	}
	connectionCopy := *connection
	if err := connectionCopy.PermitRead(startedAt); err != nil {
		t.Fatal(err)
	}
	if err := connection.CompleteRequest(startedAt); err != nil {
		t.Fatal(err)
	}
	if snapshot := state.Snapshot(); snapshot.ActiveConnections != 1 || snapshot.LifetimeConnections != 1 || snapshot.AttemptedOperations != 1 {
		t.Fatalf("copied handle snapshot = %#v", snapshot)
	}
	connectionCopy.Close()
	connection.Close()
	if snapshot := stateCopy.Snapshot(); snapshot.ActiveConnections != 0 || snapshot.LifetimeConnections != 1 {
		t.Fatalf("copied close snapshot = %#v", snapshot)
	}
	stateCopy.Close()
	if connection, openErr := state.OpenConnection(startedAt); connection != nil || !errors.Is(openErr, ErrSSHAgentRelayClosed) {
		t.Fatalf("copied state close = %#v, %v", connection, openErr)
	}
}

func TestSSHAgentRelayClosedAndZeroValuesFailClosed(t *testing.T) {
	t.Parallel()

	if state, err := NewSSHAgentRelayState(time.Time{}); state != nil || !errors.Is(err, ErrSSHAgentRelayTimestamp) {
		t.Fatalf("zero start = %#v, %v", state, err)
	}
	var zeroState SSHAgentRelayState
	if connection, err := zeroState.OpenConnection(time.Unix(1, 0)); connection != nil || !errors.Is(err, ErrSSHAgentRelayStateInvalid) {
		t.Fatalf("zero state open = %#v, %v", connection, err)
	}
	var zeroConnection SSHAgentRelayConnection
	if err := zeroConnection.PermitRead(time.Unix(1, 0)); !errors.Is(err, ErrSSHAgentRelayConnectionInvalid) {
		t.Fatalf("zero connection read error = %v", err)
	}

	state, err := NewSSHAgentRelayState(time.Unix(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	connection, err := state.OpenConnection(time.Unix(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	state.Close()
	state.Close()
	if err := connection.PermitRead(time.Unix(2, 0)); !errors.Is(err, ErrSSHAgentRelayClosed) {
		t.Fatalf("closed state read error = %v", err)
	}
	connection.Close()
	if snapshot := state.Snapshot(); snapshot.ActiveConnections != 0 {
		t.Fatalf("closed snapshot = %#v", snapshot)
	}
}

func TestSSHAgentRelayErrorsAreStableAndSanitized(t *testing.T) {
	t.Parallel()

	canary := "ssh-relay-sensitive-payload-canary"
	for _, err := range []error{
		ErrSSHAgentRelayStateInvalid,
		ErrSSHAgentRelayConnectionInvalid,
		ErrSSHAgentRelayClosed,
		ErrSSHAgentRelayConnectionClosed,
		ErrSSHAgentRelayTimestamp,
		ErrSSHAgentRelayConcurrentConnectionLimit,
		ErrSSHAgentRelayLifetimeConnectionLimit,
		ErrSSHAgentRelayOperationLimit,
		ErrSSHAgentRelayRequestOutstanding,
		ErrSSHAgentRelayNoRequestOutstanding,
		ErrSSHAgentRelayIdleTimeout,
		ErrSSHAgentRelayHardLifetime,
	} {
		if err == nil || strings.Contains(fmt.Sprintf("%v %#v", err, err), canary) {
			t.Fatalf("unsafe relay error: %v", err)
		}
	}
}
