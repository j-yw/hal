//go:build l7_setpriv_semantics && linux

package l7profile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	l7ConfiguredProviderOutputLimit = 16 * 1024
	l7ConfiguredProviderTimeout     = 5 * time.Second
	l7ConfiguredProviderCleanup     = 250 * time.Millisecond
)

var errL7ConfiguredProviderQuery = errors.New("configured subordinate ID provider query failed")

var (
	startL7ConfiguredProviderCommand = func(command *exec.Cmd) error {
		return command.Start()
	}
	signalL7ConfiguredProviderProcessGroup = func(processGroupID int, signal syscall.Signal) error {
		return syscall.Kill(-processGroupID, signal)
	}
	reapL7ConfiguredProviderCommand = func(command *exec.Cmd) error {
		return command.Wait()
	}
	l7ConfiguredProviderProcessGroupHasOtherMembers = scanL7ConfiguredProviderProcessGroup
)

func TestL7SetprivLockedKeepCapsSemantics(t *testing.T) {
	for _, command := range []string{"getsubids", "newgidmap", "newuidmap", "setpriv", "unshare"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Fatalf("%s is required for the explicit setpriv semantic gate", command)
		}
	}
	current, err := user.Current()
	if err != nil || strings.TrimSpace(current.Username) == "" {
		t.Fatal("current user identity is required for the explicit setpriv semantic gate")
	}
	uidStart := requireL7SubordinateID(t, current.Username, false)
	gidStart := requireL7SubordinateID(t, current.Username, true)

	productionOptions := l7ProductionSetprivOptions(t)
	arguments := []string{
		"--user",
		"--map-users=" + l7IDMap(0, uint64(os.Getuid()), 1),
		"--map-users=" + l7SubordinateIDMap(uidStart),
		"--map-groups=" + l7IDMap(0, uint64(os.Getgid()), 1),
		"--map-groups=" + l7SubordinateIDMap(gidStart),
		"--setgroups=allow",
		"setpriv",
	}
	arguments = append(arguments, productionOptions...)
	arguments = append(arguments,
		"/bin/sh", "-c",
		"/usr/bin/setpriv --dump; grep -E '^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs):' /proc/self/status",
	)
	output, err := exec.Command("unshare", arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("setpriv semantic probe failed with sanitized exit state: %v", err)
	}
	text := string(output)
	for _, required := range []string{
		"Inheritable capabilities: [none]",
		"Ambient capabilities: [none]",
		"Capability bounding set: [none]",
		"Securebits: keep_caps_locked",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("setpriv semantic probe missing sanitized assertion %q", required)
		}
	}
	requireL7StatusFields(t, text, "uid:", []string{"1000"})
	requireL7StatusFields(t, text, "euid:", []string{"1000"})
	requireL7StatusFields(t, text, "gid:", []string{"1000"})
	requireL7StatusFields(t, text, "egid:", []string{"1000"})
	requireL7StatusFields(t, text, "Supplementary groups:", []string{"[none]"})
	requireL7StatusFields(t, text, "no_new_privs:", []string{"1"})
	requireL7ProcStatusFields(t, text, "Uid:", []string{"1000", "1000", "1000", "1000"})
	requireL7ProcStatusFields(t, text, "Gid:", []string{"1000", "1000", "1000", "1000"})
	requireL7ProcStatusFields(t, text, "Groups:", nil)
	for _, field := range []string{"CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"} {
		requireL7ProcStatusFields(t, text, field, []string{"0000000000000000"})
	}
	requireL7ProcStatusFields(t, text, "NoNewPrivs:", []string{"1"})
}

func requireL7ProcStatusFields(t *testing.T, output, name string, want []string) {
	requireL7StatusFields(t, output, name, want)
}

func requireL7StatusFields(t *testing.T, output, name string, want []string) {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if !strings.HasPrefix(line, name) {
			continue
		}
		got := strings.Fields(strings.TrimPrefix(line, name))
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Fatalf("setpriv semantic probe returned an invalid sanitized %s field", name)
		}
		return
	}
	t.Fatalf("setpriv semantic probe omitted sanitized %s field", name)
}

func l7ProductionSetprivOptions(t *testing.T) []string {
	t.Helper()
	init := readProfileFile(t, "rootfs-overlay/sbin/init")
	lines := strings.Split(init, "\n")
	options := make([]string, 0, 12)
	reading := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "/usr/bin/setpriv \\" {
			reading = true
			continue
		}
		if !reading {
			continue
		}
		line = strings.TrimSpace(strings.TrimSuffix(line, "\\"))
		if line == "/usr/bin/hal-guest-agent" {
			break
		}
		options = append(options, strings.Fields(line)...)
	}
	want := []string{
		"--bounding-set=-all",
		"--inh-caps=-all",
		"--ambient-caps=-all",
		"--securebits=+keep_caps_locked",
		"--reuid", "1000",
		"--regid", "1000",
		"--clear-groups",
		"--no-new-privs",
	}
	if strings.Join(options, "\x00") != strings.Join(want, "\x00") {
		t.Fatal("production setpriv option sequence drifted from the semantic probe contract")
	}
	return options
}

func requireL7SubordinateID(t *testing.T, username string, group bool) uint64 {
	t.Helper()
	arguments := []string{username}
	if group {
		arguments = []string{"-g", username}
	}
	output, err := runL7ConfiguredProviderQuery(
		context.Background(),
		l7ConfiguredProviderTimeout,
		l7ConfiguredProviderOutputLimit,
		"getsubids",
		arguments...,
	)
	if err != nil {
		t.Fatal("configured subordinate ID provider query failed for the explicit setpriv semantic gate")
	}
	id, err := parseL7GetSubIDs(output, username)
	if err != nil {
		t.Fatal("configured subordinate ID provider returned invalid output for the explicit setpriv semantic gate")
	}
	return id
}

type l7BoundedOutput struct {
	mu           sync.Mutex
	data         []byte
	limit        int
	overflow     bool
	overflowOnce sync.Once
	overflowed   chan struct{}
}

func newL7BoundedOutput(limit int) *l7BoundedOutput {
	return &l7BoundedOutput{
		data:       make([]byte, 0, limit),
		limit:      limit,
		overflowed: make(chan struct{}),
	}
}

func (output *l7BoundedOutput) markOverflow() {
	output.overflow = true
	output.overflowOnce.Do(func() {
		close(output.overflowed)
	})
}

func (output *l7BoundedOutput) Write(data []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	written := len(data)
	remaining := output.limit - len(output.data)
	if remaining <= 0 {
		if written > 0 {
			output.markOverflow()
		}
		return written, nil
	}
	if len(data) > remaining {
		output.data = append(output.data, data[:remaining]...)
		output.markOverflow()
		return written, nil
	}
	output.data = append(output.data, data...)
	return written, nil
}

func (output *l7BoundedOutput) snapshot() ([]byte, bool) {
	output.mu.Lock()
	defer output.mu.Unlock()
	return append([]byte(nil), output.data...), output.overflow
}

type l7ConfiguredProviderOutputDrain struct {
	reader    *os.File
	done      chan error
	closeOnce sync.Once
	complete  bool
	err       error
}

func newL7ConfiguredProviderOutputDrain(reader *os.File, output io.Writer) *l7ConfiguredProviderOutputDrain {
	drain := &l7ConfiguredProviderOutputDrain{
		reader: reader,
		done:   make(chan error, 1),
	}
	go func() {
		_, err := io.Copy(output, reader)
		drain.done <- err
	}()
	return drain
}

func (drain *l7ConfiguredProviderOutputDrain) waitUntil(deadline time.Time) (error, bool) {
	if drain.complete {
		return drain.err, true
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, false
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case drain.err = <-drain.done:
		drain.complete = true
		return drain.err, true
	case <-timer.C:
		return nil, false
	}
}

func (drain *l7ConfiguredProviderOutputDrain) close() {
	if drain == nil {
		return
	}
	drain.closeOnce.Do(func() {
		_ = drain.reader.Close()
	})
}

func runL7ConfiguredProviderQuery(
	parent context.Context,
	timeout time.Duration,
	outputLimit int,
	executable string,
	arguments ...string,
) ([]byte, error) {
	if parent == nil || timeout <= 0 || outputLimit <= 0 || strings.TrimSpace(executable) == "" {
		return nil, errL7ConfiguredProviderQuery
	}
	if parent.Err() != nil {
		return nil, errL7ConfiguredProviderQuery
	}
	queryContext, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if queryContext.Err() != nil {
		return nil, errL7ConfiguredProviderQuery
	}
	output := newL7BoundedOutput(outputLimit)
	stderr, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return nil, errL7ConfiguredProviderQuery
	}
	defer func() {
		_ = stderr.Close()
	}()
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		return nil, errL7ConfiguredProviderQuery
	}

	command := exec.Command(executable, arguments...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Stdout = stdoutWriter
	command.Stderr = stderr
	if queryContext.Err() != nil {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		return nil, errL7ConfiguredProviderQuery
	}
	if err := startL7ConfiguredProviderCommand(command); err != nil {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		return nil, errL7ConfiguredProviderQuery
	}
	failed := stdoutWriter.Close() != nil
	drain := newL7ConfiguredProviderOutputDrain(stdoutReader, output)
	defer drain.close()
	processGroupID := command.Process.Pid
	leaderTerminal, operationFailed := waitL7ConfiguredProviderLeader(queryContext, output.overflowed, processGroupID)
	failed = failed || operationFailed

	cleanupDeadline := time.Now().Add(l7ConfiguredProviderCleanup)
	groupSignaled := false
	if !leaderTerminal {
		groupSignaled = true
		if signalErr := signalL7ConfiguredProviderProcessGroup(processGroupID, syscall.SIGKILL); signalErr != nil {
			failed = true
		}
		leaderTerminal = waitL7ConfiguredProviderLeaderTerminal(processGroupID, cleanupDeadline)
		if !leaderTerminal {
			failed = true
		}
	}

	groupAbsent := false
	for leaderTerminal && time.Now().Before(cleanupDeadline) {
		hasOtherMembers, membersErr := l7ConfiguredProviderProcessGroupHasOtherMembers(processGroupID, processGroupID)
		if membersErr != nil {
			failed = true
			break
		}
		if !hasOtherMembers {
			groupAbsent = true
			break
		}
		failed = true
		if !groupSignaled {
			groupSignaled = true
			if signalErr := signalL7ConfiguredProviderProcessGroup(processGroupID, syscall.SIGKILL); signalErr != nil {
				failed = true
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !groupAbsent {
		failed = true
	}

	drainErr, drainComplete := drain.waitUntil(time.Now().Add(l7ConfiguredProviderCleanup))
	if !drainComplete {
		failed = true
		drain.close()
		drainErr, drainComplete = drain.waitUntil(time.Now().Add(l7ConfiguredProviderCleanup))
	}
	if !drainComplete {
		return nil, errL7ConfiguredProviderQuery
	}
	if drainErr != nil && !errors.Is(drainErr, os.ErrClosed) {
		failed = true
	}

	if !leaderTerminal {
		return nil, errL7ConfiguredProviderQuery
	}
	waitErr := reapL7ConfiguredProviderCommand(command)
	data, overflow := output.snapshot()
	if waitErr != nil || queryContext.Err() != nil || overflow {
		failed = true
	}
	if failed {
		return data, errL7ConfiguredProviderQuery
	}
	return data, nil
}

func waitL7ConfiguredProviderLeader(parent context.Context, overflowed <-chan struct{}, leaderPID int) (bool, bool) {
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for {
		terminal, err := observeL7ConfiguredProviderLeaderTerminal(leaderPID)
		if err != nil {
			return false, true
		}
		if terminal {
			return true, false
		}
		select {
		case <-parent.Done():
			return false, true
		case <-overflowed:
			return false, true
		case <-ticker.C:
		}
	}
}

func waitL7ConfiguredProviderLeaderTerminal(leaderPID int, deadline time.Time) bool {
	for time.Now().Before(deadline) {
		terminal, err := observeL7ConfiguredProviderLeaderTerminal(leaderPID)
		if err != nil {
			return false
		}
		if terminal {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return false
}

func observeL7ConfiguredProviderLeaderTerminal(leaderPID int) (bool, error) {
	var info unix.Siginfo
	if err := unix.Waitid(
		unix.P_PID,
		leaderPID,
		&info,
		unix.WEXITED|unix.WNOHANG|unix.WNOWAIT,
		nil,
	); err != nil {
		return false, err
	}
	return info.Signo != 0, nil
}

func scanL7ConfiguredProviderProcessGroup(processGroupID, leaderPID int) (bool, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid <= 0 || pid == leaderPID {
			continue
		}
		stat, readErr := os.ReadFile("/proc/" + entry.Name() + "/stat")
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) {
				continue
			}
			return false, readErr
		}
		closeIndex := strings.LastIndex(string(stat), ") ")
		if closeIndex < 0 {
			return false, errL7ConfiguredProviderQuery
		}
		fields := strings.Fields(string(stat[closeIndex+2:]))
		if len(fields) < 3 {
			return false, errL7ConfiguredProviderQuery
		}
		group, groupErr := strconv.Atoi(fields[2])
		if groupErr != nil {
			return false, errL7ConfiguredProviderQuery
		}
		if group == processGroupID {
			return true, nil
		}
	}
	return false, nil
}

func parseL7GetSubIDs(output []byte, username string) (uint64, error) {
	const maximumLinuxID = uint64(1<<32 - 2)
	if username == "" {
		return 0, fmt.Errorf("invalid configured provider identity")
	}
	text := strings.TrimSuffix(string(output), "\n")
	if text == "" {
		return 0, fmt.Errorf("empty configured provider output")
	}
	lines := strings.Split(text, "\n")
	var first uint64
	for index, line := range lines {
		fields := strings.Fields(strings.TrimSuffix(line, "\r"))
		if len(fields) != 4 || fields[0] != strconv.Itoa(index)+":" || fields[1] != username {
			return 0, fmt.Errorf("malformed configured provider record")
		}
		start, startErr := strconv.ParseUint(fields[2], 10, 64)
		count, countErr := strconv.ParseUint(fields[3], 10, 64)
		if startErr != nil || countErr != nil || start == 0 || start > maximumLinuxID || count == 0 || count-1 > maximumLinuxID-start {
			return 0, fmt.Errorf("invalid configured provider range")
		}
		if index == 0 {
			first = start
		}
	}
	return first, nil
}

func l7SubordinateIDMap(outer uint64) string {
	return l7IDMap(1000, outer, 1)
}

func l7IDMap(inner, outer, count uint64) string {
	return fmt.Sprintf("%d:%d:%d", inner, outer, count)
}
