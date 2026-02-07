//go:build integration
// +build integration

package engine

import (
	"bytes"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

// Display TTY integration tests are intentionally separated from default unit runs.
//
// Scope:
//   - PTY-backed lifecycle coverage for Display spinner rendering and terminal teardown.
//   - Assertions that rely on real TTY redraw behavior (\r and ANSI control sequences).
//
// Determinism constraints:
//   - Use bounded waits (no unbounded sleeps/loops).
//   - Normalize terminal output before asserting.
//   - Keep cleanup strict so spinner goroutines and PTY handles never leak.
const (
	ptyShutdownTimeout = 2 * time.Second
	ptyWaitTimeout     = 2 * time.Second
	ptyPollInterval    = 20 * time.Millisecond
)

var ansiControlSequenceRegex = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

type displayTTYHarness struct {
	t       *testing.T
	display *Display
	master  *os.File
	slave   *os.File

	mu      sync.Mutex
	output  bytes.Buffer
	readErr error

	readDone  chan struct{}
	closeOnce sync.Once
}

func newDisplayTTYHarness(t *testing.T) *displayTTYHarness {
	t.Helper()

	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("PTY not supported in this environment: %v", err)
	}

	h := &displayTTYHarness{
		t:        t,
		display:  NewDisplay(slave),
		master:   master,
		slave:    slave,
		readDone: make(chan struct{}),
	}

	go h.captureOutput()

	t.Cleanup(func() {
		h.Close()
	})

	return h
}

func (h *displayTTYHarness) captureOutput() {
	defer close(h.readDone)

	buf := make([]byte, 4096)
	for {
		n, err := h.master.Read(buf)
		if n > 0 {
			h.mu.Lock()
			_, _ = h.output.Write(buf[:n])
			h.mu.Unlock()
		}

		if err != nil {
			if isExpectedPTYReadError(err) {
				return
			}
			h.mu.Lock()
			h.readErr = err
			h.mu.Unlock()
			return
		}
	}
}

func (h *displayTTYHarness) Close() {
	h.closeOnce.Do(func() {
		h.display.StopSpinner()
		_ = h.slave.Close()
		_ = h.master.Close()

		select {
		case <-h.readDone:
		case <-time.After(ptyShutdownTimeout):
			h.t.Errorf("timed out waiting for PTY capture goroutine shutdown")
		}

		if err := h.ReadErr(); err != nil {
			h.t.Errorf("PTY capture failed: %v", err)
		}
	})
}

func (h *displayTTYHarness) Output() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.output.String()
}

func (h *displayTTYHarness) ReadErr() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.readErr
}

func (h *displayTTYHarness) WaitForOutputContains(marker string, timeout, interval time.Duration) string {
	h.t.Helper()

	if timeout <= 0 {
		h.t.Fatalf("timeout must be > 0, got %s", timeout)
	}
	if interval <= 0 {
		h.t.Fatalf("interval must be > 0, got %s", interval)
	}

	deadline := time.Now().Add(timeout)
	for {
		raw := h.Output()
		normalized := normalizeTTYOutput(raw)
		if strings.Contains(normalized, marker) {
			return normalized
		}

		if err := h.ReadErr(); err != nil {
			h.t.Fatalf(
				"PTY capture failed while waiting for marker %q: %v\nlatest normalized output:\n%s\nlatest raw output (escaped): %q",
				marker,
				err,
				normalized,
				raw,
			)
		}

		if time.Now().After(deadline) {
			h.t.Fatalf(
				"timed out after %s waiting for marker %q (poll interval %s)\nlatest normalized output:\n%s\nlatest raw output (escaped): %q",
				timeout,
				marker,
				interval,
				normalized,
				raw,
			)
		}

		time.Sleep(interval)
	}
}

func isExpectedPTYReadError(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, os.ErrClosed) ||
		errors.Is(err, syscall.EIO)
}

func normalizeTTYOutput(output string) string {
	if output == "" {
		return ""
	}

	normalized := ansiControlSequenceRegex.ReplaceAllString(output, "")
	normalized = strings.ReplaceAll(normalized, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	return normalized
}

func TestNormalizeTTYOutput_StripsANSIAndCarriageReturns(t *testing.T) {
	raw := "\x1b[2K\r   \x1b[31m[●]\x1b[0m processing...\r\x1b[2K   > Read README.md\n"
	normalized := normalizeTTYOutput(raw)

	if strings.Contains(normalized, "\x1b[") {
		t.Fatalf("expected ANSI control sequences to be removed, got %q", normalized)
	}
	if strings.Contains(normalized, "\r") {
		t.Fatalf("expected carriage returns to be normalized, got %q", normalized)
	}
	if !strings.Contains(normalized, "Read README.md") {
		t.Fatalf("normalized output missing expected marker: %q", normalized)
	}
}

func TestDisplayTTYHarness_CapturesLifecycleOutput(t *testing.T) {
	h := newDisplayTTYHarness(t)

	if !h.display.isTTY {
		t.Fatal("expected Display to run in TTY mode when backed by PTY slave")
	}

	h.display.ShowEvent(&Event{Type: EventInit, Data: EventData{Model: "integration-model"}})
	h.display.ShowEvent(&Event{Type: EventTool, Tool: "Read", Detail: "README.md"})

	normalized := h.WaitForOutputContains("Read README.md", ptyWaitTimeout, ptyPollInterval)

	if !strings.Contains(normalized, "model: integration-model") {
		t.Fatalf("captured output missing model line: %q", normalized)
	}
	if !strings.Contains(normalized, "Read README.md") {
		t.Fatalf("captured output missing tool history line: %q", normalized)
	}

	h.display.StopSpinner()
	h.Close()
}
