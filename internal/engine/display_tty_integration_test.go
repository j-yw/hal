//go:build integration
// +build integration

package engine

import (
	"bytes"
	"errors"
	"io"
	"os"
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

const ptyShutdownTimeout = 2 * time.Second

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

func isExpectedPTYReadError(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, os.ErrClosed) ||
		errors.Is(err, syscall.EIO)
}

func TestDisplayTTYHarness_CapturesLifecycleOutput(t *testing.T) {
	h := newDisplayTTYHarness(t)

	if !h.display.isTTY {
		t.Fatal("expected Display to run in TTY mode when backed by PTY slave")
	}

	h.display.ShowEvent(&Event{Type: EventInit, Data: EventData{Model: "integration-model"}})
	h.display.ShowEvent(&Event{Type: EventTool, Tool: "Read", Detail: "README.md"})
	h.display.StopSpinner()
	h.Close()

	output := h.Output()
	if output == "" {
		t.Fatal("expected captured PTY output, got empty string")
	}
	if !strings.Contains(output, "model: integration-model") {
		t.Fatalf("captured output missing model line: %q", output)
	}
	if !strings.Contains(output, "Read README.md") {
		t.Fatalf("captured output missing tool history line: %q", output)
	}
}
