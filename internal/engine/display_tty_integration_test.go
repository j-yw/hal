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

type lifecyclePhase string

const (
	phaseThinking lifecyclePhase = "thinking"
	phaseTool     lifecyclePhase = "tool"
	phaseTerminal lifecyclePhase = "terminal"
)

type phaseOutputSnapshot struct {
	Raw        string
	Normalized string
}

type lifecycleCheckpoints struct {
	ThinkingMarker string
	ToolMarker     string
	TerminalMarker string
	Timeout        time.Duration
	Interval       time.Duration
}

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

type displayLifecycleDriver struct {
	h         *displayTTYHarness
	snapshots map[lifecyclePhase]phaseOutputSnapshot
}

func newDisplayLifecycleDriver(h *displayTTYHarness) *displayLifecycleDriver {
	return &displayLifecycleDriver{
		h:         h,
		snapshots: make(map[lifecyclePhase]phaseOutputSnapshot),
	}
}

func (d *displayLifecycleDriver) DriveSuccessLifecycle(checkpoints lifecycleCheckpoints) map[lifecyclePhase]phaseOutputSnapshot {
	cfg := checkpoints.withDefaults()

	emitCanonicalThinkingEvents(d.h.display, "integration-model")
	d.capturePhase(phaseThinking, cfg.ThinkingMarker, cfg)

	emitCanonicalToolEvent(d.h.display, "Read", "README.md")
	d.capturePhase(phaseTool, cfg.ToolMarker, cfg)

	emitCanonicalResultEvent(d.h.display, true, 1500, 5000)
	d.capturePhase(phaseTerminal, cfg.TerminalMarker, cfg)

	return d.Snapshots()
}

func (d *displayLifecycleDriver) DriveErrorLifecycle(message string, checkpoints lifecycleCheckpoints) map[lifecyclePhase]phaseOutputSnapshot {
	cfg := checkpoints.withDefaults()

	emitCanonicalThinkingEvents(d.h.display, "integration-model")
	d.capturePhase(phaseThinking, cfg.ThinkingMarker, cfg)

	emitCanonicalToolEvent(d.h.display, "Read", "README.md")
	d.capturePhase(phaseTool, cfg.ToolMarker, cfg)

	emitCanonicalErrorEvent(d.h.display, message)
	d.capturePhase(phaseTerminal, cfg.TerminalMarker, cfg)

	return d.Snapshots()
}

func (d *displayLifecycleDriver) Snapshots() map[lifecyclePhase]phaseOutputSnapshot {
	copied := make(map[lifecyclePhase]phaseOutputSnapshot, len(d.snapshots))
	for phase, snapshot := range d.snapshots {
		copied[phase] = snapshot
	}
	return copied
}

func (d *displayLifecycleDriver) capturePhase(phase lifecyclePhase, marker string, checkpoints lifecycleCheckpoints) {
	if marker != "" {
		d.h.WaitForOutputContains(marker, checkpoints.Timeout, checkpoints.Interval)
	}

	raw := d.h.Output()
	d.snapshots[phase] = phaseOutputSnapshot{
		Raw:        raw,
		Normalized: normalizeTTYOutput(raw),
	}
}

func (c lifecycleCheckpoints) withDefaults() lifecycleCheckpoints {
	if c.Timeout <= 0 {
		c.Timeout = ptyWaitTimeout
	}
	if c.Interval <= 0 {
		c.Interval = ptyPollInterval
	}
	return c
}

func emitCanonicalThinkingEvents(display *Display, model string) {
	display.ShowEvent(&Event{Type: EventInit, Data: EventData{Model: model}})
	display.ShowEvent(&Event{Type: EventThinking, Data: EventData{Message: "start"}})
	display.ShowEvent(&Event{Type: EventThinking, Data: EventData{Message: "delta"}})
}

func emitCanonicalToolEvent(display *Display, tool, detail string) {
	display.ShowEvent(&Event{Type: EventTool, Tool: tool, Detail: detail})
}

func emitCanonicalResultEvent(display *Display, success bool, tokens int, durationMS float64) {
	display.ShowEvent(&Event{
		Type: EventResult,
		Data: EventData{
			Success:    success,
			Tokens:     tokens,
			DurationMs: durationMS,
		},
	})
}

func emitCanonicalErrorEvent(display *Display, message string) {
	display.ShowEvent(&Event{Type: EventError, Data: EventData{Message: message}})
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

func TestDisplayLifecycleDriver_DriveSuccessLifecycle(t *testing.T) {
	h := newDisplayTTYHarness(t)
	driver := newDisplayLifecycleDriver(h)

	snapshots := driver.DriveSuccessLifecycle(lifecycleCheckpoints{
		ThinkingMarker: "model: integration-model",
		ToolMarker:     "Read README.md",
		TerminalMarker: "[OK]",
		Timeout:        ptyWaitTimeout,
		Interval:       ptyPollInterval,
	})

	assertPhaseSnapshotContains(t, snapshots, phaseThinking, "model: integration-model")
	assertPhaseSnapshotContains(t, snapshots, phaseTool, "Read README.md")
	assertPhaseSnapshotContains(t, snapshots, phaseTerminal, "[OK]")
}

func TestDisplayLifecycleDriver_DriveErrorLifecycle(t *testing.T) {
	h := newDisplayTTYHarness(t)
	driver := newDisplayLifecycleDriver(h)

	snapshots := driver.DriveErrorLifecycle("integration failure", lifecycleCheckpoints{
		ThinkingMarker: "model: integration-model",
		ToolMarker:     "Read README.md",
		TerminalMarker: "integration failure",
		Timeout:        ptyWaitTimeout,
		Interval:       ptyPollInterval,
	})

	assertPhaseSnapshotContains(t, snapshots, phaseThinking, "model: integration-model")
	assertPhaseSnapshotContains(t, snapshots, phaseTool, "Read README.md")
	assertPhaseSnapshotContains(t, snapshots, phaseTerminal, "integration failure")
}

func TestDisplayTTYLifecycle_SuccessPath_ShowsSpinnerAndCompletion(t *testing.T) {
	h := newDisplayTTYHarness(t)
	driver := newDisplayLifecycleDriver(h)

	snapshots := driver.DriveSuccessLifecycle(lifecycleCheckpoints{
		ThinkingMarker: "[●]",
		ToolMarker:     "[●] Read README.md",
		TerminalMarker: "[OK]",
		Timeout:        ptyWaitTimeout,
		Interval:       ptyPollInterval,
	})

	assertPhaseSnapshotContains(t, snapshots, phaseThinking, "model: integration-model")
	assertPhaseSnapshotContains(t, snapshots, phaseThinking, "[●]")
	assertPhaseSnapshotContains(t, snapshots, phaseTool, "[●] Read README.md")
	assertPhaseSnapshotContains(t, snapshots, phaseTerminal, "[OK]")
}

func assertPhaseSnapshotContains(t *testing.T, snapshots map[lifecyclePhase]phaseOutputSnapshot, phase lifecyclePhase, marker string) {
	t.Helper()

	snapshot, ok := snapshots[phase]
	if !ok {
		t.Fatalf("missing snapshot for phase %q", phase)
	}
	if snapshot.Raw == "" {
		t.Fatalf("snapshot for phase %q has empty raw output", phase)
	}
	if !strings.Contains(snapshot.Normalized, marker) {
		t.Fatalf("snapshot for phase %q missing marker %q in normalized output: %q", phase, marker, snapshot.Normalized)
	}
}
