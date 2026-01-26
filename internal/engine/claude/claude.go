package claude

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/jywlabs/goralph/internal/engine"
)

func init() {
	engine.RegisterEngine("claude", func() engine.Engine {
		return New()
	})
}

// Engine executes prompts using Claude Code CLI.
type Engine struct {
	Timeout time.Duration
}

// New creates a new Claude engine.
func New() *Engine {
	return &Engine{
		Timeout: engine.DefaultTimeout,
	}
}

// Name returns the engine identifier.
func (e *Engine) Name() string {
	return "claude"
}

// CLICommand returns the CLI executable name.
func (e *Engine) CLICommand() string {
	return "claude"
}

// BuildArgs returns the CLI arguments for execution.
func (e *Engine) BuildArgs(prompt string) []string {
	return []string{
		"-p",
		"--dangerously-skip-permissions",
		"--verbose",
		"--output-format", "stream-json",
		prompt,
	}
}

// Execute runs the prompt using Claude Code CLI.
func (e *Engine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = engine.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	startTime := time.Now()

	// Build command
	args := e.BuildArgs(prompt)
	cmd := exec.CommandContext(ctx, e.CLICommand(), args...)

	// Detach from TTY to suppress interactive UI hints.
	//
	// When Claude Code CLI detects a TTY (terminal), it displays interactive
	// hints like "ctrl+b to run in background". These hints are written directly
	// to /dev/tty, bypassing stdout/stderr redirection.
	//
	// By setting Stdin to nil, the child process has no controlling terminal,
	// causing Claude to skip TTY detection and suppress these hints.
	//
	// This ensures clean, parseable output without interactive UI elements
	// that would confuse users (since goralph doesn't support backgrounding).
	cmd.Stdin = nil

	// Set up output capture with streaming parser
	var stdout, stderr bytes.Buffer
	parser := NewParser()
	streamWriter := &streamHandler{
		parser:  parser,
		display: display,
		buffer:  nil,
	}

	cmd.Stdout = io.MultiWriter(streamWriter, &stdout)
	cmd.Stderr = &stderr

	// Run command
	err := cmd.Run()
	streamWriter.Flush()

	output := stdout.String()
	duration := time.Since(startTime)

	// Handle errors
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return engine.Result{
				Success:  false,
				Output:   output,
				Duration: duration,
				Error:    fmt.Errorf("execution timed out after %s", timeout),
			}
		}
		return engine.Result{
			Success:  false,
			Output:   output,
			Duration: duration,
			Error:    fmt.Errorf("execution failed: %w (stderr: %s)", err, stderr.String()),
		}
	}

	// Parse success from output
	success := e.parseSuccess(output)
	complete := strings.Contains(output, "<promise>COMPLETE</promise>")

	return engine.Result{
		Success:  success,
		Complete: complete,
		Output:   output,
		Duration: duration,
		Error:    nil,
	}
}

// parseSuccess checks if the Claude JSON response indicates success.
func (e *Engine) parseSuccess(output string) bool {
	lines := strings.Split(output, "\n")
	parser := NewParser()

	for _, line := range lines {
		event := parser.ParseLine([]byte(line))
		if event != nil && event.Type == engine.EventResult {
			return event.Data.Success
		}
	}

	// If we can't parse, assume success if no error
	return true
}

// streamHandler processes output line by line.
type streamHandler struct {
	parser  *Parser
	display *engine.Display
	buffer  []byte
}

func (h *streamHandler) Write(p []byte) (n int, err error) {
	h.buffer = append(h.buffer, p...)

	// Process complete lines
	for {
		idx := bytes.IndexByte(h.buffer, '\n')
		if idx == -1 {
			break
		}

		line := h.buffer[:idx]
		h.buffer = h.buffer[idx+1:]

		event := h.parser.ParseLine(line)
		h.display.ShowEvent(event)
	}

	return len(p), nil
}

func (h *streamHandler) Flush() {
	if len(h.buffer) > 0 {
		event := h.parser.ParseLine(h.buffer)
		h.display.ShowEvent(event)
		h.buffer = nil
	}
}
