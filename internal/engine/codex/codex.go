package codex

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/jywlabs/goralph/internal/engine"
)

func init() {
	engine.RegisterEngine("codex", func() engine.Engine {
		return New()
	})
}

// Engine executes prompts using OpenAI Codex CLI.
type Engine struct {
	Timeout time.Duration
}

// New creates a new Codex engine.
func New() *Engine {
	return &Engine{
		Timeout: engine.DefaultTimeout,
	}
}

// Name returns the engine identifier.
func (e *Engine) Name() string {
	return "codex"
}

// CLICommand returns the CLI executable name.
func (e *Engine) CLICommand() string {
	return "codex"
}

// BuildArgs returns the CLI arguments for execution.
func (e *Engine) BuildArgs(prompt string) []string {
	return []string{
		"exec",
		"--dangerously-bypass-approvals-and-sandbox",
		"--json",
		prompt,
	}
}

// Execute runs the prompt using Codex CLI.
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
	// Codex CLI may display interactive hints when it detects a TTY.
	// To suppress these hints, we:
	// 1. Set Stdin to nil (no input)
	// 2. Create a new session (Setsid) to detach from controlling terminal
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // Create new session, detach from controlling TTY
	}

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

// parseSuccess checks if the Codex JSON response indicates success.
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
		if h.display != nil {
			h.display.ShowEvent(event)
		}
	}

	return len(p), nil
}

func (h *streamHandler) Flush() {
	if len(h.buffer) > 0 {
		event := h.parser.ParseLine(h.buffer)
		if h.display != nil {
			h.display.ShowEvent(event)
		}
		h.buffer = nil
	}
}

// Prompt executes a single prompt and returns the text response.
// This is a simpler interface for PRD generation, validation, etc.
func (e *Engine) Prompt(ctx context.Context, prompt string) (string, error) {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = engine.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build command - simpler args without --json for plain text output
	args := []string{
		"exec",
		"--dangerously-bypass-approvals-and-sandbox",
		prompt,
	}
	cmd := exec.CommandContext(ctx, e.CLICommand(), args...)
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("prompt timed out after %s", timeout)
		}
		return "", fmt.Errorf("prompt failed: %w (stderr: %s)", err, stderr.String())
	}

	return stdout.String(), nil
}

// StreamPrompt executes a prompt with streaming display feedback.
func (e *Engine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	// TODO: Implement in US-006
	return "", nil
}
