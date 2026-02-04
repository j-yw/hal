package claude

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/jywlabs/hal/internal/engine"
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
	// Claude Code CLI displays interactive hints like "ctrl+b to run in background"
	// when it detects a TTY. These are written directly to /dev/tty.
	//
	// To suppress these hints, we:
	// 1. Set Stdin to nil (no input)
	// 2. Create a new session (Setsid) to detach from controlling terminal
	//
	// This ensures clean, parseable output without interactive UI elements.
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

// Prompt executes a single prompt and returns the text response.
// This is a simpler interface for PRD generation, validation, etc.
func (e *Engine) Prompt(ctx context.Context, prompt string) (string, error) {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = engine.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build command - similar to Execute but simpler output handling
	args := []string{
		"-p",
		"--dangerously-skip-permissions",
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
// It uses stream-json output to show progress via the display while
// collecting the text response for return.
func (e *Engine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = engine.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Use same flags as Execute for streaming
	args := e.BuildArgs(prompt)
	cmd := exec.CommandContext(ctx, e.CLICommand(), args...)
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	var stdout, stderr bytes.Buffer
	parser := NewParser()
	collector := &textCollectingStreamHandler{
		parser:  parser,
		display: display,
	}

	cmd.Stdout = io.MultiWriter(collector, &stdout)
	cmd.Stderr = &stderr

	err := cmd.Run()
	collector.Flush()

	if display != nil {
		display.StopSpinner()
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("prompt timed out after %s", timeout)
		}
		return "", fmt.Errorf("prompt failed: %w (stderr: %s)", err, stderr.String())
	}

	return collector.Text(), nil
}

// textCollectingStreamHandler streams events to the display while
// collecting text content from assistant messages.
type textCollectingStreamHandler struct {
	parser  *Parser
	display *engine.Display
	buffer  []byte
	text    strings.Builder
}

func (h *textCollectingStreamHandler) Write(p []byte) (n int, err error) {
	h.buffer = append(h.buffer, p...)

	for {
		idx := bytes.IndexByte(h.buffer, '\n')
		if idx == -1 {
			break
		}

		line := h.buffer[:idx]
		h.buffer = h.buffer[idx+1:]

		h.processLine(line)
	}

	return len(p), nil
}

func (h *textCollectingStreamHandler) processLine(line []byte) {
	// Show event on display
	event := h.parser.ParseLine(line)
	if h.display != nil {
		h.display.ShowEvent(event)
	}

	// Also extract text content from assistant messages
	h.collectText(line)
}

func (h *textCollectingStreamHandler) collectText(line []byte) {
	trimmed := trimSpace(line)
	if len(trimmed) == 0 {
		return
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return
	}

	eventType, _ := raw["type"].(string)
	if eventType != "assistant" {
		return
	}

	msg, ok := raw["message"].(map[string]interface{})
	if !ok {
		return
	}

	content, ok := msg["content"].([]interface{})
	if !ok {
		return
	}

	for _, item := range content {
		block, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if blockType, _ := block["type"].(string); blockType == "text" {
			if text, _ := block["text"].(string); text != "" {
				h.text.WriteString(text)
			}
		}
	}
}

func (h *textCollectingStreamHandler) Flush() {
	if len(h.buffer) > 0 {
		h.processLine(h.buffer)
		h.buffer = nil
	}
}

func (h *textCollectingStreamHandler) Text() string {
	return h.text.String()
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
