package codex

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/engine"
)

func init() {
	engine.RegisterEngine("codex", func(cfg *engine.EngineConfig) engine.Engine {
		return New(cfg)
	})
}

// Engine executes prompts using OpenAI Codex CLI.
type Engine struct {
	Timeout time.Duration
	model   string
}

const (
	// Keep a minimum idle threshold for short sessions, but otherwise allow
	// long reasoning to use nearly the full configured session timeout.
	codexMinStreamInactivityTimeout = 10 * time.Minute
	codexStreamInactivityGrace      = 5 * time.Minute
)

var errStreamStalled = errors.New("codex stream stalled")

// New creates a new Codex engine.
func New(cfg *engine.EngineConfig) *Engine {
	e := &Engine{
		Timeout: engine.DefaultTimeout,
	}
	if cfg != nil {
		if cfg.Model != "" {
			e.model = cfg.Model
		}
		if cfg.Timeout > 0 {
			e.Timeout = cfg.Timeout
		}
	}
	return e
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
// Prompt is passed via stdin using "-" placeholder.
func (e *Engine) BuildArgs() []string {
	args := []string{
		"exec",
		"--dangerously-bypass-approvals-and-sandbox",
		"--json",
	}
	if e.model != "" {
		args = append(args, "--model", e.model)
	}
	args = append(args, "-") // Read prompt from stdin
	return args
}

// BuildArgsNoJSON returns CLI arguments without JSON flag.
func (e *Engine) BuildArgsNoJSON() []string {
	args := []string{
		"exec",
		"--dangerously-bypass-approvals-and-sandbox",
	}
	if e.model != "" {
		args = append(args, "--model", e.model)
	}
	args = append(args, "-") // Read prompt from stdin
	return args
}

func contextRunError(ctx context.Context, timeout time.Duration, operation string) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		if ctxErr == context.DeadlineExceeded {
			return fmt.Errorf("%s timed out after %s", operation, timeout)
		}
		return fmt.Errorf("%s canceled: %w", operation, ctxErr)
	}

	return nil
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
	args := e.BuildArgs()
	cmd := exec.CommandContext(ctx, e.CLICommand(), args...)

	// Pass prompt via stdin
	cmd.Stdin = strings.NewReader(prompt)
	cmd.SysProcAttr = newSysProcAttr()
	setupProcessCleanup(cmd)

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
		if result, recovered := e.recoverExecuteResult(ctx, timeout, output, duration); recovered {
			return result
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
	hasResult, success := e.parseResultStatus(output)
	if hasResult {
		return success
	}

	parser := NewParser()
	for _, line := range strings.Split(output, "\n") {
		parser.ParseLine([]byte(line))
	}

	if parser.HasFailure() {
		return false
	}

	// If we can't parse, assume success if no error
	return true
}

func (e *Engine) parseResultStatus(output string) (hasResult bool, success bool) {
	parser := NewParser()

	for _, line := range strings.Split(output, "\n") {
		parser.ParseLine([]byte(line))
	}

	return parser.ResultStatus()
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

	// Build command - use stdin for prompt
	args := e.BuildArgsNoJSON()
	cmd := exec.CommandContext(ctx, e.CLICommand(), args...)
	cmd.Stdin = strings.NewReader(prompt)
	cmd.SysProcAttr = newSysProcAttr()
	setupProcessCleanup(cmd)

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
// It uses --json flag for JSONL output to show progress via the display
// while collecting text content from assistant messages for return.
func (e *Engine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = engine.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Use BuildArgs which includes --json flag for streaming, prompt via stdin.
	args := e.BuildArgs()
	cmd := exec.CommandContext(ctx, e.CLICommand(), args...)
	cmd.Stdin = strings.NewReader(prompt)
	cmd.SysProcAttr = newSysProcAttr()
	setupProcessCleanup(cmd)

	var stderr bytes.Buffer
	parser := NewParser()
	collector := &textCollectingStreamHandler{
		parser:       parser,
		display:      display,
		lastActivity: time.Now(),
	}
	idleTimeout := codexStreamInactivityTimeout(timeout)

	// Stream directly into the collector/display to avoid buffering the entire
	// JSONL stream in memory during long review sessions.
	cmd.Stdout = collector
	cmd.Stderr = &stderr

	err := runCommandWithInactivityWatch(cmd, collector, idleTimeout)
	collector.Flush()

	if display != nil {
		display.StopSpinner()
	}

	if err != nil {
		if text, recoverErr, recovered := recoverPromptError(
			ctx,
			timeout,
			idleTimeout,
			err,
			collector.ResultStatus,
			collector.Text(),
			stderr.String(),
		); recovered {
			return text, recoverErr
		}
		return "", fmt.Errorf("prompt failed: %w (stderr: %s)", err, stderr.String())
	}

	return collector.Text(), nil
}

func codexStreamInactivityTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		timeout = engine.DefaultTimeout
	}

	idleTimeout := timeout - codexStreamInactivityGrace
	if idleTimeout < codexMinStreamInactivityTimeout {
		idleTimeout = codexMinStreamInactivityTimeout
	}
	if idleTimeout > timeout {
		idleTimeout = timeout
	}

	return idleTimeout
}

func (e *Engine) recoverExecuteResult(
	ctx context.Context,
	timeout time.Duration,
	output string,
	duration time.Duration,
) (engine.Result, bool) {
	if ctxErr := ctx.Err(); ctxErr == context.Canceled {
		return engine.Result{
			Success:  false,
			Output:   output,
			Duration: duration,
			Error:    fmt.Errorf("execution canceled: %w", ctxErr),
		}, true
	}

	if hasResult, success := e.parseResultStatus(output); hasResult && success {
		complete := strings.Contains(output, "<promise>COMPLETE</promise>")
		return engine.Result{
			Success:  true,
			Complete: complete,
			Output:   output,
			Duration: duration,
			Error:    nil,
		}, true
	}

	if runErr := contextRunError(ctx, timeout, "execution"); runErr != nil {
		return engine.Result{
			Success:  false,
			Output:   output,
			Duration: duration,
			Error:    runErr,
		}, true
	}

	return engine.Result{}, false
}

func recoverPromptError(
	ctx context.Context,
	timeout time.Duration,
	idleTimeout time.Duration,
	err error,
	resultStatus func() (hasResult bool, success bool),
	text string,
	stderr string,
) (string, error, bool) {
	if ctxErr := ctx.Err(); ctxErr == context.Canceled {
		return "", fmt.Errorf("prompt canceled: %w", ctxErr), true
	}

	if hasResult, success := resultStatus(); hasResult && success {
		if strings.TrimSpace(text) != "" {
			return text, nil, true
		}
		return "", engine.NewOutputFallbackRequiredError(
			fmt.Errorf("prompt failed: %w (stderr: %s)", err, stderr),
		), true
	}

	if errors.Is(err, errStreamStalled) {
		return "", fmt.Errorf("prompt stalled: no output for %s", idleTimeout), true
	}

	if runErr := contextRunError(ctx, timeout, "prompt"); runErr != nil {
		return "", runErr, true
	}

	return "", nil, false
}

func runCommandWithInactivityWatch(cmd *exec.Cmd, collector *textCollectingStreamHandler, idleTimeout time.Duration) error {
	if err := cmd.Start(); err != nil {
		return err
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	if idleTimeout <= 0 {
		return <-waitCh
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case err := <-waitCh:
			return err
		case <-ticker.C:
			if collector == nil {
				continue
			}
			if collector.idleFor(time.Now()) < idleTimeout {
				continue
			}

			// Prefer command completion over synthetic stall errors when both are ready.
			select {
			case err := <-waitCh:
				return err
			default:
			}

			terminateCommand(cmd)
			<-waitCh
			return fmt.Errorf("%w: no output for %s", errStreamStalled, idleTimeout)
		}
	}
}

func terminateCommand(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.Cancel != nil {
		_ = cmd.Cancel()
		return
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

// textCollectingStreamHandler streams events to the display while
// collecting text content from Codex agent_message events.
type textCollectingStreamHandler struct {
	parser            *Parser
	display           *engine.Display
	buffer            []byte
	text              strings.Builder
	hasMachinePayload bool
	activityMu        sync.Mutex
	lastActivity      time.Time
}

func (h *textCollectingStreamHandler) Write(p []byte) (n int, err error) {
	if len(p) > 0 {
		h.touchActivity()
	}

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

	// Also extract text content from agent messages
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
	var text string

	switch eventType {
	case "item.completed":
		text = extractItemCompletedAgentMessage(raw)
	case "response_item":
		text = extractResponseItemAssistantText(raw)
	case "event_msg":
		text = extractEventMessageText(raw)
	default:
		return
	}

	text = strings.TrimSpace(text)
	if text == "" {
		return
	}

	if isMachineReadableJSON(text) {
		h.hasMachinePayload = true
		h.text.Reset()
		h.text.WriteString(text)
		return
	}

	if h.hasMachinePayload {
		return
	}

	if h.text.Len() > 0 {
		h.text.WriteByte('\n')
	}
	h.text.WriteString(text)
}

func isMachineReadableJSON(text string) bool {
	if text == "" {
		return false
	}
	if !strings.HasPrefix(text, "{") && !strings.HasPrefix(text, "[") {
		return false
	}
	return json.Valid([]byte(text))
}

func extractItemCompletedAgentMessage(raw map[string]interface{}) string {
	item, ok := raw["item"].(map[string]interface{})
	if !ok {
		return ""
	}

	itemType, _ := item["type"].(string)
	if itemType != "agent_message" {
		return ""
	}

	text, _ := item["text"].(string)
	return text
}

func extractResponseItemAssistantText(raw map[string]interface{}) string {
	payload, ok := raw["payload"].(map[string]interface{})
	if !ok {
		return ""
	}

	payloadType, _ := payload["type"].(string)
	if payloadType != "message" {
		return ""
	}

	role, _ := payload["role"].(string)
	if role != "assistant" {
		return ""
	}

	phase, _ := payload["phase"].(string)
	if phase == "commentary" {
		return ""
	}

	content, ok := payload["content"].([]interface{})
	if !ok {
		return ""
	}

	parts := make([]string, 0, len(content))
	for _, entry := range content {
		part, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		partType, _ := part["type"].(string)
		if partType != "output_text" {
			continue
		}
		if text, ok := part["text"].(string); ok {
			parts = append(parts, text)
		}
	}

	return strings.Join(parts, "")
}

func extractEventMessageText(raw map[string]interface{}) string {
	payload, ok := raw["payload"].(map[string]interface{})
	if !ok {
		return ""
	}

	payloadType, _ := payload["type"].(string)
	if payloadType != "agent_message" {
		return ""
	}

	message, _ := payload["message"].(string)
	message = strings.TrimSpace(message)
	if message == "" {
		return ""
	}

	// Ignore commentary updates; keep only likely machine-readable payloads.
	if strings.HasPrefix(message, "{") || strings.HasPrefix(message, "[") {
		return message
	}

	return ""
}

func (h *textCollectingStreamHandler) touchActivity() {
	h.activityMu.Lock()
	h.lastActivity = time.Now()
	h.activityMu.Unlock()
}

func (h *textCollectingStreamHandler) idleFor(now time.Time) time.Duration {
	h.activityMu.Lock()
	last := h.lastActivity
	h.activityMu.Unlock()

	if last.IsZero() {
		return 0
	}

	return now.Sub(last)
}

func (h *textCollectingStreamHandler) Flush() {
	if len(h.buffer) > 0 {
		h.processLine(h.buffer)
		h.buffer = nil
		h.touchActivity()
	}
}

func (h *textCollectingStreamHandler) Text() string {
	return h.text.String()
}

func (h *textCollectingStreamHandler) ResultStatus() (hasResult bool, success bool) {
	if h == nil || h.parser == nil {
		return false, false
	}

	return h.parser.ResultStatus()
}
