package pi

import (
	"encoding/json"
	"strings"

	"github.com/jywlabs/hal/internal/engine"
)

// Parser parses pi's streaming JSON output format.
//
// Pi emits JSONL with these top-level event types:
//
//	session        — session metadata (first line)
//	agent_start    — agent begins processing
//	turn_start     — new turn begins
//	message_start  — message begins (user or assistant)
//	message_update — streaming content (text deltas, tool calls)
//	message_end    — message complete
//	tool_execution_start/update/end — tool execution lifecycle
//	turn_end       — turn complete with usage
//	agent_end      — agent done, final messages array
//
// Tool calls are nested inside message_update events under
// assistantMessageEvent with types: toolcall_start, toolcall_delta, toolcall_end.
// Text content uses: text_start, text_delta, text_end.
type Parser struct {
	model       string
	totalTokens int
	hasFailure  bool
	text        strings.Builder
}

// NewParser creates a new Pi output parser.
func NewParser() *Parser {
	return &Parser{}
}

// TotalTokens returns accumulated token usage.
func (p *Parser) TotalTokens() int {
	return p.totalTokens
}

// HasFailure returns true if any error was encountered.
func (p *Parser) HasFailure() bool {
	return p.hasFailure
}

// CollectedText returns all assistant text accumulated during parsing.
func (p *Parser) CollectedText() string {
	return p.text.String()
}

// ParseLine parses a single JSON line from pi's streaming output.
func (p *Parser) ParseLine(line []byte) *engine.Event {
	line = trimSpace(line)
	if len(line) == 0 {
		return nil
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil
	}

	eventType, _ := raw["type"].(string)

	switch eventType {
	case "session":
		return p.parseSession(raw)
	case "message_start":
		return p.parseMessageStart(raw)
	case "message_update":
		return p.parseMessageUpdate(raw)
	case "message_end":
		return p.parseMessageEnd(raw)
	case "tool_execution_start":
		return p.parseToolExecutionStart(raw)
	case "tool_execution_end":
		return p.parseToolExecutionEnd(raw)
	case "turn_end":
		return p.parseTurnEnd(raw)
	case "agent_end":
		return p.parseAgentEnd(raw)
	default:
		return nil
	}
}

func (p *Parser) parseSession(raw map[string]interface{}) *engine.Event {
	// Session event doesn't include model; we'll pick it up from message_start.
	// Model left empty — the real model name arrives in the first assistant message_start.
	return &engine.Event{
		Type: engine.EventInit,
		Data: engine.EventData{
			Model: "",
		},
	}
}

func (p *Parser) parseMessageStart(raw map[string]interface{}) *engine.Event {
	msg, ok := raw["message"].(map[string]interface{})
	if !ok {
		return nil
	}

	// Only care about assistant messages for model extraction.
	role, _ := msg["role"].(string)
	if role != "assistant" {
		return nil
	}

	// Extract model name from first assistant message.
	if model, _ := msg["model"].(string); model != "" && p.model == "" {
		p.model = model
		return &engine.Event{
			Type: engine.EventInit,
			Data: engine.EventData{
				Model: model,
			},
		}
	}

	return nil
}

func (p *Parser) parseMessageUpdate(raw map[string]interface{}) *engine.Event {
	ame, ok := raw["assistantMessageEvent"].(map[string]interface{})
	if !ok {
		return nil
	}

	ameType, _ := ame["type"].(string)

	switch ameType {
	case "toolcall_end":
		return p.parseToolCallEnd(ame)
	case "text_end":
		return p.parseTextEnd(ame)
	default:
		return nil
	}
}

func (p *Parser) parseToolCallEnd(ame map[string]interface{}) *engine.Event {
	tc, ok := ame["toolCall"].(map[string]interface{})
	if !ok {
		return nil
	}

	name, _ := tc["name"].(string)
	args, _ := tc["arguments"].(map[string]interface{})

	event := &engine.Event{
		Type: engine.EventTool,
		Tool: strings.ToLower(name),
	}

	switch strings.ToLower(name) {
	case "read":
		path, _ := args["path"].(string)
		event.Detail = shortPath(path)
	case "write":
		path, _ := args["path"].(string)
		event.Detail = shortPath(path)
	case "edit":
		path, _ := args["path"].(string)
		event.Detail = shortPath(path)
	case "bash":
		cmd, _ := args["command"].(string)
		event.Detail = truncate(cmd, 50)
		event.Tool = "run"
	case "grep":
		pattern, _ := args["pattern"].(string)
		event.Detail = truncate(pattern, 40)
	case "find":
		pattern, _ := args["pattern"].(string)
		if pattern == "" {
			pattern, _ = args["path"].(string)
		}
		event.Detail = truncate(pattern, 40)
	case "ls":
		path, _ := args["path"].(string)
		event.Detail = shortPath(path)
	default:
		event.Tool = strings.ToLower(name)
	}

	return event
}

func (p *Parser) parseTextEnd(ame map[string]interface{}) *engine.Event {
	content, _ := ame["content"].(string)
	if content != "" {
		p.text.WriteString(content)
	}

	// Text end events are usually intermediate; don't emit a visible event.
	// The display will just keep the spinner running.
	return nil
}

func (p *Parser) parseMessageEnd(raw map[string]interface{}) *engine.Event {
	msg, ok := raw["message"].(map[string]interface{})
	if !ok {
		return nil
	}

	// Extract usage from assistant message_end for running totals.
	role, _ := msg["role"].(string)
	if role == "assistant" {
		p.accumulateUsage(msg)
	}

	return nil
}

func (p *Parser) parseToolExecutionStart(raw map[string]interface{}) *engine.Event {
	// We already show tool calls from toolcall_end; this is supplementary.
	// Could show a spinner message here, but toolcall_end already handles it.
	return nil
}

func (p *Parser) parseToolExecutionEnd(raw map[string]interface{}) *engine.Event {
	isError, _ := raw["isError"].(bool)
	if !isError {
		return nil
	}

	toolName, _ := raw["toolName"].(string)
	p.hasFailure = true

	// Extract error message from result
	message := toolName + " failed"
	if result, ok := raw["result"].(map[string]interface{}); ok {
		if content, ok := result["content"].([]interface{}); ok {
			for _, item := range content {
				block, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				if text, _ := block["text"].(string); text != "" {
					message = truncate(text, 80)
					break
				}
			}
		}
	}

	return &engine.Event{
		Type: engine.EventError,
		Data: engine.EventData{
			Message: message,
		},
	}
}

func (p *Parser) parseTurnEnd(raw map[string]interface{}) *engine.Event {
	// Accumulate usage from the turn_end message.
	if msg, ok := raw["message"].(map[string]interface{}); ok {
		p.accumulateUsage(msg)
	}

	return nil
}

func (p *Parser) parseAgentEnd(raw map[string]interface{}) *engine.Event {
	// agent_end is the final event. Emit a result.
	success := !p.hasFailure

	return &engine.Event{
		Type: engine.EventResult,
		Data: engine.EventData{
			Success: success,
			Tokens:  p.totalTokens,
		},
	}
}

// accumulateUsage extracts and adds token usage from a message object.
func (p *Parser) accumulateUsage(msg map[string]interface{}) {
	usage, ok := msg["usage"].(map[string]interface{})
	if !ok {
		return
	}

	// Pi usage fields: input, output, cacheRead, cacheWrite, totalTokens
	if total, ok := usage["totalTokens"].(float64); ok && total > 0 {
		p.totalTokens = int(total) // Use the latest totalTokens (cumulative per turn)
		return
	}

	// Fallback: sum individual fields
	tokens := 0
	if v, ok := usage["input"].(float64); ok {
		tokens += int(v)
	}
	if v, ok := usage["output"].(float64); ok {
		tokens += int(v)
	}
	if v, ok := usage["cacheRead"].(float64); ok {
		tokens += int(v)
	}
	if v, ok := usage["cacheWrite"].(float64); ok {
		tokens += int(v)
	}
	if tokens > p.totalTokens {
		p.totalTokens = tokens
	}
}

// Helper functions

func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpace(b[start]) {
		start++
	}
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

func shortPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) <= 2 {
		return path
	}
	return ".../" + strings.Join(parts[len(parts)-2:], "/")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
