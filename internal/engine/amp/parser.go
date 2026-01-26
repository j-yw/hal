package amp

import (
	"encoding/json"
	"strings"

	"github.com/jywlabs/goralph/internal/engine"
)

// Parser parses Amp's output format.
// NOTE: This is a placeholder - actual Amp output format TBD.
type Parser struct{}

// NewParser creates a new Amp output parser.
func NewParser() *Parser {
	return &Parser{}
}

// ParseLine parses a single line from Amp's output.
// TODO: Implement actual Amp output parsing when format is known.
func (p *Parser) ParseLine(line []byte) *engine.Event {
	line = trimSpace(line)
	if len(line) == 0 {
		return nil
	}

	// Try to parse as JSON first
	var raw map[string]interface{}
	if err := json.Unmarshal(line, &raw); err != nil {
		// Not JSON - might be plain text output
		return p.parsePlainText(string(line))
	}

	// Handle JSON output if Amp supports it
	eventType, _ := raw["type"].(string)

	switch eventType {
	case "tool":
		return p.parseTool(raw)
	case "result":
		return p.parseResult(raw)
	default:
		return nil
	}
}

func (p *Parser) parsePlainText(line string) *engine.Event {
	// Detect tool usage from plain text patterns
	lower := strings.ToLower(line)

	if strings.Contains(lower, "reading") || strings.Contains(lower, "read file") {
		return &engine.Event{
			Type:   engine.EventTool,
			Tool:   "read",
			Detail: extractPath(line),
		}
	}

	if strings.Contains(lower, "writing") || strings.Contains(lower, "write file") {
		return &engine.Event{
			Type:   engine.EventTool,
			Tool:   "write",
			Detail: extractPath(line),
		}
	}

	if strings.Contains(lower, "running") || strings.Contains(lower, "executing") {
		return &engine.Event{
			Type:   engine.EventTool,
			Tool:   "run",
			Detail: truncate(line, 50),
		}
	}

	return nil
}

func (p *Parser) parseTool(raw map[string]interface{}) *engine.Event {
	name, _ := raw["tool"].(string)
	return &engine.Event{
		Type: engine.EventTool,
		Tool: strings.ToLower(name),
	}
}

func (p *Parser) parseResult(raw map[string]interface{}) *engine.Event {
	success, _ := raw["success"].(bool)
	return &engine.Event{
		Type: engine.EventResult,
		Data: engine.EventData{
			Success: success,
		},
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

func extractPath(line string) string {
	// Try to extract a file path from the line
	// This is a simple heuristic - can be improved
	parts := strings.Fields(line)
	for _, part := range parts {
		if strings.Contains(part, "/") || strings.Contains(part, ".") {
			return truncate(part, 40)
		}
	}
	return ""
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
