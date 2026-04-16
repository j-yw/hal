package product

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// SelectedTargets describes which product documents are in scope for a run.
type SelectedTargets struct {
	Mission   bool `json:"mission"`
	Roadmap   bool `json:"roadmap"`
	TechStack bool `json:"techStack"`
}

// InterviewAnswer captures one question/answer pair from interactive input.
type InterviewAnswer struct {
	Question string `json:"question"`
	Answer   string `json:"answer"`
}

// CollectedAnswers contains interview answers grouped by selected target.
type CollectedAnswers struct {
	Mission   []InterviewAnswer `json:"mission,omitempty"`
	Roadmap   []InterviewAnswer `json:"roadmap,omitempty"`
	TechStack []InterviewAnswer `json:"techStack,omitempty"`
}

// FileState stores the current existence and content of a product document.
type FileState struct {
	Exists  bool
	Content string
}

// ExistingFiles holds current on-disk state for all product documents.
type ExistingFiles struct {
	Mission   FileState
	Roadmap   FileState
	TechStack FileState
}

// GeneratedPayload is the strict JSON response schema from generation.
// Keys are file names so selective writes can map directly to target files.
type GeneratedPayload struct {
	Mission   *string `json:"mission.md,omitempty"`
	Roadmap   *string `json:"roadmap.md,omitempty"`
	TechStack *string `json:"tech-stack.md,omitempty"`
}

// ParseGeneratedPayload parses strict JSON output for product generation.
func ParseGeneratedPayload(data []byte) (GeneratedPayload, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return GeneratedPayload{}, fmt.Errorf("parse generated payload: expected JSON object")
	}

	var payload GeneratedPayload
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return GeneratedPayload{}, fmt.Errorf("parse generated payload: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return GeneratedPayload{}, fmt.Errorf("parse generated payload: expected single JSON object")
	}
	return payload, nil
}

// ParseGeneratedPayloadForTargets parses strict JSON and enforces required keys
// for selected targets.
func ParseGeneratedPayloadForTargets(data []byte, targets SelectedTargets) (GeneratedPayload, error) {
	payload, err := ParseGeneratedPayload(data)
	if err != nil {
		return GeneratedPayload{}, err
	}
	if err := validateGeneratedPayloadTargets(payload, targets); err != nil {
		return GeneratedPayload{}, err
	}
	return payload, nil
}

func validateGeneratedPayloadTargets(payload GeneratedPayload, targets SelectedTargets) error {
	missing := make([]string, 0, 3)
	if targets.Mission && payload.Mission == nil {
		missing = append(missing, "mission.md")
	}
	if targets.Roadmap && payload.Roadmap == nil {
		missing = append(missing, "roadmap.md")
	}
	if targets.TechStack && payload.TechStack == nil {
		missing = append(missing, "tech-stack.md")
	}
	if len(missing) > 0 {
		return fmt.Errorf("parse generated payload: missing required key(s): %s", strings.Join(missing, ", "))
	}
	return nil
}
