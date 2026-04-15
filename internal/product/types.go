package product

import (
	"encoding/json"
	"fmt"
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
	var payload GeneratedPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return GeneratedPayload{}, fmt.Errorf("parse generated payload: %w", err)
	}
	return payload, nil
}
