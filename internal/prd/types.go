package prd

// ValidationResult holds the outcome of PRD validation.
type ValidationResult struct {
	Valid    bool    `json:"valid"`
	Errors   []Issue `json:"errors,omitempty"`
	Warnings []Issue `json:"warnings,omitempty"`
}

// Issue represents a validation error or warning.
type Issue struct {
	StoryID  string `json:"storyId,omitempty"`
	Field    string `json:"field,omitempty"`
	Message  string `json:"message"`
	Severity string `json:"severity"` // "error" or "warning"
}


// Question represents a clarifying question during PRD generation.
type Question struct {
	Number   int      `json:"number"`
	Text     string   `json:"text"`
	Options  []Option `json:"options"`
}

// Option represents a selectable option for a question.
type Option struct {
	Letter      string `json:"letter"` // A, B, C, D
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
}

// QuestionsResponse is the expected format from the engine during phase 1.
type QuestionsResponse struct {
	Questions []Question `json:"questions"`
}

// GenerationRequest holds the inputs for PRD generation.
type GenerationRequest struct {
	Description string            // Feature description from user
	Answers     map[int]string    // Question number -> selected option(s)
	ProjectInfo string            // Optional codebase context
}

// ConversionRequest holds the inputs for PRD conversion.
type ConversionRequest struct {
	MarkdownPath string // Path to markdown PRD
	OutputPath   string // Path for output prd.json
	Validate     bool   // Whether to validate after conversion
}
