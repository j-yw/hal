package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/factory"
)

// FactoryRunResponse is the machine-readable JSON output for hal factory run --json.
type FactoryRunResponse struct {
	ContractVersion string                        `json:"contractVersion"`
	Version         string                        `json:"version"`
	RunID           string                        `json:"runId"`
	Status          string                        `json:"status"`
	NextAction      *FactoryRunNextAction         `json:"nextAction"`
	Artifacts       []FactoryRunArtifactReference `json:"artifacts"`
	EventSummary    FactoryRunEventSummary        `json:"eventSummary"`
	Failure         *FactoryRunFailure            `json:"failure"`
}

// FactoryRunNextAction suggests what to do after a local factory run.
type FactoryRunNextAction struct {
	ID          string `json:"id"`
	Command     string `json:"command"`
	Description string `json:"description"`
}

// FactoryRunEventSummary summarizes the durable timeline associated with a run.
type FactoryRunEventSummary struct {
	Total         int            `json:"total"`
	ByType        map[string]int `json:"byType"`
	LastEventType string         `json:"lastEventType,omitempty"`
	LastSummary   string         `json:"lastSummary,omitempty"`
}

// FactoryRunFailure is the result-surface failure detail for failed factory runs.
type FactoryRunFailure struct {
	Classification   string `json:"classification"`
	ErrorMessage     string `json:"errorMessage"`
	SuggestedCommand string `json:"suggestedCommand,omitempty"`
}

// FactoryRunArtifactReference preserves the factory-run-v1 artifact shape while
// avoiding raw workspace-local absolute paths.
type FactoryRunArtifactReference struct {
	ID         string         `json:"id,omitempty"`
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	SourcePath string         `json:"sourcePath,omitempty"`
	StoredPath string         `json:"storedPath,omitempty"`
	Path       string         `json:"path,omitempty"`
	URL        string         `json:"url,omitempty"`
	SizeBytes  *int64         `json:"sizeBytes,omitempty"`
	CreatedAt  *time.Time     `json:"createdAt,omitempty"`
	Summary    map[string]any `json:"summary,omitempty"`
	Warnings   []string       `json:"warnings,omitempty"`
	Partial    bool           `json:"partial,omitempty"`
}

func renderFactoryRunJSON(out io.Writer, resp FactoryRunResponse) error {
	resp = normalizeFactoryRunResponse(resp)
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal factory run result: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func renderFactoryRunValidationErrorJSON(out io.Writer, err error) error {
	message := strings.TrimSpace(err.Error())
	var exitErr *ExitCodeError
	if errors.As(err, &exitErr) && exitErr.Err != nil {
		message = strings.TrimSpace(exitErr.Err.Error())
	}
	if message == "" {
		message = "factory run validation failed"
	}

	return renderFactoryRunJSON(out, FactoryRunResponse{
		ContractVersion: FactoryRunContractVersion,
		Version:         Version,
		Status:          factory.RunStatusFailed,
		Artifacts:       []FactoryRunArtifactReference{},
		EventSummary:    FactoryRunEventSummary{ByType: map[string]int{}},
		Failure: &FactoryRunFailure{
			Classification: factory.FailureCategoryValidation,
			ErrorMessage:   message,
		},
	})
}

func renderFactoryRunSummary(out io.Writer, resp FactoryRunResponse) error {
	resp = normalizeFactoryRunResponse(resp)
	if _, err := fmt.Fprintf(out, "Run ID: %s\n", resp.RunID); err != nil {
		return fmt.Errorf("write factory run summary: %w", err)
	}
	if _, err := fmt.Fprintf(out, "Status: %s\n", resp.Status); err != nil {
		return fmt.Errorf("write factory run summary: %w", err)
	}

	if resp.Failure != nil {
		if strings.TrimSpace(resp.Failure.ErrorMessage) != "" {
			if _, err := fmt.Fprintf(out, "Error: %s\n", resp.Failure.ErrorMessage); err != nil {
				return fmt.Errorf("write factory run summary: %w", err)
			}
		}
		if strings.TrimSpace(resp.Failure.Classification) != "" {
			if _, err := fmt.Fprintf(out, "Classification: %s\n", resp.Failure.Classification); err != nil {
				return fmt.Errorf("write factory run summary: %w", err)
			}
		}
		if command := factoryRunSuggestedCommand(resp); command != "" {
			if _, err := fmt.Fprintf(out, "Suggested command: %s\n", command); err != nil {
				return fmt.Errorf("write factory run summary: %w", err)
			}
		}
		return nil
	}

	if resp.NextAction != nil && strings.TrimSpace(resp.NextAction.Command) != "" {
		if _, err := fmt.Fprintf(out, "Next action: %s\n", resp.NextAction.Command); err != nil {
			return fmt.Errorf("write factory run summary: %w", err)
		}
	}
	return nil
}

func newFactoryRunResponse(record factory.RunRecord, events []factory.EventRecord) FactoryRunResponse {
	return FactoryRunResponse{
		ContractVersion: FactoryRunContractVersion,
		Version:         Version,
		RunID:           record.RunID,
		Status:          record.Status,
		NextAction:      newFactoryRunNextAction(record),
		Artifacts:       newFactoryRunArtifactReferences(record.Artifacts),
		EventSummary:    newFactoryRunEventSummary(events),
		Failure:         newFactoryRunFailure(record),
	}
}

func newFactoryRunArtifactReferences(artifacts []factory.ArtifactReference) []FactoryRunArtifactReference {
	refs := make([]FactoryRunArtifactReference, 0, len(artifacts))
	for _, artifact := range artifacts {
		refs = append(refs, FactoryRunArtifactReference{
			ID:         strings.TrimSpace(artifact.ID),
			Name:       strings.TrimSpace(artifact.Name),
			Type:       strings.TrimSpace(artifact.Type),
			SourcePath: sanitizeFactoryArtifactPath(artifact.SourcePath),
			StoredPath: strings.TrimSpace(artifact.StoredPath),
			Path:       sanitizeFactoryArtifactPath(artifact.Path),
			URL:        safeFactoryPRURL(artifact.URL),
			SizeBytes:  artifact.SizeBytes,
			CreatedAt:  artifact.CreatedAt,
			Summary:    sanitizeFactoryArtifactSummary(artifact.Summary),
			Warnings:   sanitizeFactoryArtifactWarnings(artifact.Warnings),
			Partial:    artifact.Partial,
		})
	}
	return refs
}

func newFactoryRunNextAction(record factory.RunRecord) *FactoryRunNextAction {
	command := factoryRunInspectCommand(record.RunID)
	if command == "" {
		return nil
	}
	return &FactoryRunNextAction{
		ID:          "inspect_factory_run",
		Command:     command,
		Description: "Inspect the durable run record and timeline.",
	}
}

func newFactoryRunFailure(record factory.RunRecord) *FactoryRunFailure {
	if record.Failure == nil {
		return nil
	}
	failure := &FactoryRunFailure{
		Classification: factoryRunFailureClassification(record.Failure.Category),
		ErrorMessage:   record.Failure.Message,
	}
	if suggested := strings.TrimSpace(record.Failure.SuggestedCommand); suggested != "" {
		failure.SuggestedCommand = suggested
	} else if nextAction := newFactoryRunNextAction(record); nextAction != nil {
		failure.SuggestedCommand = nextAction.Command
	}
	return failure
}

func factoryRunFailureClassification(category string) string {
	switch strings.TrimSpace(category) {
	case factory.FailureCategoryValidation:
		return factory.FailureCategoryValidation
	case factory.FailureCategoryPipeline:
		return factory.FailureCategoryPipeline
	case factory.FailureCategoryEngine:
		return factory.FailureCategoryEngine
	case factory.FailureCategoryGit:
		return factory.FailureCategoryGit
	case factory.FailureCategoryCI:
		return factory.FailureCategoryCI
	case factory.BootstrapFailureCategoryRepo:
		return factory.FailureCategoryGit
	case factory.BootstrapFailureCategoryAuth, factory.BootstrapFailureCategoryDependency:
		return factory.FailureCategoryValidation
	case factory.BootstrapFailureCategoryEngineSetup:
		return factory.FailureCategoryEngine
	default:
		return factory.FailureCategoryUnknown
	}
}

func factoryRunInspectCommand(runID string) string {
	runID = strings.TrimSpace(runID)
	if runID == "" {
		return ""
	}
	return fmt.Sprintf("hal factory status %s --json", runID)
}

func normalizeFactoryRunResponse(resp FactoryRunResponse) FactoryRunResponse {
	if resp.Artifacts == nil {
		resp.Artifacts = []FactoryRunArtifactReference{}
	}
	if resp.EventSummary.ByType == nil {
		resp.EventSummary.ByType = map[string]int{}
	}
	return resp
}

func factoryRunSuggestedCommand(resp FactoryRunResponse) string {
	if resp.Failure != nil {
		if command := strings.TrimSpace(resp.Failure.SuggestedCommand); command != "" {
			return command
		}
	}
	if resp.NextAction != nil {
		return strings.TrimSpace(resp.NextAction.Command)
	}
	return ""
}

func newFactoryRunEventSummary(events []factory.EventRecord) FactoryRunEventSummary {
	summary := FactoryRunEventSummary{
		Total:  len(events),
		ByType: map[string]int{},
	}

	for _, event := range events {
		if event.EventType != "" {
			summary.ByType[event.EventType]++
		}
	}

	if len(events) > 0 {
		last := events[len(events)-1]
		summary.LastEventType = last.EventType
		summary.LastSummary = last.Summary
	}

	return summary
}
