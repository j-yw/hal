package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
)

// FactoryRunResponse is the machine-readable JSON output for hal factory run --json.
type FactoryRunResponse struct {
	ContractVersion string                        `json:"contractVersion"`
	Version         string                        `json:"version"`
	RunID           string                        `json:"runId"`
	Status          string                        `json:"status"`
	ExecutorMode    string                        `json:"executorMode"`
	BaseBranch      string                        `json:"baseBranch"`
	NextAction      *FactoryRunNextAction         `json:"nextAction"`
	Artifacts       []FactoryRunArtifactReference `json:"artifacts"`
	Telemetry       *factory.RunTelemetry         `json:"telemetry,omitempty"`
	EventSummary    FactoryRunEventSummary        `json:"eventSummary"`
	Failure         *FactoryRunFailure            `json:"failure"`
}

type factoryRunResponseWithSecurityReadinessGate struct {
	FactoryRunResponse
	SecurityReadinessGate *sandbox.SandboxSecurityCapabilityReadinessGateDecision `json:"securityReadinessGate,omitempty"`
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

// FactoryRunArtifactReference is the safe factory-run-v1 artifact surface.
type FactoryRunArtifactReference struct {
	ID         string         `json:"id,omitempty"`
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	StoredPath string         `json:"storedPath,omitempty"`
	Path       string         `json:"path,omitempty"`
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

func renderFactoryRunJSONWithSecurityReadinessGate(out io.Writer, resp FactoryRunResponse, gate *sandbox.SandboxSecurityCapabilityReadinessGateDecision) error {
	gate = sandbox.CloneSandboxSecurityCapabilityReadinessGateDecisionPtr(gate)
	if gate == nil {
		return renderFactoryRunJSON(out, resp)
	}
	resp = normalizeFactoryRunResponse(resp)
	data, err := json.MarshalIndent(factoryRunResponseWithSecurityReadinessGate{
		FactoryRunResponse:    resp,
		SecurityReadinessGate: gate,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal factory run result: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func renderFactoryRunSummary(out io.Writer, resp FactoryRunResponse) error {
	return renderFactoryRunSummaryWithSecurityReadinessGate(out, resp, nil)
}

func renderFactoryRunSummaryWithSecurityReadinessGate(out io.Writer, resp FactoryRunResponse, gate *sandbox.SandboxSecurityCapabilityReadinessGateDecision) error {
	resp = normalizeFactoryRunResponse(resp)
	if _, err := fmt.Fprintf(out, "Run ID: %s\n", resp.RunID); err != nil {
		return fmt.Errorf("write factory run summary: %w", err)
	}
	if _, err := fmt.Fprintf(out, "Status: %s\n", resp.Status); err != nil {
		return fmt.Errorf("write factory run summary: %w", err)
	}
	executorMode := strings.TrimSpace(resp.ExecutorMode)
	if executorMode == "" {
		executorMode = "(unknown)"
	}
	if _, err := fmt.Fprintf(out, "Executor: %s\n", executorMode); err != nil {
		return fmt.Errorf("write factory run summary: %w", err)
	}
	baseBranch := strings.TrimSpace(resp.BaseBranch)
	if baseBranch == "" {
		baseBranch = "(unresolved)"
	}
	if _, err := fmt.Fprintf(out, "Base: %s\n", baseBranch); err != nil {
		return fmt.Errorf("write factory run summary: %w", err)
	}
	if readiness := factorySecurityReadinessGateHuman(gate); readiness != "" {
		if _, err := fmt.Fprintf(out, "%s\n", readiness); err != nil {
			return fmt.Errorf("write factory run summary: %w", err)
		}
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
		ExecutorMode:    strings.TrimSpace(record.ExecutorMode),
		BaseBranch:      strings.TrimSpace(record.BaseBranch),
		NextAction:      newFactoryRunNextAction(record),
		Artifacts:       newFactoryRunArtifactReferences(record.Artifacts),
		Telemetry:       factory.DeriveRunTelemetry(record, events),
		EventSummary:    newFactoryRunEventSummary(events),
		Failure:         newFactoryRunFailure(record),
	}
}

func factorySecurityReadinessGateHuman(gate *sandbox.SandboxSecurityCapabilityReadinessGateDecision) string {
	return sandboxRuntimeSecurityReadinessGateHuman(gate)
}

func newFactoryRunArtifactReferences(artifacts []factory.ArtifactReference) []FactoryRunArtifactReference {
	refs := make([]FactoryRunArtifactReference, 0, len(artifacts))
	for _, artifact := range artifacts {
		refs = append(refs, FactoryRunArtifactReference{
			ID:         strings.TrimSpace(artifact.ID),
			Name:       strings.TrimSpace(artifact.Name),
			Type:       strings.TrimSpace(artifact.Type),
			StoredPath: strings.TrimSpace(artifact.StoredPath),
			Path:       sanitizeFactoryArtifactPath(artifact.Path),
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
	if factoryRunHasRecoverableSandboxBundle(record) {
		return &FactoryRunNextAction{
			ID:          "recover_factory_run",
			Command:     "hal factory recover " + strings.TrimSpace(record.RunID),
			Description: "Apply the stored sandbox recovery bundle locally.",
		}
	}

	command := factoryRunInspectCommand(record.RunID)
	if command == "" {
		return nil
	}
	actionID := "inspect_factory_run"
	description := "Inspect the durable run record and timeline."
	if record.Status == factory.RunStatusSucceeded {
		description = "Inspect the completed durable run record and timeline."
	}

	return &FactoryRunNextAction{
		ID:          actionID,
		Command:     command,
		Description: description,
	}
}

func factoryRunHasRecoverableSandboxBundle(record factory.RunRecord) bool {
	if record.Status != factory.RunStatusFailed || record.ExecutorMode != factory.ExecutorModeSandbox {
		return false
	}
	if strings.TrimSpace(record.RunID) == "" {
		return false
	}
	_, ok := factoryRunRecoveryBundleArtifact(record)
	return ok
}

func newFactoryRunFailure(record factory.RunRecord) *FactoryRunFailure {
	if record.Failure == nil {
		return nil
	}
	classification := factory.NormalizeFailureCategoryForContractV1(record.Failure.Category)
	failure := &FactoryRunFailure{
		Classification: classification,
		ErrorMessage:   sanitizeFactoryRunResultText(record.Failure.Message),
	}
	if nextAction := newFactoryRunNextAction(record); nextAction != nil && nextAction.ID == "recover_factory_run" {
		failure.SuggestedCommand = sanitizeFactoryRunResultText(nextAction.Command)
	} else if suggested := sanitizeFactoryRunResultText(record.Failure.SuggestedCommand); suggested != "" {
		failure.SuggestedCommand = suggested
	} else if nextAction := newFactoryRunNextAction(record); nextAction != nil {
		failure.SuggestedCommand = sanitizeFactoryRunResultText(nextAction.Command)
	}
	return failure
}

func sanitizeFactoryRunResultText(value string) string {
	return sanitizeFactoryLogText(value)
}

func factoryRunInspectCommand(runID string) string {
	return factory.HandoffInspectCommand(runID)
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
