package factory

import (
	"strconv"
	"strings"
	"time"
)

const bootstrapTimelineFailureCategoryKey = "failureCategory"

// BootstrapTimelineEventFromStep converts a bootstrap step outcome into the
// sanitized, timeline-ready event shape used by bootstrap results.
func BootstrapTimelineEventFromStep(request BootstrapRequest, step BootstrapStepResult, commandResult BootstrapCommandResult, failure *BootstrapFailure) BootstrapTimelineEvent {
	event := BootstrapTimelineEvent{
		Timestamp:      bootstrapTimelineTimestamp(step),
		Step:           strings.TrimSpace(step.Name),
		Status:         strings.TrimSpace(step.Status),
		Message:        bootstrapTimelineMessage(step, failure),
		CommandSummary: strings.TrimSpace(step.CommandSummary),
		OutputSummary:  bootstrapTimelineOutputSummary(commandResult),
		Metadata:       bootstrapTimelineMetadata(step, commandResult, failure),
	}
	return SanitizeBootstrapTimelineEvent(request, event)
}

func recordBootstrapStepResult(result *BootstrapResult, request BootstrapRequest, step BootstrapStepResult, commandResult BootstrapCommandResult, failure *BootstrapFailure) {
	result.Steps = append(result.Steps, step)
	result.Timeline = append(result.Timeline, BootstrapTimelineEventFromStep(request, step, commandResult, failure))
}

func bootstrapTimelineTimestamp(step BootstrapStepResult) time.Time {
	if step.FinishedAt != nil {
		return *step.FinishedAt
	}
	return step.StartedAt
}

func bootstrapTimelineMessage(step BootstrapStepResult, failure *BootstrapFailure) string {
	if failure != nil {
		return failure.Message
	}

	switch step.Status {
	case RunStatusSucceeded:
		return "bootstrap step succeeded"
	case RunStatusPending:
		return "bootstrap step planned"
	case RunStatusFailed:
		return "bootstrap step failed"
	default:
		if step.Status = strings.TrimSpace(step.Status); step.Status != "" {
			return "bootstrap step " + step.Status
		}
		return "bootstrap step recorded"
	}
}

func bootstrapTimelineOutputSummary(result BootstrapCommandResult) string {
	return strings.TrimSpace(result.classificationOutput())
}

func bootstrapTimelineMetadata(step BootstrapStepResult, result BootstrapCommandResult, failure *BootstrapFailure) map[string]string {
	metadata := make(map[string]string, len(result.Metadata)+2)
	for key, value := range result.Metadata {
		if key = strings.TrimSpace(key); key != "" {
			metadata[key] = value
		}
	}

	if step.FinishedAt != nil || step.ExitCode != 0 {
		metadata["exitCode"] = strconv.Itoa(step.ExitCode)
	}
	if failure != nil && strings.TrimSpace(failure.Category) != "" {
		metadata[bootstrapTimelineFailureCategoryKey] = strings.TrimSpace(failure.Category)
	}
	if len(metadata) == 0 {
		return nil
	}
	return metadata
}
