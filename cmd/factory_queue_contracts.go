package cmd

import (
	"time"

	"github.com/jywlabs/hal/internal/factory"
)

const (
	FactoryQueueAddContractVersion  = "factory-queue-add-v1"
	FactoryQueueListContractVersion = "factory-queue-list-v1"
	FactoryQueueWorkContractVersion = "factory-queue-work-v1"
)

// FactoryQueueAddResponse is the machine-readable JSON output for
// hal factory queue add --json.
type FactoryQueueAddResponse struct {
	ContractVersion string            `json:"contractVersion"`
	Entry           FactoryQueueEntry `json:"entry"`
	Summary         string            `json:"summary"`
}

// FactoryQueueListResponse is the machine-readable JSON output for
// hal factory queue list --json.
type FactoryQueueListResponse struct {
	ContractVersion string              `json:"contractVersion"`
	Entries         []FactoryQueueEntry `json:"entries"`
	Summary         string              `json:"summary"`
}

// FactoryQueueWorkResponse is the machine-readable JSON output for
// hal factory queue work --json.
type FactoryQueueWorkResponse struct {
	ContractVersion string             `json:"contractVersion"`
	Claimed         bool               `json:"claimed"`
	Entry           *FactoryQueueEntry `json:"entry"`
	Summary         string             `json:"summary"`
}

// FactoryQueueEntry is the command-safe queue entry shape embedded by queue
// JSON responses.
type FactoryQueueEntry struct {
	QueueID      string              `json:"queueId"`
	RunID        string              `json:"runId"`
	ExecutorMode string              `json:"executorMode"`
	Status       string              `json:"status"`
	CreatedAt    time.Time           `json:"createdAt"`
	ClaimedAt    *time.Time          `json:"claimedAt,omitempty"`
	CompletedAt  *time.Time          `json:"completedAt,omitempty"`
	Claim        *factory.QueueClaim `json:"claim,omitempty"`
	AttemptCount int                 `json:"attemptCount"`
	LastError    string              `json:"lastError,omitempty"`
}

func newFactoryQueueEntryResponse(entry factory.QueueEntry) FactoryQueueEntry {
	return FactoryQueueEntry{
		QueueID:      entry.QueueID,
		RunID:        entry.RunID,
		ExecutorMode: entry.ExecutorMode,
		Status:       entry.Status,
		CreatedAt:    entry.CreatedAt,
		ClaimedAt:    entry.ClaimedAt,
		CompletedAt:  entry.CompletedAt,
		Claim:        entry.Claim,
		AttemptCount: entry.AttemptCount,
		LastError:    sanitizeFactoryQueueEntryLastError(entry.LastError),
	}
}

func newFactoryQueueEntryResponses(entries []factory.QueueEntry) []FactoryQueueEntry {
	safe := make([]FactoryQueueEntry, 0, len(entries))
	for _, entry := range entries {
		safe = append(safe, newFactoryQueueEntryResponse(entry))
	}
	return safe
}

func newFactoryQueueEntryResponsePtr(entry *factory.QueueEntry) *FactoryQueueEntry {
	if entry == nil {
		return nil
	}
	safe := newFactoryQueueEntryResponse(*entry)
	return &safe
}

func sanitizeFactoryQueueEntryLastError(value string) string {
	return sanitizeFactoryRunResultText(value)
}
