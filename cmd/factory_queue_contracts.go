package cmd

import "github.com/jywlabs/hal/internal/factory"

const (
	FactoryQueueAddContractVersion  = "factory-queue-add-v1"
	FactoryQueueListContractVersion = "factory-queue-list-v1"
	FactoryQueueWorkContractVersion = "factory-queue-work-v1"
)

// FactoryQueueAddResponse is the machine-readable JSON output for
// hal factory queue add --json.
type FactoryQueueAddResponse struct {
	ContractVersion string             `json:"contractVersion"`
	Entry           factory.QueueEntry `json:"entry"`
	Summary         string             `json:"summary"`
}

// FactoryQueueListResponse is the machine-readable JSON output for
// hal factory queue list --json.
type FactoryQueueListResponse struct {
	ContractVersion string               `json:"contractVersion"`
	Entries         []factory.QueueEntry `json:"entries"`
	Summary         string               `json:"summary"`
}

// FactoryQueueWorkResponse is the machine-readable JSON output for
// hal factory queue work --json.
type FactoryQueueWorkResponse struct {
	ContractVersion string              `json:"contractVersion"`
	Claimed         bool                `json:"claimed"`
	Entry           *factory.QueueEntry `json:"entry"`
	Summary         string              `json:"summary"`
}
