package compound

import "time"

// AnalysisResult contains the analyzed priority item from a report.
type AnalysisResult struct {
	PriorityItem       string   `json:"priorityItem"`
	Description        string   `json:"description"`
	Rationale          string   `json:"rationale"`
	AcceptanceCriteria []string `json:"acceptanceCriteria"`
	EstimatedTasks     int      `json:"estimatedTasks"`
	BranchName         string   `json:"branchName"`
}

// PipelineState represents the current state of a compound pipeline run.
// This state is persisted to allow resumption from interruptions.
type PipelineState struct {
	Step       string          `json:"step"`
	BranchName string          `json:"branchName"`
	ReportPath string          `json:"reportPath"`
	PRDPath    string          `json:"prdPath"`
	StartedAt  time.Time       `json:"startedAt"`
	Analysis   *AnalysisResult `json:"analysis,omitempty"`
}

// Valid step values for PipelineState.Step
const (
	StepAnalyze = "analyze"
	StepBranch  = "branch"
	StepPRD     = "prd"
	StepExplode = "explode"
	StepLoop    = "loop"
	StepPR      = "pr"
	StepDone    = "done"
)
