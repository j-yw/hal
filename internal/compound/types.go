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
	Step              string          `json:"step"`
	BaseBranch        string          `json:"baseBranch,omitempty"` // Empty means current HEAD (git default)
	BranchName        string          `json:"branchName"`
	ReportPath        string          `json:"reportPath"`
	PRDPath           string          `json:"prdPath"`
	StartedAt         time.Time       `json:"startedAt"`
	LoopIterations    int             `json:"loopIterations,omitempty"`
	LoopComplete      bool            `json:"loopComplete,omitempty"`
	LoopMaxIterations int             `json:"loopMaxIterations,omitempty"`
	Analysis          *AnalysisResult `json:"analysis,omitempty"`
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

// ReviewResult contains the output of a review operation.
type ReviewResult struct {
	ReportPath      string   `json:"reportPath"`
	Summary         string   `json:"summary"`
	PatternsAdded   []string `json:"patternsAdded"`
	Recommendations []string `json:"recommendations"`
}

// ReviewOptions controls review behavior.
type ReviewOptions struct {
	DryRun     bool
	SkipAgents bool
}

// ReviewLoopResult contains the output of a hal review loop run.
type ReviewLoopResult struct {
	Command             string                `json:"command"`
	BaseBranch          string                `json:"baseBranch"`
	CurrentBranch       string                `json:"currentBranch"`
	RequestedIterations int                   `json:"requestedIterations"`
	CompletedIterations int                   `json:"completedIterations"`
	StopReason          string                `json:"stopReason"`
	StartedAt           time.Time             `json:"startedAt"`
	EndedAt             time.Time             `json:"endedAt"`
	Totals              ReviewLoopTotals      `json:"totals"`
	Iterations          []ReviewLoopIteration `json:"iterations"`
}

// ReviewLoopTotals tracks aggregate counts for a review loop run.
type ReviewLoopTotals struct {
	IssuesFound   int `json:"issuesFound"`
	ValidIssues   int `json:"validIssues"`
	InvalidIssues int `json:"invalidIssues"`
	FixesApplied  int `json:"fixesApplied"`
}

// ReviewLoopIteration contains per-iteration review/fix statistics.
type ReviewLoopIteration struct {
	Iteration     int    `json:"iteration"`
	IssuesFound   int    `json:"issuesFound"`
	ValidIssues   int    `json:"validIssues"`
	InvalidIssues int    `json:"invalidIssues"`
	FixesApplied  int    `json:"fixesApplied"`
	Summary       string `json:"summary"`
	Status        string `json:"status"`
}
