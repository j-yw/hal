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

// PipelineState represents the current state of an auto pipeline run.
// This state is persisted to allow resumption from interruptions.
type PipelineState struct {
	Step           string           `json:"step"`
	BaseBranch     string           `json:"baseBranch,omitempty"` // Empty means current HEAD (git default)
	BranchName     string           `json:"branchName"`
	SourceMarkdown string           `json:"sourceMarkdown,omitempty"`
	ReportPath     string           `json:"reportPath,omitempty"`
	StartedAt      time.Time        `json:"startedAt"`
	Validation     *ValidationState `json:"validation,omitempty"`
	Run            *RunState        `json:"run,omitempty"`
	Review         *ReviewState     `json:"review,omitempty"`
	CI             *CIState         `json:"ci,omitempty"`
	Analysis       *AnalysisResult  `json:"analysis,omitempty"`
}

// ValidationState stores validation telemetry in pipeline state.
type ValidationState struct {
	Attempts int    `json:"attempts,omitempty"`
	Status   string `json:"status,omitempty"`
}

// RunState stores run-step telemetry in pipeline state.
type RunState struct {
	Iterations    int  `json:"iterations,omitempty"`
	Complete      bool `json:"complete,omitempty"`
	MaxIterations int  `json:"maxIterations,omitempty"`
}

// ReviewState stores review-step telemetry in pipeline state.
type ReviewState struct {
	Status string `json:"status,omitempty"`
}

// CIState stores ci-step telemetry in pipeline state.
type CIState struct {
	Status string `json:"status,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Valid step values for PipelineState.Step.
const (
	StepAnalyze  = "analyze"
	StepSpec     = "spec"
	StepBranch   = "branch"
	StepConvert  = "convert"
	StepValidate = "validate"
	StepRun      = "run"
	StepReview   = "review"
	StepReport   = "report"
	StepCI       = "ci"
	StepArchive  = "archive"
	StepDone     = "done"

	// Legacy aliases retained for internal readability while state values remain normalized.
	StepPRD     = StepSpec
	StepExplode = StepConvert
	StepLoop    = StepRun
	StepPR      = StepCI
)

// ReviewResult contains the output of a review operation.
type ReviewResult struct {
	ReportPath      string   `json:"reportPath"`
	Summary         string   `json:"summary"`
	PatternsAdded   []string `json:"patternsAdded"`
	Recommendations []string `json:"recommendations"`
	Issues          []string `json:"issues,omitempty"`
	TechDebt        []string `json:"techDebt,omitempty"`
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
	Engine              string                `json:"engine,omitempty"`
	RequestedIterations int                   `json:"requestedIterations"`
	CompletedIterations int                   `json:"completedIterations"`
	StopReason          string                `json:"stopReason"`
	StartedAt           time.Time             `json:"startedAt"`
	EndedAt             time.Time             `json:"endedAt"`
	Duration            time.Duration         `json:"duration,omitempty"`
	Totals              ReviewLoopTotals      `json:"totals"`
	Iterations          []ReviewLoopIteration `json:"iterations"`
}

// ReviewLoopTotals tracks aggregate counts for a review loop run.
type ReviewLoopTotals struct {
	IssuesFound   int      `json:"issuesFound"`
	ValidIssues   int      `json:"validIssues"`
	InvalidIssues int      `json:"invalidIssues"`
	FixesApplied  int      `json:"fixesApplied"`
	FilesAffected []string `json:"filesAffected,omitempty"`
}

// ReviewLoopIteration contains per-iteration review/fix statistics.
type ReviewLoopIteration struct {
	Iteration     int                 `json:"iteration"`
	IssuesFound   int                 `json:"issuesFound"`
	ValidIssues   int                 `json:"validIssues"`
	InvalidIssues int                 `json:"invalidIssues"`
	FixesApplied  int                 `json:"fixesApplied"`
	Summary       string              `json:"summary"`
	Status        string              `json:"status"`
	Duration      time.Duration       `json:"duration,omitempty"`
	Issues        []ReviewIssueDetail `json:"issues,omitempty"`
}

// ReviewIssueDetail captures per-issue context from a review iteration,
// combining the review-phase finding with the fix-phase outcome.
type ReviewIssueDetail struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	File         string `json:"file"`
	Line         int    `json:"line,omitempty"`
	Rationale    string `json:"rationale,omitempty"`
	SuggestedFix string `json:"suggestedFix,omitempty"`
	Valid        bool   `json:"valid"`
	Fixed        bool   `json:"fixed"`
	Reason       string `json:"reason,omitempty"`
}
