package ci

// Stable machine-contract identifiers for CI command output.
const (
	PushContractVersion   = "ci-push-v1"
	StatusContractVersion = "ci-status-v1"
	FixContractVersion    = "ci-fix-v1"
	MergeContractVersion  = "ci-merge-v1"
)

// Aggregated status values.
const (
	StatusPending = "pending"
	StatusFailing = "failing"
	StatusPassing = "passing"
)

// Wait terminal reason values.
const (
	WaitTerminalReasonCompleted        = "completed"
	WaitTerminalReasonTimeout          = "timeout"
	WaitTerminalReasonNoChecksDetected = "no_checks_detected"
)

// Check context source values.
const (
	CheckSourceCheckRun = "check"
	CheckSourceStatus   = "status"
)

// PushResult is the shared machine-readable output for push flows.
type PushResult struct {
	ContractVersion string      `json:"contractVersion"`
	Branch          string      `json:"branch"`
	Pushed          bool        `json:"pushed"`
	DryRun          bool        `json:"dryRun"`
	PullRequest     PullRequest `json:"pullRequest"`
	Summary         string      `json:"summary"`
}

// PullRequest contains PR metadata shared by CI operations.
type PullRequest struct {
	Number   int    `json:"number"`
	URL      string `json:"url"`
	Title    string `json:"title"`
	HeadRef  string `json:"headRef,omitempty"`
	HeadSHA  string `json:"headSha,omitempty"`
	BaseRef  string `json:"baseRef,omitempty"`
	Draft    bool   `json:"draft"`
	Existing bool   `json:"existing"`
}

// StatusResult is the shared machine-readable output for ci status.
type StatusResult struct {
	ContractVersion    string        `json:"contractVersion"`
	Branch             string        `json:"branch"`
	SHA                string        `json:"sha"`
	Status             string        `json:"status"`
	ChecksDiscovered   bool          `json:"checksDiscovered"`
	Wait               bool          `json:"wait"`
	WaitTerminalReason string        `json:"waitTerminalReason"`
	Checks             []StatusCheck `json:"checks"`
	Totals             StatusTotals  `json:"totals"`
	Summary            string        `json:"summary"`
}

// StatusCheck is one aggregated CI context.
type StatusCheck struct {
	Key    string `json:"key"`
	Source string `json:"source"`
	Name   string `json:"name"`
	Status string `json:"status"`
	URL    string `json:"url,omitempty"`
}

// StatusTotals summarizes aggregated check counts.
type StatusTotals struct {
	Pending int `json:"pending"`
	Failing int `json:"failing"`
	Passing int `json:"passing"`
}

// FixResult is the shared machine-readable output for ci fix.
type FixResult struct {
	ContractVersion string   `json:"contractVersion"`
	Attempt         int      `json:"attempt"`
	MaxAttempts     int      `json:"maxAttempts,omitempty"`
	Applied         bool     `json:"applied"`
	Branch          string   `json:"branch"`
	CommitSHA       string   `json:"commitSha,omitempty"`
	Pushed          bool     `json:"pushed"`
	FilesChanged    []string `json:"filesChanged,omitempty"`
	Summary         string   `json:"summary"`
}

// MergeResult is the shared machine-readable output for ci merge.
type MergeResult struct {
	ContractVersion string `json:"contractVersion"`
	PRNumber        int    `json:"prNumber"`
	Strategy        string `json:"strategy"`
	DryRun          bool   `json:"dryRun"`
	Merged          bool   `json:"merged"`
	MergeCommitSHA  string `json:"mergeCommitSha,omitempty"`
	BranchDeleted   bool   `json:"branchDeleted"`
	DeleteWarning   string `json:"deleteWarning,omitempty"`
	Summary         string `json:"summary"`
}
