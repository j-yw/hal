package factory

import "time"

// BootstrapRequest captures the repository workspace setup contract for future
// factory executors without tying them to CLI state.
type BootstrapRequest struct {
	RepositoryURL   string            `json:"repositoryUrl"`
	BaseBranch      string            `json:"baseBranch"`
	RunBranch       string            `json:"runBranch"`
	WorkspaceDir    string            `json:"workspaceDir"`
	RequiredEnvKeys []string          `json:"requiredEnvKeys"`
	Env             map[string]string `json:"env,omitempty"`
	Options         BootstrapOptions  `json:"options"`
}

// BootstrapOptions controls repository and Hal setup behavior for a bootstrap
// run while leaving execution and persistence decisions to callers.
type BootstrapOptions struct {
	RefreshHal         bool `json:"refreshHal"`
	InstallMissingCLIs bool `json:"installMissingClis"`
	DryRun             bool `json:"dryRun"`
}

// BootstrapResult captures the machine-readable outcome of preparing a remote
// workspace for a factory run.
type BootstrapResult struct {
	RepoPath         string                   `json:"repoPath"`
	CheckedOutBranch string                   `json:"checkedOutBranch"`
	Steps            []BootstrapStepResult    `json:"steps"`
	Timeline         []BootstrapTimelineEvent `json:"timeline"`
	Failure          *BootstrapFailure        `json:"failure,omitempty"`
}

// BootstrapStepResult records one executed or planned bootstrap step.
type BootstrapStepResult struct {
	Name           string     `json:"name"`
	Status         string     `json:"status"`
	CommandSummary string     `json:"commandSummary,omitempty"`
	StartedAt      time.Time  `json:"startedAt"`
	FinishedAt     *time.Time `json:"finishedAt,omitempty"`
	ExitCode       int        `json:"exitCode,omitempty"`
}

// BootstrapTimelineEvent is a timeline-ready, sanitized bootstrap event.
type BootstrapTimelineEvent struct {
	Timestamp      time.Time         `json:"timestamp"`
	Step           string            `json:"step"`
	Status         string            `json:"status"`
	Message        string            `json:"message,omitempty"`
	CommandSummary string            `json:"commandSummary,omitempty"`
	OutputSummary  string            `json:"outputSummary,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// BootstrapFailure records classified bootstrap failure details suitable for
// sanitized timeline and result output.
type BootstrapFailure struct {
	Step     string `json:"step,omitempty"`
	Category string `json:"category"`
	Message  string `json:"message"`
}
