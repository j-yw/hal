// Package verify defines the stable machine-readable verification contract.
package verify

import "time"

// SchemaVersion is the current verify JSON contract identifier.
const SchemaVersion = "verify-v1"

// Top-level verification status values.
const (
	StatusPass = "pass"
	StatusFail = "fail"
	StatusWarn = "warn"
)

// Per-check verification status values.
const (
	CheckStatusPass    = "pass"
	CheckStatusFail    = "fail"
	CheckStatusTimeout = "timeout"
	CheckStatusMissing = "missing"
	CheckStatusSkipped = "skipped"
)

// Adapter values.
const (
	AdapterShell = "shell"
)

// Result is the top-level verify-v1 machine-readable payload.
type Result struct {
	SchemaVersion string              `json:"schemaVersion"`
	GeneratedAt   time.Time           `json:"generatedAt"`
	Status        string              `json:"status"`
	Summary       Summary             `json:"summary"`
	Checks        []CheckResult       `json:"checks"`
	Warnings      []Warning           `json:"warnings"`
	Artifacts     []ArtifactReference `json:"artifacts"`
}

// Summary contains aggregate verification counts.
type Summary struct {
	Total    int `json:"total"`
	Passed   int `json:"passed"`
	Failed   int `json:"failed"`
	TimedOut int `json:"timedOut"`
	Missing  int `json:"missing"`
	Skipped  int `json:"skipped"`
	Warnings int `json:"warnings"`
}

// CheckResult captures one configured verification check.
type CheckResult struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Adapter        string    `json:"adapter"`
	Status         string    `json:"status"`
	Required       bool      `json:"required"`
	Command        string    `json:"command"`
	WorkDir        string    `json:"workDir"`
	TimeoutSeconds int       `json:"timeoutSeconds"`
	StartedAt      time.Time `json:"startedAt"`
	FinishedAt     time.Time `json:"finishedAt"`
	DurationMs     int64     `json:"durationMs"`
	ExitCode       int       `json:"exitCode"`
	StdoutArtifact string    `json:"stdoutArtifact"`
	StderrArtifact string    `json:"stderrArtifact"`
	Message        string    `json:"message"`
}

// Warning describes a non-fatal verification problem.
type Warning struct {
	CheckID string `json:"checkId"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// ArtifactReference points to an output artifact produced by verification.
type ArtifactReference struct {
	CheckID string `json:"checkId"`
	Kind    string `json:"kind"`
	Path    string `json:"path"`
}
