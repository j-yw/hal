package loop

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WorkerAssignment describes the single PRD task assigned to a parallel worker.
type WorkerAssignment struct {
	TaskID             string                    `json:"taskId"`
	Title              string                    `json:"title"`
	Description        string                    `json:"description"`
	AcceptanceCriteria []string                  `json:"acceptanceCriteria,omitempty"`
	PRDFile            string                    `json:"prdFile"`
	ProgressFile       string                    `json:"progressFile"`
	BaseBranch         string                    `json:"baseBranch"`
	BranchName         string                    `json:"branchName"`
	Scheduling         *WorkerSchedulingMetadata `json:"scheduling,omitempty"`
}

// WorkerSchedulingMetadata carries optional scheduler context for a worker task.
type WorkerSchedulingMetadata struct {
	Priority        int      `json:"priority,omitempty"`
	Index           int      `json:"index,omitempty"`
	Total           int      `json:"total,omitempty"`
	DependsOn       []string `json:"dependsOn,omitempty"`
	ConflictDomains []string `json:"conflictDomains,omitempty"`
	ParallelSafe    *bool    `json:"parallelSafe,omitempty"`
	Barrier         bool     `json:"barrier,omitempty"`
	ParallelReason  string   `json:"parallelReason,omitempty"`
}

// WorkerManifest records the result of a parallel worker's assigned task.
type WorkerManifest struct {
	TaskID        string   `json:"taskId"`
	Status        string   `json:"status"`
	Branch        string   `json:"branch"`
	Commit        string   `json:"commit"`
	Checks        []string `json:"checks"`
	FilesChanged  []string `json:"filesChanged"`
	ProgressEntry string   `json:"progressEntry"`
	Notes         string   `json:"notes"`
	Error         string   `json:"error"`
}

const (
	WorkerManifestStatusReadyForIntegration = "ready_for_integration"
	WorkerManifestStatusFailed              = "failed"
)

// BuildWorkerAssignmentPrompt builds an agent prompt scoped to one assigned task.
func BuildWorkerAssignmentPrompt(assignment WorkerAssignment) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Parallel Worker Assignment\n\n")
	fmt.Fprintf(&b, "Implement only this assigned task. Do not choose the highest-priority task from the PRD.\n\n")
	fmt.Fprintf(&b, "## Task\n\n")
	fmt.Fprintf(&b, "- Task ID: %s\n", assignment.TaskID)
	fmt.Fprintf(&b, "- Title: %s\n", assignment.Title)
	fmt.Fprintf(&b, "- Description: %s\n", assignment.Description)
	fmt.Fprintf(&b, "- PRD file: %s\n", assignment.PRDFile)
	fmt.Fprintf(&b, "- Progress file: %s\n", assignment.ProgressFile)
	fmt.Fprintf(&b, "- Base branch: %s\n", assignment.BaseBranch)
	fmt.Fprintf(&b, "- Worker branch: %s\n", assignment.BranchName)

	if assignment.Scheduling != nil {
		fmt.Fprintf(&b, "\n## Scheduling Metadata\n\n")
		if assignment.Scheduling.Priority != 0 {
			fmt.Fprintf(&b, "- Priority: %d\n", assignment.Scheduling.Priority)
		}
		if assignment.Scheduling.Index != 0 || assignment.Scheduling.Total != 0 {
			fmt.Fprintf(&b, "- Position: %d of %d\n", assignment.Scheduling.Index, assignment.Scheduling.Total)
		}
		if len(assignment.Scheduling.DependsOn) > 0 {
			fmt.Fprintf(&b, "- Depends on: %s\n", strings.Join(assignment.Scheduling.DependsOn, ", "))
		}
		if len(assignment.Scheduling.ConflictDomains) > 0 {
			fmt.Fprintf(&b, "- Conflict domains: %s\n", strings.Join(assignment.Scheduling.ConflictDomains, ", "))
		}
		if assignment.Scheduling.ParallelSafe != nil {
			fmt.Fprintf(&b, "- Parallel safe: %t\n", *assignment.Scheduling.ParallelSafe)
		}
		if assignment.Scheduling.Barrier {
			fmt.Fprintf(&b, "- Barrier task: true\n")
		}
		if assignment.Scheduling.ParallelReason != "" {
			fmt.Fprintf(&b, "- Parallel reason: %s\n", assignment.Scheduling.ParallelReason)
		}
	}

	if len(assignment.AcceptanceCriteria) > 0 {
		fmt.Fprintf(&b, "\n## Acceptance Criteria\n\n")
		for _, criterion := range assignment.AcceptanceCriteria {
			fmt.Fprintf(&b, "- %s\n", criterion)
		}
	}

	fmt.Fprintf(&b, "\n## Guardrails\n\n")
	fmt.Fprintf(&b, "- Implement only task `%s`; do not work ahead or pick another pending task.\n", assignment.TaskID)
	fmt.Fprintf(&b, "- Do not edit canonical `.hal/prd.json`.\n")
	fmt.Fprintf(&b, "- Do not append canonical `.hal/progress.txt`.\n")
	fmt.Fprintf(&b, "- Use the assigned PRD and progress file listed above as read-only task context unless your runner provides writable worker-specific copies.\n")
	fmt.Fprintf(&b, "- Commit implementation changes on branch `%s` when the task is done.\n", assignment.BranchName)
	fmt.Fprintf(&b, "- Write a worker manifest JSON file with `taskId`, `status`, `branch`, `commit`, `checks`, `filesChanged`, `progressEntry`, `notes`, and `error`.\n")
	fmt.Fprintf(&b, "- Use manifest status `%s` only when the task commit is ready for Hal to integrate serially.\n", WorkerManifestStatusReadyForIntegration)
	fmt.Fprintf(&b, "- Put the progress summary in the manifest `progressEntry`; do not append it to canonical progress.\n")

	return b.String()
}

// ReadWorkerManifest reads a worker manifest JSON file from path.
func ReadWorkerManifest(path string) (*WorkerManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var manifest WorkerManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

// WriteWorkerManifest writes a worker manifest JSON file through a temp file and rename.
func WriteWorkerManifest(path string, manifest WorkerManifest) error {
	if path == "" {
		return fmt.Errorf("worker manifest path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	base := filepath.Base(path)
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+base+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()

	encoder := json.NewEncoder(tmp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(manifest); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	removeTemp = false
	return nil
}
