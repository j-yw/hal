package loop

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	ManifestFile       string                    `json:"manifestFile"`
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
	if assignment.ManifestFile != "" {
		fmt.Fprintf(&b, "- Manifest file: %s\n", assignment.ManifestFile)
	}
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
	if assignment.ManifestFile != "" {
		fmt.Fprintf(&b, "- Write the worker manifest JSON to `%s`.\n", assignment.ManifestFile)
	}
	fmt.Fprintf(&b, "- Write a worker manifest JSON file with `taskId`, `status`, `branch`, `commit`, `checks`, `filesChanged`, `progressEntry`, `notes`, and `error`.\n")
	fmt.Fprintf(&b, "- Manifest `checks` and `filesChanged` MUST be JSON arrays of strings, not objects.\n")
	fmt.Fprintf(&b, "- Use manifest status `%s` only when the task commit is ready for Hal to integrate serially.\n", WorkerManifestStatusReadyForIntegration)
	fmt.Fprintf(&b, "- Put the progress summary in the manifest `progressEntry`; do not append it to canonical progress.\n")
	fmt.Fprintf(&b, "\nManifest JSON shape:\n\n")
	fmt.Fprintf(&b, "```json\n")
	fmt.Fprintf(&b, "{\n")
	fmt.Fprintf(&b, "  \"taskId\": \"%s\",\n", assignment.TaskID)
	fmt.Fprintf(&b, "  \"status\": \"%s\",\n", WorkerManifestStatusReadyForIntegration)
	fmt.Fprintf(&b, "  \"branch\": \"%s\",\n", assignment.BranchName)
	fmt.Fprintf(&b, "  \"commit\": \"<worker commit sha>\",\n")
	fmt.Fprintf(&b, "  \"checks\": [\"go test ./...\"],\n")
	fmt.Fprintf(&b, "  \"filesChanged\": [\"path/to/changed-file\"],\n")
	fmt.Fprintf(&b, "  \"progressEntry\": \"- %s: implemented assigned task\",\n", assignment.TaskID)
	fmt.Fprintf(&b, "  \"notes\": \"ready for integration\",\n")
	fmt.Fprintf(&b, "  \"error\": \"\"\n")
	fmt.Fprintf(&b, "}\n")
	fmt.Fprintf(&b, "```\n")

	return b.String()
}

// UnmarshalJSON accepts the canonical manifest schema while tolerating common
// real-engine drift for string-list fields.
func (m *WorkerManifest) UnmarshalJSON(data []byte) error {
	var raw struct {
		TaskID        string          `json:"taskId"`
		Status        string          `json:"status"`
		Branch        string          `json:"branch"`
		Commit        string          `json:"commit"`
		Checks        json.RawMessage `json:"checks"`
		FilesChanged  json.RawMessage `json:"filesChanged"`
		ProgressEntry string          `json:"progressEntry"`
		Notes         string          `json:"notes"`
		Error         string          `json:"error"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	checks, err := decodeManifestStringList(raw.Checks, "checks")
	if err != nil {
		return err
	}
	filesChanged, err := decodeManifestStringList(raw.FilesChanged, "filesChanged")
	if err != nil {
		return err
	}

	*m = WorkerManifest{
		TaskID:        raw.TaskID,
		Status:        raw.Status,
		Branch:        raw.Branch,
		Commit:        raw.Commit,
		Checks:        checks,
		FilesChanged:  filesChanged,
		ProgressEntry: raw.ProgressEntry,
		Notes:         raw.Notes,
		Error:         raw.Error,
	}
	return nil
}

func decodeManifestStringList(raw json.RawMessage, field string) ([]string, error) {
	value := strings.TrimSpace(string(raw))
	if value == "" || value == "null" {
		return nil, nil
	}

	var items []string
	if err := json.Unmarshal(raw, &items); err == nil {
		return cleanManifestStringList(items), nil
	}

	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return cleanManifestStringList([]string{single}), nil
	}

	var object map[string]any
	if err := json.Unmarshal(raw, &object); err == nil {
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		items := make([]string, 0, len(keys))
		for _, key := range keys {
			formatted := formatManifestObjectValue(object[key])
			if formatted == "" {
				items = append(items, key)
				continue
			}
			items = append(items, fmt.Sprintf("%s: %s", key, formatted))
		}
		return cleanManifestStringList(items), nil
	}

	return nil, fmt.Errorf("worker manifest %s must be a string, array of strings, or object", field)
}

func cleanManifestStringList(items []string) []string {
	cleaned := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		cleaned = append(cleaned, item)
	}
	return cleaned
}

func formatManifestObjectValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		data, err := json.Marshal(typed)
		if err != nil {
			return fmt.Sprintf("%v", typed)
		}
		return string(data)
	}
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
