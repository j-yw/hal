// Package status implements workflow state classification for hal.
//
// The Status function inspects .hal/ artifacts and returns a structured
// StatusResult that tells agents and humans:
//   - what workflow track is active (manual, auto, review_loop, unknown)
//   - what state the workflow is in
//   - which artifacts exist
//   - what the next recommended action is
package status

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jywlabs/hal/internal/template"
)

// ContractVersion is the current version of the status contract.
const ContractVersion = 1

// Workflow track values.
const (
	TrackManual = "manual"
	TrackAuto   = "auto"
	// TrackCompound is a legacy alias retained for compatibility.
	TrackCompound   = TrackAuto
	TrackReviewLoop = "review_loop"
	TrackUnknown    = "unknown"
)

// State values.
const (
	StateNotInitialized   = "not_initialized"
	StateInitializedNoPRD = "hal_initialized_no_prd"
	StateManualInProgress = "manual_in_progress"
	StateManualComplete   = "manual_complete"
	StateAutoActive       = "auto_active"
	StateAutoInactive     = "auto_inactive"
	// Legacy aliases retained for compatibility.
	StateCompoundActive     = StateAutoActive
	StateCompoundComplete   = StateAutoInactive
	StateReviewLoopComplete = "review_loop_complete"
)

// NextAction IDs.
const (
	ActionRunInit    = "run_init"
	ActionRunPlan    = "run_plan"
	ActionRunManual  = "run_manual"
	ActionRunReport  = "run_report"
	ActionResumeAuto = "resume_auto"
	ActionRunAuto    = "run_auto"
)

// StatusResult is the v1 machine-readable status contract.
type StatusResult struct {
	ContractVersion int        `json:"contractVersion"`
	WorkflowTrack   string     `json:"workflowTrack"`
	State           string     `json:"state"`
	Artifacts       Artifacts  `json:"artifacts"`
	NextAction      NextAction `json:"nextAction"`
	Summary         string     `json:"summary"`
	// Optional detail fields (additive, omitempty for backward compat)
	Manual     *ManualDetail     `json:"manual,omitempty"`
	Compound   *CompoundDetail   `json:"compound,omitempty"`
	ReviewLoop *ReviewLoopDetail `json:"reviewLoop,omitempty"`
	Paths      *StatusPaths      `json:"paths,omitempty"`
}

// ManualDetail provides story-level detail for manual workflows.
type ManualDetail struct {
	BranchName       string    `json:"branchName,omitempty"`
	TotalStories     int       `json:"totalStories"`
	CompletedStories int       `json:"completedStories"`
	NextStory        *StoryRef `json:"nextStory,omitempty"`
}

// StoryRef identifies a single story.
type StoryRef struct {
	ID    string `json:"id"`
	Title string `json:"title,omitempty"`
}

// CompoundDetail provides pipeline-level detail for auto workflows.
// Field name remains "compound" for contract compatibility.
type CompoundDetail struct {
	Step       string `json:"step,omitempty"`
	BranchName string `json:"branchName,omitempty"`
}

// ReviewLoopDetail provides review-loop detail.
type ReviewLoopDetail struct {
	LatestReport string `json:"latestReport,omitempty"`
}

// StatusPaths lists canonical file paths relevant to the current state.
type StatusPaths struct {
	PRDJson   string `json:"prdJson,omitempty"`
	AutoState string `json:"autoState,omitempty"`
}

// Artifacts describes which .hal/ files exist.
type Artifacts struct {
	HalDir          bool `json:"halDir"`
	MarkdownPRD     bool `json:"markdownPRD"`
	JSONPRD         bool `json:"jsonPRD"`
	ProgressFile    bool `json:"progressFile"`
	ReportAvailable bool `json:"reportAvailable"`
	AutoState       bool `json:"autoState"`
}

// NextAction recommends what the user/agent should do next.
type NextAction struct {
	ID          string `json:"id"`
	Command     string `json:"command"`
	Description string `json:"description"`
}

// prdJSON is the minimal structure to read pass/fail from prd.json.
type prdJSON struct {
	BranchName string     `json:"branchName"`
	Stories    []prdStory `json:"stories"`
	// Also accept "userStories" key used by some PRD formats
	UserStories []prdStory `json:"userStories"`
}

func (p *prdJSON) allStories() []prdStory {
	if len(p.Stories) > 0 {
		return p.Stories
	}
	return p.UserStories
}

type prdStory struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
}

// Get inspects the filesystem at dir (project root) and returns the current workflow status.
func Get(dir string) StatusResult {
	halDir := filepath.Join(dir, template.HalDir)

	artifacts := detectArtifacts(dir, halDir)

	if !artifacts.HalDir {
		return StatusResult{
			ContractVersion: ContractVersion,
			WorkflowTrack:   TrackUnknown,
			State:           StateNotInitialized,
			Artifacts:       artifacts,
			NextAction: NextAction{
				ID:          ActionRunInit,
				Command:     "hal init",
				Description: "Initialize .hal/ directory.",
			},
			Summary: "Hal is not initialized. Run hal init.",
		}
	}

	// Check auto state first (higher precedence).
	if artifacts.AutoState {
		return classifyAuto(halDir, artifacts)
	}

	// Check for review-loop reports when no PRD exists (review-only workflow)
	if !artifacts.JSONPRD {
		if latestReview := findLatestReviewLoopReport(halDir); latestReview != "" {
			return StatusResult{
				ContractVersion: ContractVersion,
				WorkflowTrack:   TrackReviewLoop,
				State:           StateReviewLoopComplete,
				Artifacts:       artifacts,
				NextAction: NextAction{
					ID:          ActionRunPlan,
					Command:     "hal plan",
					Description: "Review loop completed. Create a PRD for new work, or run another review.",
				},
				ReviewLoop: &ReviewLoopDetail{
					LatestReport: latestReview,
				},
				Summary: "Review loop completed; latest report available.",
			}
		}
	}

	// Manual workflow
	if !artifacts.JSONPRD {
		// If there's a markdown PRD but no JSON, suggest convert
		if artifacts.MarkdownPRD {
			return StatusResult{
				ContractVersion: ContractVersion,
				WorkflowTrack:   TrackManual,
				State:           StateInitializedNoPRD,
				Artifacts:       artifacts,
				NextAction: NextAction{
					ID:          "run_convert",
					Command:     "hal convert",
					Description: "Convert your markdown PRD to JSON for execution.",
				},
				Summary: "Markdown PRD found but no prd.json. Run hal convert.",
			}
		}
		return StatusResult{
			ContractVersion: ContractVersion,
			WorkflowTrack:   TrackManual,
			State:           StateInitializedNoPRD,
			Artifacts:       artifacts,
			NextAction: NextAction{
				ID:          ActionRunPlan,
				Command:     "hal plan",
				Description: "Create a PRD for the next piece of work.",
			},
			Summary: "Hal is initialized, but there is no PRD yet.",
		}
	}

	return classifyManual(dir, halDir, artifacts)
}

func detectArtifacts(dir, halDir string) Artifacts {
	a := Artifacts{}

	if info, err := os.Stat(halDir); err == nil && info.IsDir() {
		a.HalDir = true
	}

	// Check markdown PRDs (prd-*.md pattern)
	matches, _ := filepath.Glob(filepath.Join(halDir, "prd-*.md"))
	a.MarkdownPRD = len(matches) > 0

	if _, err := os.Stat(filepath.Join(halDir, template.PRDFile)); err == nil {
		a.JSONPRD = true
	}

	if _, err := os.Stat(filepath.Join(halDir, template.ProgressFile)); err == nil {
		a.ProgressFile = true
	}

	// Check for reports
	reportsDir := filepath.Join(halDir, "reports")
	if entries, err := os.ReadDir(reportsDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && e.Name() != ".gitkeep" {
				a.ReportAvailable = true
				break
			}
		}
	}

	if _, err := os.Stat(filepath.Join(halDir, template.AutoStateFile)); err == nil {
		a.AutoState = true
	}

	return a
}

// findLatestReviewLoopReport returns the path of the newest review-loop-*.json
// report, or empty string if none found.
func findLatestReviewLoopReport(halDir string) string {
	reportsDir := filepath.Join(halDir, "reports")
	matches, err := filepath.Glob(filepath.Join(reportsDir, "review-loop-*.json"))
	if err != nil || len(matches) == 0 {
		return ""
	}
	// Sort descending to get newest first (timestamp in name)
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	// Return relative path
	rel, err := filepath.Rel(filepath.Dir(halDir), matches[0])
	if err != nil {
		return matches[0]
	}
	return rel
}

func classifyManual(dir, halDir string, artifacts Artifacts) StatusResult {
	prdRelPath := filepath.Join(template.HalDir, template.PRDFile)
	prdPath := filepath.Join(halDir, template.PRDFile)

	// Check if there's also a review-loop report (supplementary)
	var reviewLoop *ReviewLoopDetail
	if latest := findLatestReviewLoopReport(halDir); latest != "" {
		reviewLoop = &ReviewLoopDetail{LatestReport: latest}
	}
	data, err := os.ReadFile(prdPath)
	if err != nil {
		return StatusResult{
			ContractVersion: ContractVersion,
			WorkflowTrack:   TrackManual,
			State:           StateManualInProgress,
			Artifacts:       artifacts,
			NextAction: NextAction{
				ID:          ActionRunManual,
				Command:     "hal run",
				Description: "Execute the remaining PRD stories.",
			},
			Paths:   &StatusPaths{PRDJson: prdRelPath},
			Summary: "Manual workflow is in progress.",
		}
	}

	var prd prdJSON
	if err := json.Unmarshal(data, &prd); err != nil {
		return StatusResult{
			ContractVersion: ContractVersion,
			WorkflowTrack:   TrackManual,
			State:           StateManualInProgress,
			Artifacts:       artifacts,
			NextAction: NextAction{
				ID:          ActionRunManual,
				Command:     "hal run",
				Description: "Execute the remaining PRD stories.",
			},
			Paths:   &StatusPaths{PRDJson: prdRelPath},
			Summary: "Manual workflow is in progress.",
		}
	}

	stories := prd.allStories()
	total := len(stories)
	completed := 0
	var nextStory *StoryRef
	for _, s := range stories {
		if s.Status == "passed" {
			completed++
		} else if nextStory == nil {
			nextStory = &StoryRef{ID: s.ID, Title: s.Title}
		}
	}

	manual := &ManualDetail{
		BranchName:       prd.BranchName,
		TotalStories:     total,
		CompletedStories: completed,
		NextStory:        nextStory,
	}
	paths := &StatusPaths{PRDJson: prdRelPath}

	if total > 0 && completed >= total {
		nextAction := NextAction{
			ID:          ActionRunReport,
			Command:     "hal report",
			Description: "Generate a report for the completed manual work.",
		}
		summary := fmt.Sprintf("Manual workflow is complete (%d/%d stories); generate a report.", completed, total)
		// If reports already exist, suggest auto pipeline
		if artifacts.ReportAvailable {
			nextAction = NextAction{
				ID:          ActionRunAuto,
				Command:     "hal auto",
				Description: "Start the auto pipeline from the latest report.",
			}
			summary = fmt.Sprintf("Manual workflow is complete (%d/%d stories); report available, ready for auto pipeline.", completed, total)
		}
		return StatusResult{
			ContractVersion: ContractVersion,
			WorkflowTrack:   TrackManual,
			State:           StateManualComplete,
			Artifacts:       artifacts,
			NextAction:      nextAction,
			Manual:          manual,
			ReviewLoop:      reviewLoop,
			Paths:           paths,
			Summary:         summary,
		}
	}

	return StatusResult{
		ContractVersion: ContractVersion,
		WorkflowTrack:   TrackManual,
		State:           StateManualInProgress,
		Artifacts:       artifacts,
		NextAction: NextAction{
			ID:          ActionRunManual,
			Command:     "hal run",
			Description: "Continue executing the remaining PRD stories.",
		},
		Manual:     manual,
		ReviewLoop: reviewLoop,
		Paths:      paths,
		Summary:    fmt.Sprintf("Manual workflow in progress (%d/%d stories complete).", completed, total),
	}
}

func classifyAuto(halDir string, artifacts Artifacts) StatusResult {
	autoStatePath := filepath.Join(halDir, template.AutoStateFile)

	var compound *CompoundDetail
	autoActive := true
	if data, err := os.ReadFile(autoStatePath); err == nil {
		var state struct {
			Step       string `json:"step"`
			BranchName string `json:"branchName"`
		}
		if json.Unmarshal(data, &state) == nil {
			normalizedStep := normalizeAutoStep(state.Step)
			compound = &CompoundDetail{
				Step:       normalizedStep,
				BranchName: state.BranchName,
			}
			autoActive = normalizedStep != "done"
		}
	}

	paths := &StatusPaths{AutoState: filepath.Join(template.HalDir, template.AutoStateFile)}

	if !autoActive {
		return StatusResult{
			ContractVersion: ContractVersion,
			WorkflowTrack:   TrackAuto,
			State:           StateAutoInactive,
			Artifacts:       artifacts,
			NextAction: NextAction{
				ID:          ActionRunAuto,
				Command:     "hal auto",
				Description: "Start a new auto pipeline run.",
			},
			Compound: compound,
			Paths:    paths,
			Summary:  "Auto pipeline is inactive; start a new run with hal auto.",
		}
	}

	return StatusResult{
		ContractVersion: ContractVersion,
		WorkflowTrack:   TrackAuto,
		State:           StateAutoActive,
		Artifacts:       artifacts,
		NextAction: NextAction{
			ID:          ActionResumeAuto,
			Command:     "hal auto --resume",
			Description: "Resume the saved auto pipeline state.",
		},
		Compound: compound,
		Paths:    paths,
		Summary:  "Auto pipeline is active; resume with hal auto --resume.",
	}
}

func normalizeAutoStep(step string) string {
	switch strings.TrimSpace(step) {
	case "prd":
		return "spec"
	case "explode":
		return "convert"
	case "loop":
		return "run"
	case "pr":
		return "ci"
	default:
		return strings.TrimSpace(step)
	}
}
