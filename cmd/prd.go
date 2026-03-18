package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var prdAuditJSONFlag bool

// PRDAuditResult is the machine-readable output of hal prd audit --json.
type PRDAuditResult struct {
	ContractVersion int        `json:"contractVersion"`
	OK              bool       `json:"ok"`
	JSONPath        string     `json:"jsonPath,omitempty"`
	MarkdownPath    string     `json:"markdownPath,omitempty"`
	JSONExists      bool       `json:"jsonExists"`
	MarkdownExists  bool       `json:"markdownExists"`
	Issues          []string   `json:"issues,omitempty"`
	PRDSummary      *PRDInfo   `json:"prd,omitempty"`
	Summary         string     `json:"summary"`
}

// PRDInfo provides basic PRD metadata.
type PRDInfo struct {
	Project     string `json:"project,omitempty"`
	BranchName  string `json:"branchName,omitempty"`
	TotalStories int   `json:"totalStories"`
	CompletedStories int `json:"completedStories"`
}

var prdCmd = &cobra.Command{
	Use:   "prd",
	Short: "Manage PRD files",
	Long: `Inspect and manage Product Requirements Document files.

Use 'hal prd audit' to check PRD health and detect drift.`,
	Example: `  hal prd audit
  hal prd audit --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var prdAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit PRD health and detect drift",
	Args:  noArgsValidation(),
	Long: `Audit PRD files for health issues and drift.

Checks:
  - Whether prd.json exists and is valid JSON
  - Whether markdown PRD files exist
  - Whether prd.json has stories/userStories
  - Story completion status
  - Whether both markdown and JSON exist (potential drift)

Use --json for machine-readable output.`,
	Example: `  hal prd audit
  hal prd audit --json`,
	RunE: runPRDAudit,
}

func init() {
	prdAuditCmd.Flags().BoolVar(&prdAuditJSONFlag, "json", false, "Output machine-readable JSON result")
	prdCmd.AddCommand(prdAuditCmd)
	rootCmd.AddCommand(prdCmd)
}

func runPRDAudit(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	jsonMode := prdAuditJSONFlag
	if cmd != nil {
		out = cmd.OutOrStdout()
		if cmd.Flags().Lookup("json") != nil {
			v, _ := cmd.Flags().GetBool("json")
			jsonMode = v
		}
	}
	return runPRDAuditFn(".", jsonMode, out)
}

func runPRDAuditFn(dir string, jsonMode bool, out io.Writer) error {
	halDir := filepath.Join(dir, template.HalDir)
	jsonPath := filepath.Join(halDir, template.PRDFile)
	var issues []string
	var prdInfo *PRDInfo

	// Check JSON PRD
	jsonExists := false
	jsonData, err := os.ReadFile(jsonPath)
	if err == nil {
		jsonExists = true

		var prd engine.PRD
		if err := json.Unmarshal(jsonData, &prd); err != nil {
			issues = append(issues, "prd.json contains invalid JSON: "+err.Error())
		} else {
			completed, total := prd.Progress()
			prdInfo = &PRDInfo{
				Project:          prd.Project,
				BranchName:       prd.BranchName,
				TotalStories:     total,
				CompletedStories: completed,
			}

			if total == 0 {
				issues = append(issues, "prd.json has no stories")
			}
			if prd.BranchName == "" {
				issues = append(issues, "prd.json is missing branchName")
			}
		}
	}

	// Check markdown PRDs
	markdownPath := ""
	markdownExists := false
	matches, _ := filepath.Glob(filepath.Join(halDir, "prd-*.md"))
	if len(matches) > 0 {
		markdownExists = true
		markdownPath = matches[len(matches)-1] // newest by name
		rel, err := filepath.Rel(dir, markdownPath)
		if err == nil {
			markdownPath = rel
		}
	}

	// Drift detection
	if jsonExists && markdownExists {
		issues = append(issues, "both prd.json and markdown PRD exist — potential drift. Consider archiving one.")
	}
	if !jsonExists && !markdownExists {
		issues = append(issues, "no PRD files found. Run hal plan or create a PRD manually.")
	}

	ok := len(issues) == 0

	summary := "PRD is healthy."
	if !ok {
		parts := make([]string, len(issues))
		copy(parts, issues)
		summary = strings.Join(parts, "; ")
	}

	result := PRDAuditResult{
		ContractVersion: 1,
		OK:              ok,
		JSONPath:        filepath.Join(template.HalDir, template.PRDFile),
		MarkdownPath:    markdownPath,
		JSONExists:      jsonExists,
		MarkdownExists:  markdownExists,
		Issues:          issues,
		PRDSummary:      prdInfo,
		Summary:         summary,
	}

	if jsonMode {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal audit result: %w", err)
		}
		fmt.Fprintln(out, string(data))
		return nil
	}

	// Human-readable
	if jsonExists {
		fmt.Fprintln(out, "JSON PRD:     ✓ "+filepath.Join(template.HalDir, template.PRDFile))
		if prdInfo != nil {
			fmt.Fprintf(out, "  Project:    %s\n", prdInfo.Project)
			fmt.Fprintf(out, "  Branch:     %s\n", prdInfo.BranchName)
			fmt.Fprintf(out, "  Stories:    %d/%d complete\n", prdInfo.CompletedStories, prdInfo.TotalStories)
		}
	} else {
		fmt.Fprintln(out, "JSON PRD:     ✗ not found")
	}

	if markdownExists {
		fmt.Fprintf(out, "Markdown PRD: ✓ %s\n", markdownPath)
	} else {
		fmt.Fprintln(out, "Markdown PRD: ✗ not found")
	}

	fmt.Fprintln(out)
	if ok {
		fmt.Fprintln(out, "PRD is healthy.")
	} else {
		fmt.Fprintln(out, "Issues:")
		for _, issue := range issues {
			fmt.Fprintf(out, "  ⚠ %s\n", issue)
		}
	}

	return nil
}
