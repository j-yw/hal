package prd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/skills"
	"github.com/jywlabs/hal/internal/template"
)

// RepairValidationWithEngine applies validation-guided fixes directly to PRD artifacts.
//
// The engine is instructed to edit files in place so the next validation attempt can
// re-check updated content without regenerating from scratch.
func RepairValidationWithEngine(ctx context.Context, eng engine.Engine, mdPath, prdPath string, validation *ValidationResult, display *engine.Display) error {
	if eng == nil {
		return fmt.Errorf("repair validation requires a non-nil engine")
	}

	prdPath = strings.TrimSpace(prdPath)
	if prdPath == "" {
		return fmt.Errorf("repair validation requires a non-empty runtime prd path")
	}

	if validation == nil {
		return fmt.Errorf("repair validation requires validation feedback")
	}

	halSkill, err := skills.LoadSkill("hal")
	if err != nil {
		return fmt.Errorf("failed to load hal skill: %w", err)
	}

	mdPath = strings.TrimSpace(mdPath)
	paths := []string{prdPath}
	if mdPath != "" {
		paths = append(paths, mdPath)
	}

	before, err := captureRepairSnapshots(paths...)
	if err != nil {
		return err
	}

	prompt, err := buildValidationRepairPrompt(halSkill, mdPath, prdPath, validation)
	if err != nil {
		return err
	}

	if display != nil {
		_, err = eng.StreamPrompt(ctx, prompt, display)
	} else {
		_, err = eng.Prompt(ctx, prompt)
	}
	if err != nil {
		if engine.RequiresOutputFallback(err) {
			changed, changeErr := repairFilesChanged(before)
			if changeErr != nil {
				return fmt.Errorf("repair prompt failed: %w (and failed to inspect file changes: %v)", err, changeErr)
			}
			if changed {
				return nil
			}
		}
		return fmt.Errorf("repair prompt failed: %w", err)
	}

	return nil
}

type repairSnapshot struct {
	exists bool
	data   []byte
}

func captureRepairSnapshots(paths ...string) (map[string]repairSnapshot, error) {
	snapshots := make(map[string]repairSnapshot, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				snapshots[path] = repairSnapshot{exists: false}
				continue
			}
			return nil, fmt.Errorf("failed to inspect %s before repair: %w", path, err)
		}

		snapshots[path] = repairSnapshot{exists: true, data: data}
	}

	return snapshots, nil
}

func repairFilesChanged(before map[string]repairSnapshot) (bool, error) {
	for path, prev := range before {
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			if !prev.exists {
				return true, nil
			}
			if !bytes.Equal(prev.data, data) {
				return true, nil
			}
		case os.IsNotExist(err):
			if prev.exists {
				return true, nil
			}
		default:
			return false, fmt.Errorf("failed to inspect %s after repair: %w", path, err)
		}
	}

	return false, nil
}

func buildValidationRepairPrompt(skill, mdPath, prdPath string, validation *ValidationResult) (string, error) {
	feedback, err := json.MarshalIndent(validation, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to encode validation feedback: %w", err)
	}

	markdownInstruction := "- Source markdown PRD: not available (repair runtime JSON only)"
	if mdPath != "" {
		markdownInstruction = fmt.Sprintf("- Source markdown PRD: %s (keep aligned with runtime JSON)", mdPath)
	}

	return fmt.Sprintf(`You are a PRD repair agent. Apply validation feedback by editing PRD files in place.

<skill>
%s
</skill>

Validation feedback JSON:
<validation>
%s
</validation>

Files to update:
%s
- Runtime PRD JSON: %s

Repair requirements:
1. Resolve every validation error in the feedback JSON.
2. Keep existing intent and branchName stable unless feedback explicitly requires a correction.
3. Ensure stories/tasks remain dependency-ordered and each is completable in one iteration.
4. Ensure each story has "Typecheck passes" and UI stories include "%s".
5. Keep markdown and JSON consistent when markdown source is available.
6. Apply edits directly to files using tools.

After finishing edits, respond with a single line: REPAIRED`, skill, string(feedback), markdownInstruction, prdPath, template.BrowserVerificationCriterion), nil
}
