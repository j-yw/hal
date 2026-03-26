package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
)

var liveRunningTokens = map[string]struct{}{
	"running": {},
	"active":  {},
	"started": {},
	"online":  {},
	"ready":   {},
}

var liveStoppedTokens = map[string]struct{}{
	"stopped":  {},
	"off":      {},
	"inactive": {},
	"halted":   {},
	"shutdown": {},
	"shutoff":  {},
}

var liveColumnSplitPattern = regexp.MustCompile(`\s{2,}`)

type localStateSyncWarning struct {
	err error
}

func (w *localStateSyncWarning) Error() string {
	if w == nil || w.err == nil {
		return ""
	}
	return w.err.Error()
}

func (w *localStateSyncWarning) Unwrap() error {
	if w == nil {
		return nil
	}
	return w.err
}

func asLocalStateSyncWarning(err error) (*localStateSyncWarning, bool) {
	var warning *localStateSyncWarning
	if errors.As(err, &warning) {
		return warning, true
	}
	return nil, false
}

func formatLocalStateSyncWarning(err error) string {
	if warning, ok := asLocalStateSyncWarning(err); ok {
		return fmt.Sprintf("local sandbox state sync failed: %v", warning.Unwrap())
	}
	return err.Error()
}

func formatLiveStatusWarning(name string, err error) string {
	if warning, ok := asLocalStateSyncWarning(err); ok {
		return fmt.Sprintf("warning: local sandbox state sync failed for %q: %v\n", name, warning.Unwrap())
	}
	return fmt.Sprintf("warning: live status lookup failed for %q: %v\n", name, err)
}

func queryProviderLiveStatus(ctx context.Context, provider sandbox.Provider, info *sandbox.ConnectInfo, fallback string) (string, error) {
	var out bytes.Buffer
	if err := provider.Status(ctx, info, &out); err != nil {
		return sandbox.StatusUnknown, err
	}
	return normalizeLiveStatus(out.String(), fallback), nil
}

func normalizeLiveStatus(output, fallback string) string {
	status := parseLiveStatus(output)
	if status != sandbox.StatusUnknown {
		return status
	}
	switch strings.TrimSpace(strings.ToLower(fallback)) {
	case sandbox.StatusRunning, sandbox.StatusStopped, sandbox.StatusUnknown:
		return strings.TrimSpace(strings.ToLower(fallback))
	default:
		return sandbox.StatusUnknown
	}
}

func parseLiveStatus(output string) string {
	value := parseStructuredLiveStatusValue(output)
	if value == "" {
		return sandbox.StatusUnknown
	}
	return classifyLiveStatusValue(value)
}

func parseStructuredLiveStatusValue(output string) string {
	lines := strings.Split(output, "\n")
	if value := parseLabeledLiveStatus(lines); value != "" {
		return value
	}
	if value := parsePipedLiveStatus(lines); value != "" {
		return value
	}
	if value := parseColumnarLiveStatus(lines); value != "" {
		return value
	}
	return ""
}

func parseLabeledLiveStatus(lines []string) string {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if idx := strings.IndexRune(line, ':'); idx >= 0 {
			if isLiveStatusLabel(normalizeLiveStatusLabel(line[:idx])) {
				return strings.TrimSpace(line[idx+1:])
			}
			continue
		}

		cells := splitColumnLiveStatusCells(line)
		if len(cells) == 2 && isLiveStatusLabel(normalizeLiveStatusLabel(cells[0])) {
			return cells[1]
		}
	}
	return ""
}

func parsePipedLiveStatus(lines []string) string {
	return parseTabularLiveStatus(lines, splitPipeLiveStatusCells)
}

func parseColumnarLiveStatus(lines []string) string {
	return parseTabularLiveStatus(lines, splitColumnLiveStatusCells)
}

func parseTabularLiveStatus(lines []string, split func(string) []string) string {
	for i := 0; i < len(lines); i++ {
		header := split(lines[i])
		statusIndex := liveStatusFieldIndex(header)
		if statusIndex == -1 {
			continue
		}

		for j := i + 1; j < len(lines); j++ {
			row := split(lines[j])
			if len(row) == 0 || isLiveStatusDividerRow(row) {
				continue
			}
			if statusIndex < len(row) {
				return strings.TrimSpace(row[statusIndex])
			}
			return ""
		}
	}
	return ""
}

func splitPipeLiveStatusCells(line string) []string {
	if !strings.Contains(line, "|") {
		return nil
	}
	line = strings.TrimSpace(strings.Trim(line, "|"))
	if line == "" {
		return nil
	}

	raw := strings.Split(line, "|")
	cells := make([]string, 0, len(raw))
	for _, cell := range raw {
		cells = append(cells, strings.TrimSpace(cell))
	}
	return cells
}

func splitColumnLiveStatusCells(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" || strings.Contains(line, "|") || !liveColumnSplitPattern.MatchString(line) {
		return nil
	}

	cells := liveColumnSplitPattern.Split(line, -1)
	for i := range cells {
		cells[i] = strings.TrimSpace(cells[i])
	}
	return cells
}

func liveStatusFieldIndex(cells []string) int {
	for i, cell := range cells {
		if isLiveStatusLabel(normalizeLiveStatusLabel(cell)) {
			return i
		}
	}
	return -1
}

func isLiveStatusDividerRow(cells []string) bool {
	if len(cells) == 0 {
		return true
	}
	for _, cell := range cells {
		if strings.Trim(cell, "-=+ ") != "" {
			return false
		}
	}
	return true
}

func normalizeLiveStatusLabel(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "_", " ")
	return strings.Join(strings.Fields(value), " ")
}

func isLiveStatusLabel(label string) bool {
	switch label {
	case "status", "state":
		return true
	}
	return strings.HasSuffix(label, " status") || strings.HasSuffix(label, " state")
}

func classifyLiveStatusValue(value string) string {
	tokens := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})

	hasStopped := hasAnyStatusToken(tokens, liveStoppedTokens)
	hasRunning := hasAnyStatusToken(tokens, liveRunningTokens)

	switch {
	case hasStopped && !hasRunning:
		return sandbox.StatusStopped
	case hasRunning && !hasStopped:
		return sandbox.StatusRunning
	default:
		return sandbox.StatusUnknown
	}
}

func hasAnyStatusToken(tokens []string, candidates map[string]struct{}) bool {
	for _, token := range tokens {
		if _, ok := candidates[token]; ok {
			return true
		}
	}
	return false
}

func persistLiveStatus(instance *sandbox.SandboxState, status string, now time.Time, write func(*sandbox.SandboxState) error) error {
	if instance == nil {
		return nil
	}

	previousStatus := instance.Status
	previousStoppedAt := cloneStoppedAt(instance.StoppedAt)
	updateInstanceStatus(instance, status, now)
	if (instance.Status == previousStatus && sameStoppedAt(instance.StoppedAt, previousStoppedAt)) || write == nil {
		return nil
	}

	if err := write(instance); err != nil {
		instance.Status = previousStatus
		instance.StoppedAt = previousStoppedAt
		return err
	}
	if err := syncMatchingLocalSandboxState(filepath.Join(".", template.HalDir), instance); err != nil {
		return &localStateSyncWarning{err: err}
	}
	return nil
}

func cloneStoppedAt(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func sameStoppedAt(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}
