package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
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

var liveNegatedRunningTokens = map[string]struct{}{
	"running": {},
	"active":  {},
	"started": {},
	"online":  {},
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
var errLiveStatusUnparseable = errors.New("provider status output did not contain a recognizable live status")

type localStateSyncWarning struct {
	err error
}

type liveStatusResult struct {
	Status string
	IP     string
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

func queryProviderLiveStatus(ctx context.Context, provider sandbox.Provider, info *sandbox.ConnectInfo) (liveStatusResult, error) {
	var out bytes.Buffer
	if err := provider.Status(ctx, info, &out); err != nil {
		return liveStatusResult{Status: sandbox.StatusUnknown}, err
	}
	status, err := normalizeLiveStatus(out.String())
	return liveStatusResult{
		Status: status,
		IP:     parseLiveIP(out.String()),
	}, err
}

func normalizeLiveStatus(output string) (string, error) {
	status := parseLiveStatus(output)
	if status != sandbox.StatusUnknown {
		return status, nil
	}
	return sandbox.StatusUnknown, errLiveStatusUnparseable
}

func parseLiveStatus(output string) string {
	if value := parseSingleValueLiveStatus(output); value != "" {
		return value
	}
	value := parseStructuredLiveStatusValue(output)
	if value == "" {
		return sandbox.StatusUnknown
	}
	return classifyLiveStatusValue(value)
}

func parseSingleValueLiveStatus(output string) string {
	fields := strings.Fields(strings.TrimSpace(output))
	if len(fields) != 1 {
		return ""
	}

	status := classifyLiveStatusValue(fields[0])
	if status == sandbox.StatusUnknown {
		return ""
	}
	return status
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

func parseLiveIP(output string) string {
	lines := strings.Split(output, "\n")
	if value := parseLabeledLiveIP(lines); value != "" {
		return value
	}
	if value := parsePipedLiveIP(lines); value != "" {
		return value
	}
	if value := parseColumnarLiveIP(lines); value != "" {
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
		cells = splitPipeLiveStatusCells(line)
		if len(cells) == 2 && isLiveStatusLabel(normalizeLiveStatusLabel(cells[0])) {
			return cells[1]
		}
	}
	return ""
}

func parseLabeledLiveIP(lines []string) string {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if idx := strings.IndexRune(line, ':'); idx >= 0 {
			if isLiveIPLabel(normalizeLiveStatusLabel(line[:idx])) {
				return extractLiveIPValue(line[idx+1:])
			}
			continue
		}

		cells := splitColumnLiveStatusCells(line)
		if len(cells) == 2 && isLiveIPLabel(normalizeLiveStatusLabel(cells[0])) {
			return extractLiveIPValue(cells[1])
		}
		cells = splitPipeLiveStatusCells(line)
		if len(cells) == 2 && isLiveIPLabel(normalizeLiveStatusLabel(cells[0])) {
			return extractLiveIPValue(cells[1])
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

func parsePipedLiveIP(lines []string) string {
	return parseTabularLiveIP(lines, splitPipeLiveStatusCells)
}

func parseColumnarLiveIP(lines []string) string {
	return parseTabularLiveIP(lines, splitColumnLiveStatusCells)
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

func parseTabularLiveIP(lines []string, split func(string) []string) string {
	for i := 0; i < len(lines); i++ {
		header := split(lines[i])
		ipIndex := liveIPFieldIndex(header)
		if ipIndex == -1 {
			continue
		}

		for j := i + 1; j < len(lines); j++ {
			row := split(lines[j])
			if len(row) == 0 || isLiveStatusDividerRow(row) {
				continue
			}
			if ipIndex < len(row) {
				return extractLiveIPValue(row[ipIndex])
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

func liveIPFieldIndex(cells []string) int {
	for i, cell := range cells {
		if isLiveIPLabel(normalizeLiveStatusLabel(cell)) {
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

func isLiveIPLabel(label string) bool {
	switch label {
	case "ip", "public ip", "public ipv4", "public ipv6", "ipv4", "ipv6":
		return true
	}
	return false
}

func extractLiveIPValue(value string) string {
	tokens := strings.FieldsFunc(value, func(r rune) bool {
		switch r {
		case ',', ';', '|', '[', ']', '(', ')', '{', '}', '<', '>', '"', '\'':
			return true
		}
		return unicode.IsSpace(r)
	})

	for _, token := range tokens {
		if addr, err := netip.ParseAddr(strings.TrimSpace(token)); err == nil {
			return addr.String()
		}
	}
	return ""
}

func classifyLiveStatusValue(value string) string {
	tokens := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})

	if hasNegatedRunningStatus(tokens) {
		return sandbox.StatusStopped
	}

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

func hasNegatedRunningStatus(tokens []string) bool {
	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i] != "not" {
			continue
		}
		if _, ok := liveNegatedRunningTokens[tokens[i+1]]; ok {
			return true
		}
	}
	return false
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
	return persistLiveStatusResult(instance, liveStatusResult{Status: status}, now, write)
}

func persistLiveStatusResult(instance *sandbox.SandboxState, result liveStatusResult, now time.Time, write func(*sandbox.SandboxState) error) error {
	if instance == nil {
		return nil
	}

	previousStatus := instance.Status
	previousStoppedAt := cloneStoppedAt(instance.StoppedAt)
	previousIP := instance.IP
	liveIP := strings.TrimSpace(result.IP)
	updateInstanceStatus(instance, result.Status, now)
	if liveIP != "" {
		instance.IP = liveIP
	} else if shouldClearLiveIP(instance.Status) {
		instance.IP = ""
	}
	if (instance.Status == previousStatus && sameStoppedAt(instance.StoppedAt, previousStoppedAt) && instance.IP == previousIP) || write == nil {
		return nil
	}

	// Build a minimal update carrying only live-query fields so the write
	// target merges them into the current registry entry without overwriting
	// fields that were not part of the live query.
	update := &sandbox.SandboxState{
		Status:    instance.Status,
		StoppedAt: cloneStoppedAt(instance.StoppedAt),
		IP:        liveIP,
	}
	if err := write(update); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		instance.Status = previousStatus
		instance.StoppedAt = previousStoppedAt
		instance.IP = previousIP
		return err
	}
	if err := syncMatchingLocalSandboxState(filepath.Join(".", template.HalDir), instance); err != nil {
		return &localStateSyncWarning{err: err}
	}
	return nil
}

func shouldClearLiveIP(status string) bool {
	return strings.TrimSpace(status) == sandbox.StatusStopped
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
