package cmd

import (
	"bytes"
	"context"
	"strings"
	"unicode"

	"github.com/jywlabs/hal/internal/sandbox"
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
	tokens := strings.FieldsFunc(strings.ToLower(output), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})
	if hasAnyStatusToken(tokens, liveStoppedTokens) {
		return sandbox.StatusStopped
	}
	if hasAnyStatusToken(tokens, liveRunningTokens) {
		return sandbox.StatusRunning
	}
	return sandbox.StatusUnknown
}

func hasAnyStatusToken(tokens []string, candidates map[string]struct{}) bool {
	for _, token := range tokens {
		if _, ok := candidates[token]; ok {
			return true
		}
	}
	return false
}
