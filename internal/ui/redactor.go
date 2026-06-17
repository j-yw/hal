package ui

import (
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const (
	addressPlaceholder = "<address redacted>"
	secretPlaceholder  = "<secret redacted>"
	redactionTailBytes = 4096
)

var (
	ipv4Candidate = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Candidate = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}(?:%[A-Za-z0-9_.-]+)?\b`)
)

// Redactor removes sensitive values from human-facing streams.
type Redactor struct {
	ShowAddresses  bool
	KnownAddresses []string
	KnownSecrets   []string
}

// Redact sanitizes text for human output.
func (r Redactor) Redact(text string) string {
	if text == "" {
		return ""
	}

	for _, secret := range sortedNonEmpty(r.KnownSecrets) {
		text = strings.ReplaceAll(text, secret, secretPlaceholder)
	}

	if !r.ShowAddresses {
		for _, address := range sortedNonEmpty(r.KnownAddresses) {
			text = strings.ReplaceAll(text, address, addressPlaceholder)
		}
		text = redactIPCandidates(text, ipv4Candidate)
		text = redactIPCandidates(text, ipv6Candidate)
	}

	return text
}

func sortedNonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) == len(out[j]) {
			return out[i] < out[j]
		}
		return len(out[i]) > len(out[j])
	})
	return out
}

func redactIPCandidates(text string, pattern *regexp.Regexp) string {
	return pattern.ReplaceAllStringFunc(text, func(candidate string) string {
		trimmed := strings.Trim(candidate, "[]")
		if _, err := netip.ParseAddr(trimmed); err != nil {
			return candidate
		}
		return addressPlaceholder
	})
}

// RedactingWriter sanitizes complete lines as they are written. Call Flush at
// operation boundaries to emit any trailing partial line.
type RedactingWriter struct {
	mu       sync.Mutex
	dst      io.Writer
	redactor Redactor
	pending  string
}

func NewRedactingWriter(dst io.Writer, redactor Redactor) *RedactingWriter {
	return &RedactingWriter{dst: dst, redactor: redactor}
}

func (w *RedactingWriter) Write(p []byte) (int, error) {
	if w == nil || w.dst == nil {
		return len(p), nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.pending += string(p)
	if err := w.flushCompleteLinesLocked(); err != nil {
		return 0, err
	}
	if len(w.pending) > redactionTailBytes {
		flushLen := len(w.pending) - redactionTailBytes
		if _, err := io.WriteString(w.dst, w.redactor.Redact(w.pending[:flushLen])); err != nil {
			return 0, err
		}
		w.pending = w.pending[flushLen:]
	}

	return len(p), nil
}

func (w *RedactingWriter) Flush() error {
	if w == nil || w.dst == nil {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.flushCompleteLinesLocked(); err != nil {
		return err
	}
	if w.pending == "" {
		return nil
	}
	if _, err := io.WriteString(w.dst, w.redactor.Redact(w.pending)); err != nil {
		return err
	}
	w.pending = ""
	return nil
}

func (w *RedactingWriter) flushCompleteLinesLocked() error {
	for {
		idx := strings.IndexByte(w.pending, '\n')
		if idx < 0 {
			return nil
		}
		line := w.pending[:idx+1]
		if _, err := io.WriteString(w.dst, w.redactor.Redact(line)); err != nil {
			return err
		}
		w.pending = w.pending[idx+1:]
	}
}

var _ io.Writer = (*RedactingWriter)(nil)
