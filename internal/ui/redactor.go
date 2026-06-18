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
		if !validIPCandidate(candidate) {
			return candidate
		}
		return addressPlaceholder
	})
}

func validIPCandidate(candidate string) bool {
	trimmed := strings.Trim(candidate, "[]")
	_, err := netip.ParseAddr(trimmed)
	return err == nil
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
	tailBytes := w.redactor.pendingTailBytes()
	if len(w.pending) > tailBytes {
		flushLen := len(w.pending) - tailBytes
		flushLen = w.redactor.safeFlushLen(w.pending, flushLen)
		if flushLen == 0 {
			return len(p), nil
		}
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

func (r Redactor) safeFlushLen(text string, proposed int) int {
	if proposed <= 0 || proposed >= len(text) {
		return proposed
	}

	cut := proposed
	for {
		adjusted := r.adjustFlushLen(text, cut)
		if adjusted == cut || adjusted <= 0 {
			return adjusted
		}
		cut = adjusted
	}
}

func (r Redactor) pendingTailBytes() int {
	tail := redactionTailBytes
	for _, secret := range sortedNonEmpty(r.KnownSecrets) {
		if retain := len(secret) - 1; retain > tail {
			tail = retain
		}
	}

	if !r.ShowAddresses {
		for _, address := range sortedNonEmpty(r.KnownAddresses) {
			if retain := len(address) - 1; retain > tail {
				tail = retain
			}
		}
	}

	return tail
}

func (r Redactor) adjustFlushLen(text string, cut int) int {
	adjusted := cut
	for _, secret := range sortedNonEmpty(r.KnownSecrets) {
		adjusted = adjustFlushLenForLiteral(text, adjusted, secret)
	}

	if !r.ShowAddresses {
		for _, address := range sortedNonEmpty(r.KnownAddresses) {
			adjusted = adjustFlushLenForLiteral(text, adjusted, address)
		}
		adjusted = adjustFlushLenForIPPattern(text, adjusted, ipv4Candidate)
		adjusted = adjustFlushLenForIPPattern(text, adjusted, ipv6Candidate)
	}

	return adjusted
}

func adjustFlushLenForLiteral(text string, cut int, literal string) int {
	searchStart := 0
	for {
		idx := strings.Index(text[searchStart:], literal)
		if idx < 0 {
			return cut
		}
		start := searchStart + idx
		end := start + len(literal)
		if start < cut && cut < end {
			cut = start
		}
		searchStart = start + 1
	}
}

func adjustFlushLenForIPPattern(text string, cut int, pattern *regexp.Regexp) int {
	for _, match := range pattern.FindAllStringIndex(text, -1) {
		start, end := match[0], match[1]
		if start < cut && cut < end && validIPCandidate(text[start:end]) {
			cut = start
		}
	}
	return cut
}

var _ io.Writer = (*RedactingWriter)(nil)
