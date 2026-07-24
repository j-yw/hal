package sandboxworker

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

const minJobLogRecordBytes = utf8.UTFMax

func (manager *jobManager) appendLog(entry *jobEntry, stream string, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	sanitized := []byte(sanitizeJobLogData(string(data)))
	if len(sanitized) == 0 {
		return nil
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	candidateJob := cloneJob(entry.job)
	candidateRecords := cloneJobLogRecords(entry.records)
	candidateRetainedBytes := entry.retainedBytes
	for len(sanitized) > 0 {
		chunkBytes := int(manager.logRecordBytes)
		if len(sanitized) < chunkBytes {
			chunkBytes = len(sanitized)
		} else if chunkBytes < len(sanitized) && utf8.Valid(sanitized) {
			for chunkBytes > 0 && !utf8.RuneStart(sanitized[chunkBytes]) {
				chunkBytes--
			}
		}
		chunk := string(sanitized[:chunkBytes])
		sanitized = sanitized[chunkBytes:]
		candidateJob.LogCursor++
		if candidateRetainedBytes+int64(chunkBytes) > manager.logRetentionBytes {
			candidateJob.LogTruncated = true
			if stream == JobLogStreamStdout {
				candidateJob.StdoutTruncated = true
			} else {
				candidateJob.StderrTruncated = true
			}
			continue
		}
		nextRecords := append(candidateRecords, JobLogRecord{
			Cursor:    candidateJob.LogCursor,
			Stream:    stream,
			Data:      chunk,
			Timestamp: manager.now().UTC(),
		})
		encoded, err := encodeStoredJobLogs(candidateJob, nextRecords)
		if err != nil {
			return fmt.Errorf("encode job logs: %w", err)
		}
		if int64(len(encoded)) > maxJobLogsFileBytes {
			candidateJob.LogTruncated = true
			if stream == JobLogStreamStdout {
				candidateJob.StdoutTruncated = true
			} else {
				candidateJob.StderrTruncated = true
			}
			continue
		}
		candidateRecords = nextRecords
		candidateRetainedBytes += int64(chunkBytes)
	}
	if err := manager.store.save(candidateJob, candidateRecords); err != nil {
		return err
	}
	entry.job = candidateJob
	entry.records = candidateRecords
	entry.retainedBytes = candidateRetainedBytes
	return nil
}

func (manager *jobManager) markStreamTruncated(entry *jobEntry, stream string) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	candidateJob := cloneJob(entry.job)
	candidateJob.LogTruncated = true
	if stream == JobLogStreamStdout {
		candidateJob.StdoutTruncated = true
	} else {
		candidateJob.StderrTruncated = true
	}
	if err := manager.store.save(candidateJob, entry.records); err != nil {
		return err
	}
	entry.job = candidateJob
	return nil
}

type jobLogWriter struct {
	manager    *jobManager
	entry      *jobEntry
	stream     string
	limit      int64
	written    int64
	redactor   *jobLiteralRedactor
	sanitizer  jobStreamSanitizer
	mu         sync.Mutex
	truncated  bool
	persistErr error
}

func newJobLogWriter(manager *jobManager, entry *jobEntry, stream string, limit int64, redactor *jobLiteralRedactor) *jobLogWriter {
	return &jobLogWriter{manager: manager, entry: entry, stream: stream, limit: limit, redactor: redactor}
}

func (writer *jobLogWriter) Write(p []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	originalLen := len(p)
	if writer.persistErr != nil {
		return originalLen, writer.persistErr
	}
	remaining := writer.limit - writer.written
	if remaining <= 0 {
		if err := writer.markTruncated(); err != nil {
			writer.persistErr = err
			return originalLen, err
		}
		return originalLen, nil
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
		if err := writer.markTruncated(); err != nil {
			writer.persistErr = err
			return originalLen, err
		}
	}
	writer.written += int64(len(p))
	safe := writer.sanitizer.Consume(writer.redactor.Consume(p, false), false)
	if err := writer.manager.appendLog(writer.entry, writer.stream, safe); err != nil {
		writer.persistErr = err
		return originalLen, err
	}
	return originalLen, nil
}

func (writer *jobLogWriter) markTruncated() error {
	if writer.truncated {
		return nil
	}
	writer.truncated = true
	return writer.manager.markStreamTruncated(writer.entry, writer.stream)
}

func (writer *jobLogWriter) Flush() {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.persistErr != nil {
		return
	}
	writer.persistErr = writer.manager.appendLog(
		writer.entry,
		writer.stream,
		writer.sanitizer.Consume(writer.redactor.ConsumeFinal(writer.truncated), true),
	)
}

func (writer *jobLogWriter) Err() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.persistErr
}

const jobStreamSanitizerSuffixBytes = 4 << 10

// jobStreamSanitizer retains only a bounded suffix while looking for generic
// secret, endpoint, and host-path tokens split across driver Write calls. Once
// a sensitive token starts, its remainder is discarded through the next
// whitespace delimiter, or through the line break for a credential-bearing
// header, so arbitrarily long values cannot leak or consume unbounded memory.
type jobStreamSanitizer struct {
	pending                   []byte
	redacting                 bool
	redactingThroughLineBreak bool
}

func (sanitizer *jobStreamSanitizer) Consume(p []byte, final bool) []byte {
	sanitizer.pending = append(sanitizer.pending, p...)
	var out bytes.Buffer
	for len(sanitizer.pending) > 0 {
		if sanitizer.redacting {
			delimiter := firstJobLogWhitespace(sanitizer.pending)
			if sanitizer.redactingThroughLineBreak {
				delimiter = firstJobLogLineBreak(sanitizer.pending)
			}
			if delimiter < 0 {
				sanitizer.pending = sanitizer.pending[:0]
				break
			}
			out.WriteByte(sanitizer.pending[delimiter])
			sanitizer.pending = append(sanitizer.pending[:0], sanitizer.pending[delimiter+1:]...)
			sanitizer.redacting = false
			sanitizer.redactingThroughLineBreak = false
			continue
		}
		if candidate, ok := firstJobLogSensitiveCandidate(sanitizer.pending); ok {
			out.WriteString(sanitizeJobLogData(string(sanitizer.pending[:candidate.start])))
			out.WriteString(candidate.marker)
			sanitizer.pending = append(sanitizer.pending[:0], sanitizer.pending[candidate.start:]...)
			sanitizer.redacting = true
			sanitizer.redactingThroughLineBreak = candidate.throughLineBreak
			continue
		}
		if final {
			out.WriteString(sanitizeJobLogData(string(sanitizer.pending)))
			sanitizer.pending = sanitizer.pending[:0]
			break
		}
		if boundary := lastJobLogLineBoundary(sanitizer.pending); boundary > 0 {
			out.WriteString(sanitizeJobLogData(string(sanitizer.pending[:boundary])))
			sanitizer.pending = append(sanitizer.pending[:0], sanitizer.pending[boundary:]...)
			continue
		}
		if len(sanitizer.pending) <= jobStreamSanitizerSuffixBytes {
			break
		}
		limit := len(sanitizer.pending) - jobStreamSanitizerSuffixBytes
		if utf8.Valid(sanitizer.pending) {
			for limit > 0 && !utf8.RuneStart(sanitizer.pending[limit]) {
				limit--
			}
		}
		out.WriteString(sanitizeJobLogData(string(sanitizer.pending[:limit])))
		sanitizer.pending = append(sanitizer.pending[:0], sanitizer.pending[limit:]...)
	}
	if final && sanitizer.redacting {
		sanitizer.pending = sanitizer.pending[:0]
		sanitizer.redacting = false
		sanitizer.redactingThroughLineBreak = false
	}
	return out.Bytes()
}

func lastJobLogLineBoundary(data []byte) int {
	for index := len(data) - 1; index >= 0; index-- {
		if data[index] == '\n' || data[index] == '\r' {
			return index + 1
		}
	}
	return 0
}

type jobLogSensitiveCandidate struct {
	start            int
	marker           string
	throughLineBreak bool
}

func firstJobLogSensitiveCandidate(data []byte) (jobLogSensitiveCandidate, bool) {
	lower := bytes.ToLower(data)
	candidates := make([]jobLogSensitiveCandidate, 0, 3)
	if start, marker, ok := firstJobLogSecretCandidate(data, lower); ok {
		candidates = append(candidates, jobLogSensitiveCandidate{start: start, marker: marker})
	}
	if candidate, ok := firstJobLogSensitiveHeaderCandidate(lower); ok {
		candidates = append(candidates, candidate)
	}
	for _, prefix := range [][]byte{
		[]byte("/private/users/"),
		[]byte("/var/folders/"),
		[]byte("/workspaces/"),
		[]byte("/workspace/"),
		[]byte("/run/user/"),
		[]byte("/sandbox/"),
		[]byte("/remote/"),
		[]byte("/users/"),
		[]byte("/home/"),
		[]byte("/var/tmp/"),
		[]byte("/tmp/"),
	} {
		if start := bytes.Index(lower, prefix); start >= 0 {
			candidates = append(candidates, jobLogSensitiveCandidate{start: start, marker: "[redacted-path]"})
		}
	}
	for searchFrom := 0; searchFrom < len(lower); {
		relativeEnd := bytes.Index(lower[searchFrom:], []byte("://"))
		if relativeEnd < 0 {
			break
		}
		schemeEnd := searchFrom + relativeEnd
		if schemeEnd > 0 {
			start := schemeEnd - 1
			for start > 0 && isJobLogSchemeByte(lower[start-1]) {
				start--
			}
			if isJobLogASCIILetter(lower[start]) {
				candidates = append(candidates, jobLogSensitiveCandidate{start: start, marker: "[redacted-endpoint]"})
				break
			}
		}
		searchFrom = schemeEnd + len("://")
	}
	if len(candidates) == 0 {
		return jobLogSensitiveCandidate{}, false
	}
	first := candidates[0]
	for _, candidate := range candidates[1:] {
		if candidate.start < first.start {
			first = candidate
		}
	}
	return first, true
}

func firstJobLogSensitiveHeaderCandidate(lower []byte) (jobLogSensitiveCandidate, bool) {
	headers := []struct {
		name   []byte
		marker string
	}{
		{name: []byte("proxy-authorization:"), marker: "Proxy-Authorization: [redacted]"},
		{name: []byte("authorization:"), marker: "Authorization: [redacted]"},
		{name: []byte("x-auth-token:"), marker: "X-Auth-Token: [redacted]"},
		{name: []byte("x-api-key:"), marker: "X-API-Key: [redacted]"},
		{name: []byte("api-key:"), marker: "API-Key: [redacted]"},
		{name: []byte("set-cookie:"), marker: "Set-Cookie: [redacted]"},
		{name: []byte("cookie:"), marker: "Cookie: [redacted]"},
	}
	var first jobLogSensitiveCandidate
	found := false
	for _, header := range headers {
		for searchFrom := 0; searchFrom < len(lower); {
			relativeStart := bytes.Index(lower[searchFrom:], header.name)
			if relativeStart < 0 {
				break
			}
			start := searchFrom + relativeStart
			if start > 0 && isJobLogSecretKeyByte(lower[start-1]) {
				searchFrom = start + 1
				continue
			}
			candidate := jobLogSensitiveCandidate{
				start:            start,
				marker:           header.marker,
				throughLineBreak: true,
			}
			if !found || candidate.start < first.start {
				first = candidate
				found = true
			}
			break
		}
	}
	return first, found
}

func firstJobLogSecretCandidate(data, lower []byte) (int, string, bool) {
	for equals := bytes.IndexByte(lower, '='); equals >= 0; {
		start := equals
		for start > 0 && isJobLogSecretKeyByte(lower[start-1]) {
			start--
		}
		key := lower[start:equals]
		if len(key) > 0 &&
			(bytes.Contains(key, []byte("token")) ||
				bytes.Contains(key, []byte("secret")) ||
				bytes.Contains(key, []byte("password")) ||
				bytes.Contains(key, []byte("api_key")) ||
				bytes.Contains(key, []byte("api-key"))) {
			return start, string(data[start:equals+1]) + "[redacted]", true
		}
		next := bytes.IndexByte(lower[equals+1:], '=')
		if next < 0 {
			break
		}
		equals += next + 1
	}
	return 0, "", false
}

func firstJobLogWhitespace(data []byte) int {
	for index, value := range data {
		switch value {
		case ' ', '\t', '\n', '\r', '\f', '\v':
			return index
		}
	}
	return -1
}

func firstJobLogLineBreak(data []byte) int {
	for index, value := range data {
		if value == '\n' || value == '\r' {
			return index
		}
	}
	return -1
}

func isJobLogSecretKeyByte(value byte) bool {
	return isJobLogASCIILetter(value) || value >= '0' && value <= '9' || value == '_' || value == '-'
}

func isJobLogSchemeByte(value byte) bool {
	return isJobLogSecretKeyByte(value) || value == '+' || value == '.'
}

func isJobLogASCIILetter(value byte) bool {
	return value >= 'a' && value <= 'z'
}

type jobLiteralRedactor struct {
	patterns [][]byte
	pending  []byte
}

func newJobLiteralRedactor(req ExecRequest) *jobLiteralRedactor {
	unique := map[string]bool{}
	for _, value := range req.Args {
		addJobLiteralLines(unique, []byte(value))
	}
	for _, value := range req.Env {
		addJobLiteralLines(unique, []byte(value))
	}
	if req.Stdin != nil {
		if stdin, err := io.ReadAll(execStdinReader(req.Stdin)); err == nil && len(stdin) > 0 {
			addJobLiteralLines(unique, stdin)
		}
	}
	patterns := make([][]byte, 0, len(unique))
	for value := range unique {
		patterns = append(patterns, []byte(value))
	}
	sort.Slice(patterns, func(i, j int) bool { return len(patterns[i]) > len(patterns[j]) })
	return &jobLiteralRedactor{patterns: patterns}
}

func addJobLiteralLines(unique map[string]bool, value []byte) {
	for _, line := range bytes.FieldsFunc(value, func(separator rune) bool {
		return separator == '\n' || separator == '\r'
	}) {
		addJobLiteralPattern(unique, line)
	}
}

func addJobLiteralPattern(unique map[string]bool, value []byte) {
	if len(value) > 0 {
		unique[string(value)] = true
	}
}

func (redactor *jobLiteralRedactor) Consume(p []byte, final bool) []byte {
	return redactor.consume(p, final, false)
}

func (redactor *jobLiteralRedactor) ConsumeFinal(redactPartial bool) []byte {
	return redactor.consume(nil, true, redactPartial)
}

func (redactor *jobLiteralRedactor) consume(p []byte, final, redactPartial bool) []byte {
	if redactor == nil {
		return append([]byte(nil), p...)
	}
	redactor.pending = append(redactor.pending, p...)
	maxPattern := 0
	if len(redactor.patterns) > 0 {
		maxPattern = len(redactor.patterns[0])
	}
	limit := len(redactor.pending)
	if final {
		limit = 0
	} else if maxPattern > 0 {
		limit = len(redactor.pending) - maxPattern + 1
		if limit < 0 {
			limit = 0
		}
		if boundary := lastJobLogLineBoundary(redactor.pending); boundary > limit {
			limit = boundary
		}
	}
	var out bytes.Buffer
	index := 0
	for index < limit {
		matched := false
		for _, pattern := range redactor.patterns {
			if len(pattern) > 0 && bytes.HasPrefix(redactor.pending[index:], pattern) {
				out.WriteString("[redacted]")
				index += len(pattern)
				matched = true
				break
			}
		}
		if !matched {
			out.WriteByte(redactor.pending[index])
			index++
		}
	}
	if final {
		for index < len(redactor.pending) {
			matched := false
			for _, pattern := range redactor.patterns {
				if len(pattern) > 0 && bytes.HasPrefix(redactor.pending[index:], pattern) {
					out.WriteString("[redacted]")
					index += len(pattern)
					matched = true
					break
				}
			}
			if !matched && redactPartial {
				suffix := redactor.pending[index:]
				for _, pattern := range redactor.patterns {
					if len(suffix) > 0 && len(suffix) < len(pattern) && bytes.HasPrefix(pattern, suffix) {
						out.WriteString("[redacted]")
						index = len(redactor.pending)
						matched = true
						break
					}
				}
			}
			if !matched {
				out.WriteByte(redactor.pending[index])
				index++
			}
		}
	}
	redactor.pending = append(redactor.pending[:0], redactor.pending[index:]...)
	return out.Bytes()
}

func jobLogRecordsSize(records []JobLogRecord) int64 {
	var size int64
	for _, record := range records {
		size += int64(len([]byte(record.Data)))
	}
	return size
}

func sanitizeJobLogData(data string) string {
	data = strings.ToValidUTF8(data, "\uFFFD")
	data = clientSecretAssignmentPattern.ReplaceAllString(data, "$1=[redacted]")
	data = clientHostPathPattern.ReplaceAllString(data, "[redacted-path]")
	data = clientRemoteTempPathPattern.ReplaceAllString(data, "[redacted-path]")
	data = clientEndpointURLPattern.ReplaceAllString(data, "[redacted-endpoint]")
	return data
}
