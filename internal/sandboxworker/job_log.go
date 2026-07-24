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
		entry.job.LogCursor++
		if entry.retainedBytes+int64(chunkBytes) > manager.logRetentionBytes {
			entry.job.LogTruncated = true
			if stream == JobLogStreamStdout {
				entry.job.StdoutTruncated = true
			} else {
				entry.job.StderrTruncated = true
			}
			continue
		}
		candidateRecords := append(entry.records, JobLogRecord{
			Cursor:    entry.job.LogCursor,
			Stream:    stream,
			Data:      chunk,
			Timestamp: manager.now().UTC(),
		})
		encoded, err := encodeStoredJobLogs(entry.job, candidateRecords)
		if err != nil {
			return fmt.Errorf("encode job logs: %w", err)
		}
		if int64(len(encoded)) > maxJobLogsFileBytes {
			entry.job.LogTruncated = true
			if stream == JobLogStreamStdout {
				entry.job.StdoutTruncated = true
			} else {
				entry.job.StderrTruncated = true
			}
			continue
		}
		entry.records = candidateRecords
		entry.retainedBytes += int64(chunkBytes)
	}
	return manager.store.save(entry.job, entry.records)
}

func (manager *jobManager) markStreamTruncated(entry *jobEntry, stream string) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	entry.job.LogTruncated = true
	if stream == JobLogStreamStdout {
		entry.job.StdoutTruncated = true
	} else {
		entry.job.StderrTruncated = true
	}
	return manager.store.save(entry.job, entry.records)
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

// jobStreamSanitizer holds an incomplete line so generic secret, endpoint, and
// host-path patterns cannot evade redaction by spanning driver Write calls.
// The enclosing writer's capture limit also bounds this pending buffer.
type jobStreamSanitizer struct {
	pending []byte
}

func (sanitizer *jobStreamSanitizer) Consume(p []byte, final bool) []byte {
	sanitizer.pending = append(sanitizer.pending, p...)
	limit := len(sanitizer.pending)
	if !final {
		if lastNewline := bytes.LastIndexByte(sanitizer.pending, '\n'); lastNewline >= 0 {
			limit = lastNewline + 1
		} else {
			limit = 0
		}
	}
	if limit == 0 {
		return nil
	}
	out := []byte(sanitizeJobLogData(string(sanitizer.pending[:limit])))
	sanitizer.pending = append(sanitizer.pending[:0], sanitizer.pending[limit:]...)
	return out
}

type jobLiteralRedactor struct {
	patterns [][]byte
	pending  []byte
}

func newJobLiteralRedactor(req ExecRequest) *jobLiteralRedactor {
	unique := map[string]bool{}
	for _, value := range req.Args {
		if value != "" {
			unique[value] = true
		}
	}
	for _, value := range req.Env {
		if value != "" {
			unique[value] = true
		}
	}
	if req.Stdin != nil {
		if stdin, err := io.ReadAll(execStdinReader(req.Stdin)); err == nil && len(stdin) > 0 {
			addJobLiteralPattern(unique, stdin)
			addJobLiteralPattern(unique, bytes.TrimRight(stdin, "\r\n"))
			for _, line := range bytes.Split(stdin, []byte{'\n'}) {
				addJobLiteralPattern(unique, bytes.TrimSuffix(line, []byte{'\r'}))
			}
		}
	}
	patterns := make([][]byte, 0, len(unique))
	for value := range unique {
		patterns = append(patterns, []byte(value))
	}
	sort.Slice(patterns, func(i, j int) bool { return len(patterns[i]) > len(patterns[j]) })
	return &jobLiteralRedactor{patterns: patterns}
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
