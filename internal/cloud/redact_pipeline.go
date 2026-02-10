package cloud

import (
	"bufio"
	"io"
)

// redactPayload applies the default redaction rules to a JSON payload string.
// It returns the redacted string and true if any secrets were found and masked.
// If the input is nil, it returns nil and false.
func redactPayload(payloadJSON *string) (*string, bool) {
	if payloadJSON == nil {
		return nil, false
	}
	if !ContainsSecret(*payloadJSON) {
		return payloadJSON, false
	}
	redacted := Redact(*payloadJSON)
	return &redacted, true
}

// RedactingLogReader wraps an io.ReadCloser and applies redaction to each line
// of output before returning it to the caller. It is used to wrap
// runner.StreamLogs so that secrets are masked before the CLI displays them.
type RedactingLogReader struct {
	source  io.ReadCloser
	scanner *bufio.Scanner
	buf     []byte // buffered redacted output waiting to be read
}

// NewRedactingLogReader creates a new RedactingLogReader that wraps the given
// source stream and applies redaction to each line.
func NewRedactingLogReader(source io.ReadCloser) *RedactingLogReader {
	return &RedactingLogReader{
		source:  source,
		scanner: bufio.NewScanner(source),
	}
}

// Read implements io.Reader. It reads lines from the underlying source,
// redacts each line, and writes the redacted output to p.
func (r *RedactingLogReader) Read(p []byte) (int, error) {
	// Drain buffered output from a previously redacted line.
	if len(r.buf) > 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}

	// Read the next line from the source.
	if !r.scanner.Scan() {
		if err := r.scanner.Err(); err != nil {
			return 0, err
		}
		return 0, io.EOF
	}

	line := r.scanner.Text()
	redacted := Redact(line) + "\n"
	n := copy(p, []byte(redacted))
	if n < len(redacted) {
		r.buf = []byte(redacted[n:])
	}
	return n, nil
}

// Close closes the underlying source stream.
func (r *RedactingLogReader) Close() error {
	return r.source.Close()
}
