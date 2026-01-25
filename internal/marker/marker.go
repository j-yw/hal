package marker

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
)

// MarkComplete replaces "- [ ]" with "- [x]" at the specified line number (1-based)
// in the given file. It preserves all other content exactly, including UTF-8 characters.
func MarkComplete(filepath string, lineNumber int) error {
	// Read the file
	content, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Process and update the content
	updated, err := MarkCompleteContent(bytes.NewReader(content), lineNumber)
	if err != nil {
		return err
	}

	// Write the updated content back to the file
	err = os.WriteFile(filepath, updated, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// MarkCompleteContent reads content from an io.Reader and returns the updated content
// with the task at the specified line number marked as complete.
// This function is useful for testing without file I/O.
func MarkCompleteContent(r io.Reader, lineNumber int) ([]byte, error) {
	if lineNumber < 1 {
		return nil, fmt.Errorf("invalid line number: %d (must be >= 1)", lineNumber)
	}

	var result bytes.Buffer
	scanner := bufio.NewScanner(r)
	currentLine := 0

	for scanner.Scan() {
		currentLine++
		line := scanner.Text()

		if currentLine == lineNumber {
			// Check if this line is a pending task
			if strings.HasPrefix(line, "- [ ] ") {
				// Replace "- [ ]" with "- [x]"
				line = "- [x] " + strings.TrimPrefix(line, "- [ ] ")
			} else if strings.HasPrefix(line, "- [ ]") {
				// Handle case where there's no space after the bracket (edge case)
				line = "- [x]" + strings.TrimPrefix(line, "- [ ]")
			} else {
				return nil, fmt.Errorf("line %d is not a pending task (expected '- [ ]')", lineNumber)
			}
		}

		// Write line with newline
		result.WriteString(line)
		result.WriteByte('\n')
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read content: %w", err)
	}

	if currentLine == 0 {
		return nil, fmt.Errorf("file is empty")
	}

	if lineNumber > currentLine {
		return nil, fmt.Errorf("line number %d exceeds file length (%d lines)", lineNumber, currentLine)
	}

	return result.Bytes(), nil
}
