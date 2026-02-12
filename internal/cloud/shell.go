package cloud

import "strings"

// ShellQuote wraps a value in single quotes and escapes any embedded single
// quotes using the standard shell idiom: replace ' with '\''.
// The result is safe for use as a single-quoted shell argument.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
