package cloud

import "strings"

// ShellQuote wraps a value in single quotes and escapes any embedded single
// quotes using the standard shell idiom (replace each quote with end-quote,
// escaped-quote, start-quote). The result is safe as a shell argument.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
