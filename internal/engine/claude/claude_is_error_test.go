package claude

import (
	"bytes"
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/engine"
)

// Claude Code reports authentication and API failures as a result event with
// subtype "success" but is_error true. That run did no work, so Hal must not
// count it as a successful iteration, whatever the process exit code.
func TestExecute_TreatsIsErrorResultAsFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture is unix-only")
	}
	const notLoggedIn = `{"type":"result","subtype":"success","is_error":true,"duration_ms":67,"result":"Not logged in · Please run /login"}`
	for _, exitCode := range []string{"1", "0"} {
		t.Run("exit "+exitCode, func(t *testing.T) {
			binDir := t.TempDir()
			writeFakeClaude(t, binDir, "#!/bin/sh\nprintf '%s\\n' '"+notLoggedIn+"'\nexit "+exitCode+"\n")
			t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

			eng := New(&engine.EngineConfig{Timeout: 10 * time.Second})
			var buf bytes.Buffer
			result := eng.Execute(context.Background(), "test prompt", engine.NewDisplay(&buf))

			if result.Success {
				t.Fatal("Execute() success = true for an is_error result, want false")
			}
			if result.Error == nil || !strings.Contains(result.Error.Error(), "Not logged in") {
				t.Fatalf("Execute() error = %v, want Claude's result message", result.Error)
			}
		})
	}
}
