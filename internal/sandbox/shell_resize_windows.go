//go:build windows

package sandbox

import (
	"context"

	"github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
)

// sendTerminalSize is a no-op on Windows.
func sendTerminalSize(_ context.Context, _ *daytona.PtyHandle, _ int) {}

// watchResize is a no-op on Windows (no SIGWINCH equivalent).
// Returns a no-op stop function.
func watchResize(_ context.Context, _ *daytona.PtyHandle, _ int) func() {
	return func() {}
}
