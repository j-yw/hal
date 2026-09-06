//go:build windows

package sandboxworkspace

import (
	"context"
	"fmt"
	"os"
)

func gitRunSafeWithVerifiedPayload(context.Context, string, string, *os.File, ...string) error {
	return fmt.Errorf("git bundle verify failed: verified payload descriptors are unavailable on this platform")
}
