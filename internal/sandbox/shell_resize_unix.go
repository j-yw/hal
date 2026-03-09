//go:build !windows

package sandbox

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
	"golang.org/x/term"
)

// sendTerminalSize reads the current terminal dimensions and sends them to the PTY.
func sendTerminalSize(ctx context.Context, pty *daytona.PtyHandle, fd int) {
	w, h, err := term.GetSize(fd)
	if err != nil {
		return
	}
	pty.Resize(ctx, w, h)
}

// watchResize listens for SIGWINCH signals and forwards terminal size changes
// to the sandbox PTY. Returns a stop function to clean up the signal handler.
func watchResize(ctx context.Context, pty *daytona.PtyHandle, fd int) func() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-sigCh:
				if !ok {
					return
				}
				sendTerminalSize(ctx, pty, fd)
			}
		}
	}()

	return func() {
		signal.Stop(sigCh)
		close(sigCh)
	}
}
