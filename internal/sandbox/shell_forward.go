package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/term"
)

// ForwardShellIOResult contains the outcome of a shell I/O session.
type ForwardShellIOResult struct {
	// ExitCode from the remote process. 0 for clean disconnect.
	ExitCode int
	// SessionClosed is true if the sandbox disconnected during the session.
	SessionClosed bool
}

// ForwardShellIO runs bidirectional terminal I/O between the local terminal and
// the sandbox PTY. It sets the local terminal to raw mode, forwards
// stdin→PTY and PTY→stdout, handles SIGWINCH for resize, and restores the
// terminal on exit.
//
// stdin must be an *os.File to enable raw mode. If it isn't (e.g., in tests),
// raw mode is skipped.
func ForwardShellIO(ctx context.Context, conn *ShellConnection, stdin io.Reader, stdout io.Writer) (*ForwardShellIOResult, error) {
	pty := conn.PtyHandle
	if pty == nil {
		return nil, fmt.Errorf("no PTY handle in shell connection")
	}

	// Set terminal to raw mode if stdin is a terminal
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fd := int(f.Fd())
		oldState, err := term.MakeRaw(fd)
		if err != nil {
			return nil, fmt.Errorf("setting terminal to raw mode: %w", err)
		}
		defer term.Restore(fd, oldState)

		// Send initial terminal size
		sendTerminalSize(ctx, pty, fd)

		// Watch for SIGWINCH (terminal resize) — platform-specific
		stopResize := watchResize(ctx, pty, fd)
		defer stopResize()
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	result := &ForwardShellIOResult{}
	var once sync.Once
	setSessionClosed := func() {
		once.Do(func() {
			result.SessionClosed = true
		})
	}

	errCh := make(chan error, 2)

	// PTY → stdout (output forwarding)
	go func() {
		_, err := io.Copy(stdout, pty)
		if err != nil {
			setSessionClosed()
		}
		cancel()
		errCh <- err
	}()

	// stdin → PTY (input forwarding)
	go func() {
		_, err := io.Copy(pty, stdin)
		cancel()
		errCh <- err
	}()

	// Wait for context cancellation (triggered by either goroutine finishing)
	<-ctx.Done()

	// Check PTY exit code
	if code := pty.ExitCode(); code != nil {
		result.ExitCode = *code
	}

	// Clean up the PTY connection
	pty.Disconnect()

	if result.SessionClosed {
		result.ExitCode = 1
	}

	return result, nil
}
