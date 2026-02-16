package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/term"
)

type ptyStatus interface {
	ExitCode() *int
	Error() *string
}

// ForwardShellIOResult contains the outcome of a shell I/O session.
type ForwardShellIOResult struct {
	// ExitCode from the remote process. 0 for clean disconnect.
	ExitCode int
	// SessionClosed is true if the sandbox disconnected during the session.
	SessionClosed bool
}

const stdinReadDeadline = 200 * time.Millisecond

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

	var wg sync.WaitGroup
	wg.Add(2)

	// PTY → stdout (output forwarding)
	go func() {
		defer wg.Done()
		err := forwardPTYOutputWithContext(ctx, stdout, pty.DataChan())
		if err != nil {
			setSessionClosed()
		}
		cancel()
	}()

	// stdin → PTY (input forwarding)
	go func() {
		defer wg.Done()
		forwardPTYInput(ctx, pty, stdin)
		cancel()
	}()

	// Wait for context cancellation (triggered by either goroutine finishing)
	<-ctx.Done()

	// Clean up the PTY connection
	pty.Disconnect()
	wg.Wait()

	// Derive final status only after goroutines have stopped mutating result.
	applyPtyStatus(result, pty)

	if result.SessionClosed && result.ExitCode == 0 {
		result.ExitCode = 1
	}

	return result, nil
}

func applyPtyStatus(result *ForwardShellIOResult, pty ptyStatus) {
	if code := pty.ExitCode(); code != nil {
		result.ExitCode = *code
	}

	if ptyErr := pty.Error(); ptyErr != nil {
		result.SessionClosed = true
		if result.ExitCode == 0 {
			result.ExitCode = 1
		}
	}
}

func forwardPTYOutput(stdout io.Writer, dataCh <-chan []byte) error {
	return forwardPTYOutputWithContext(context.Background(), stdout, dataCh)
}

func forwardPTYOutputWithContext(ctx context.Context, stdout io.Writer, dataCh <-chan []byte) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case data, ok := <-dataCh:
			if !ok {
				return nil
			}
			if err := writeAll(stdout, data); err != nil {
				return err
			}
		}
	}
}

func forwardPTYInput(ctx context.Context, pty io.Writer, stdin io.Reader) {
	if file, ok := stdin.(*os.File); ok {
		_ = forwardFileInput(ctx, pty, file)
		return
	}

	if rc, ok := stdin.(io.ReadCloser); ok {
		copyWithCancelableReadCloser(ctx, pty, rc)
		return
	}

	_, _ = io.Copy(pty, stdin)
}

func copyWithCancelableReadCloser(ctx context.Context, dst io.Writer, src io.ReadCloser) {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = src.Close()
		case <-done:
		}
	}()

	_, _ = io.Copy(dst, src)
	close(done)
}

func forwardFileInput(ctx context.Context, pty io.Writer, file *os.File) error {
	// Use short read deadlines so blocked terminal reads can observe cancellation.
	if err := file.SetReadDeadline(time.Now().Add(stdinReadDeadline)); err != nil {
		return forwardFileInputWithoutDeadline(ctx, pty, file)
	}
	defer file.SetReadDeadline(time.Time{})

	buf := make([]byte, 32*1024)
	for {
		if ctx.Err() != nil {
			return nil
		}

		_ = file.SetReadDeadline(time.Now().Add(stdinReadDeadline))
		n, err := file.Read(buf)
		if n > 0 {
			if writeErr := writeAll(pty, buf[:n]); writeErr != nil {
				return writeErr
			}
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			if isTimeoutError(err) {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
}

func forwardFileInputWithoutDeadline(ctx context.Context, pty io.Writer, file *os.File) error {
	type readResult struct {
		data []byte
		err  error
	}

	readCh := make(chan readResult, 1)

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := file.Read(buf)

			var data []byte
			if n > 0 {
				data = append([]byte(nil), buf[:n]...)
			}

			select {
			case readCh <- readResult{data: data, err: err}:
			case <-ctx.Done():
				return
			}

			if err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case res := <-readCh:
			if len(res.data) > 0 {
				if writeErr := writeAll(pty, res.data); writeErr != nil {
					return writeErr
				}
			}

			if res.err != nil {
				if errors.Is(res.err, io.EOF) || ctx.Err() != nil {
					return nil
				}
				return res.err
			}
		}
	}
}

func isTimeoutError(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}

	type timeout interface {
		Timeout() bool
	}
	var timeoutErr timeout
	return errors.As(err, &timeoutErr) && timeoutErr.Timeout()
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
