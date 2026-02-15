package sandbox

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

type fakePtyStatus struct {
	exitCode *int
	err      *string
}

func (f fakePtyStatus) ExitCode() *int {
	return f.exitCode
}

func (f fakePtyStatus) Error() *string {
	return f.err
}

func TestForwardShellIOResult_Fields(t *testing.T) {
	result := ForwardShellIOResult{
		ExitCode:      42,
		SessionClosed: true,
	}

	if result.ExitCode != 42 {
		t.Errorf("ExitCode = %d, want 42", result.ExitCode)
	}

	if !result.SessionClosed {
		t.Error("SessionClosed should be true")
	}
}

func TestForwardShellIO_NilPtyHandle(t *testing.T) {
	conn := &ShellConnection{
		SandboxName: "test",
		PtyHandle:   nil,
	}

	ctx := context.Background()
	_, err := ForwardShellIO(ctx, conn, strings.NewReader(""), nil)
	if err == nil {
		t.Fatal("expected error for nil PTY handle")
	}
	if !strings.Contains(err.Error(), "no PTY handle") {
		t.Errorf("error %q does not mention nil PTY handle", err.Error())
	}
}

func TestForwardShellIOResult_CleanDisconnect(t *testing.T) {
	result := ForwardShellIOResult{
		ExitCode:      0,
		SessionClosed: false,
	}

	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0 for clean disconnect", result.ExitCode)
	}

	if result.SessionClosed {
		t.Error("SessionClosed should be false for clean disconnect")
	}
}

func TestForwardShellIOResult_SessionClosed(t *testing.T) {
	result := ForwardShellIOResult{
		ExitCode:      1,
		SessionClosed: true,
	}

	if result.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1 for session closed", result.ExitCode)
	}

	if !result.SessionClosed {
		t.Error("SessionClosed should be true when sandbox disconnects")
	}
}

func TestApplyPtyStatus_SetsFailureOnTransportError(t *testing.T) {
	result := &ForwardShellIOResult{}
	errMsg := "websocket read failed"

	applyPtyStatus(result, fakePtyStatus{err: &errMsg})

	if !result.SessionClosed {
		t.Fatal("SessionClosed should be true when PTY has an error")
	}
	if result.ExitCode != 1 {
		t.Fatalf("ExitCode = %d, want 1 when PTY has no exit code and transport failed", result.ExitCode)
	}
}

func TestApplyPtyStatus_PreservesNonZeroExitCode(t *testing.T) {
	exitCode := 127
	errMsg := "connection dropped"
	result := &ForwardShellIOResult{}

	applyPtyStatus(result, fakePtyStatus{exitCode: &exitCode, err: &errMsg})

	if !result.SessionClosed {
		t.Fatal("SessionClosed should be true when PTY has an error")
	}
	if result.ExitCode != 127 {
		t.Fatalf("ExitCode = %d, want 127", result.ExitCode)
	}
}

func TestApplyPtyStatus_CleanExit(t *testing.T) {
	exitCode := 0
	result := &ForwardShellIOResult{}

	applyPtyStatus(result, fakePtyStatus{exitCode: &exitCode})

	if result.SessionClosed {
		t.Fatal("SessionClosed should be false on clean exit")
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}
}

type chunkWriter struct {
	maxChunk int
	buf      bytes.Buffer
}

func (w *chunkWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := len(p)
	if w.maxChunk > 0 && n > w.maxChunk {
		n = w.maxChunk
	}
	return w.buf.Write(p[:n])
}

type failingWriter struct {
	err error
}

func (w *failingWriter) Write(_ []byte) (int, error) {
	return 0, w.err
}

func TestForwardPTYOutput_WritesFullFrames(t *testing.T) {
	ch := make(chan []byte, 2)
	ch <- bytes.Repeat([]byte("A"), 1024)
	ch <- bytes.Repeat([]byte("B"), 8192)
	close(ch)

	writer := &chunkWriter{maxChunk: 17}
	if err := forwardPTYOutput(writer, ch); err != nil {
		t.Fatalf("forwardPTYOutput returned error: %v", err)
	}

	want := append(bytes.Repeat([]byte("A"), 1024), bytes.Repeat([]byte("B"), 8192)...)
	if !bytes.Equal(writer.buf.Bytes(), want) {
		t.Fatalf("forwardPTYOutput output length = %d, want %d", writer.buf.Len(), len(want))
	}
}

func TestForwardPTYOutput_PropagatesWriteError(t *testing.T) {
	ch := make(chan []byte, 1)
	ch <- []byte("hello")
	close(ch)

	writeErr := errors.New("write failed")
	err := forwardPTYOutput(&failingWriter{err: writeErr}, ch)
	if !errors.Is(err, writeErr) {
		t.Fatalf("forwardPTYOutput error = %v, want %v", err, writeErr)
	}
}

type zeroWriter struct{}

func (w *zeroWriter) Write(_ []byte) (int, error) {
	return 0, nil
}

func TestWriteAll_ReturnsShortWriteError(t *testing.T) {
	err := writeAll(&zeroWriter{}, []byte("x"))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("writeAll error = %v, want io.ErrShortWrite", err)
	}
}
