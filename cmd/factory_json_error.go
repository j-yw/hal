package cmd

import (
	"errors"
	"io"
)

type factoryCountingWriter struct {
	written int64
	out     io.Writer
}

func newFactoryCountingWriter(out io.Writer) *factoryCountingWriter {
	if out == nil {
		out = io.Discard
	}
	return &factoryCountingWriter{out: out}
}

func (w *factoryCountingWriter) Write(p []byte) (int, error) {
	n, err := w.out.Write(p)
	w.written += int64(n)
	return n, err
}

func suppressFactoryJSONRenderedError(err error, jsonMode bool, writer *factoryCountingWriter) error {
	if err == nil {
		return nil
	}
	if jsonMode && writer != nil && writer.written > 0 {
		return &ExitCodeError{Code: factoryRenderedJSONExitCode(err)}
	}
	return err
}

func factoryRenderedJSONExitCode(err error) int {
	var exitErr *ExitCodeError
	if errors.As(err, &exitErr) && exitErr.Code > 0 {
		return exitErr.Code
	}
	return 1
}
