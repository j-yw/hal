package localresolver

import (
	"context"
	"errors"
	"io"
	"time"
)

// Observe the original absolute deadline even before its timer is scheduled.
// Only standard context sentinels cross this boundary, never caller error text.
func acquisitionContextError(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.Canceled) {
			return context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		return ErrInvalidRequest
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func acquisitionError(ctx context.Context, err error) error {
	if current := acquisitionContextError(ctx); current != nil {
		if err == nil {
			return current
		}
		if errors.Is(err, current) {
			return err
		}
		return errors.Join(current, err)
	}
	return err
}

// No WriterTo or ReadFrom shortcut: every actual read is bounded and checks the
// same lifetime before and after the syscall. A blocked syscall still must return.
type acquisitionReader struct {
	ctx    context.Context
	source io.Reader
}

func (reader acquisitionReader) Read(output []byte) (int, error) {
	if err := acquisitionContextError(reader.ctx); err != nil {
		return 0, err
	}
	if len(output) > 32<<10 {
		output = output[:32<<10]
	}
	n, err := reader.source.Read(output)
	if current := acquisitionContextError(reader.ctx); current != nil {
		return n, current
	}
	return n, err
}
