//go:build !linux

package minimalcontrol

import "context"

func ReadLinuxBootCommandLine(context.Context) (string, error) { return "", ErrUnavailable }

type bootstrapEntropy struct{}

func (bootstrapEntropy) Read(value []byte) (int, error) {
	clear(value)
	return 0, ErrUnavailable
}
