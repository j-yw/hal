//go:build !linux

package l7network

import "context"

type unsupportedNamespaceCommand struct{}

func newPlatformNamespaceCommand(string) (NamespaceCommandBoundary, bool) {
	return unsupportedNamespaceCommand{}, false
}

func tapPlatformSupported() bool { return false }

func (unsupportedNamespaceCommand) Run(context.Context, NamespaceLease, NamespaceCommandRequest, int64) ([]byte, error) {
	return nil, ErrUnsupported
}
