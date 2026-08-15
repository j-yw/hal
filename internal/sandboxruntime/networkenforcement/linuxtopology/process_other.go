//go:build !linux

package linuxtopology

import (
	"context"
	"os"
)

type unsupportedProcessBoundary struct{}

func platformDependencies() (bool, ProcessStarter, CommandRunner, NamespaceOpener) {
	boundary := unsupportedProcessBoundary{}
	return false, boundary, boundary, func(int) (*NamespaceHandle, error) { return nil, ErrUnsupported }
}

func executableToolPaths(ToolPaths) bool { return false }

func (unsupportedProcessBoundary) Start(context.Context, ProcessSpec) (ProcessHandle, error) {
	return nil, ErrUnsupported
}

func (unsupportedProcessBoundary) Run(context.Context, ProcessSpec) ([]byte, error) {
	return nil, ErrUnsupported
}

// Keep os in the non-Linux build's dependency closure because ProcessSpec's
// platform-neutral live descriptor slice must compile on every target.
var _ *os.File
