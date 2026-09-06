//go:build !linux

package linuxrules

import "context"

type unsupportedExecutor struct{}

type ProductionExecutorOptions struct {
	NSenterPath string
	NFTPath     string
}

func NewProductionExecutor(ProductionExecutorOptions) (NFTExecutor, error) {
	return nil, ErrUnsupported
}

func (unsupportedExecutor) ApplyBatch(context.Context, NamespaceHandle, []byte) error {
	return ErrUnsupported
}

func (unsupportedExecutor) ListTableJSON(context.Context, NamespaceHandle, TableQuery, int64) ([]byte, error) {
	return nil, ErrUnsupported
}
