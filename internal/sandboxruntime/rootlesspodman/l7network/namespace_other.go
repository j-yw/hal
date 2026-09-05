//go:build !linux

package l7network

import (
	"context"

	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
)

type ProductionNamespaceResolverOptions struct {
	LifecycleRunner rootlesspodman.LifecycleCommandRunner
	PodmanPath      string
	NSenterPath     string
	IPPath          string
	InterfaceName   string
	MaxOutputBytes  int64
}

type ProductionNamespaceResolver struct{}

func NewProductionNamespaceResolver(ProductionNamespaceResolverOptions) (*ProductionNamespaceResolver, error) {
	return nil, ErrNamespaceUnverified
}

func (*ProductionNamespaceResolver) Resolve(context.Context, rootlesspodman.NetworkTopologyTargetRequest) (NamespaceResolution, error) {
	return NamespaceResolution{}, ErrNamespaceUnverified
}
