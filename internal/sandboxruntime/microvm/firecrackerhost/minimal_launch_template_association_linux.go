//go:build linux

package firecrackerhost

import (
	"context"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition/registry"
)

// Constructor-owned deployment association, not an OCI-to-rootfs digest proof.
type minimalTemplateAssociation struct {
	scope                  sandboxruntime.MinimalLaunchScope
	template               sandboxruntime.MinimalLaunchTemplateIdentity
	templateSource         string
	bundleDir, parentL7Dir string
	expected               localresolver.L8MinimalExpectedIdentity
}

type minimalLaunchProvider struct{}

// Compiling RED: no production provider owns acquisition yet.
func newMinimalLaunchProvider(minimalTemplateAssociation, registry.Options) (*minimalLaunchProvider, error) {
	return nil, sandboxruntime.ErrMinimalLaunchUnavailable
}

func (*minimalLaunchProvider) ResolveMinimalSelection(context.Context, sandboxruntime.MinimalLaunchSelectionHints) (sandboxruntime.MinimalLaunchSelection, error) {
	return nil, sandboxruntime.ErrMinimalLaunchUnavailable
}
