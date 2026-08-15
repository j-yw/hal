package firecrackerhost_test

import (
	"context"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
)

type externalL7IntentResolver struct{}

func (externalL7IntentResolver) ResolveL7RuntimeIntent(
	context.Context,
	string,
) (l7network.PrepareRequest, error) {
	return l7network.PrepareRequest{}, nil
}

type externalL7AssetResolver struct{}

func (externalL7AssetResolver) AcquireL7RuntimeAssets(
	context.Context,
	l7network.Identity,
) (firecrackerhost.L7RuntimeAssets, error) {
	return firecrackerhost.L7RuntimeAssets{}, nil
}

var (
	_ firecrackerhost.L7RuntimeIntentResolver = externalL7IntentResolver{}
	_ firecrackerhost.L7RuntimeAssetResolver  = externalL7AssetResolver{}
)
