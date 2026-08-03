//go:build !linux

package policyproxy

import (
	"context"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

// Adapter is a fail-closed placeholder on non-Linux platforms.
type Adapter struct{}

// New fails closed because L6 listener ownership is accepted on Linux only.
func New(Config) (*Adapter, error) {
	return nil, ErrUnsupported
}

func (*Adapter) PrepareProxyListener(context.Context, networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	return networkenforcement.ProxyListenerLifecycleMetadata{}, ErrUnsupported
}

func (*Adapter) StartProxyListener(context.Context, networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	return networkenforcement.ProxyListenerLifecycleMetadata{}, ErrUnsupported
}

func (*Adapter) ActiveProxyListener(context.Context, networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	return networkenforcement.ProxyListenerLifecycleMetadata{}, ErrUnsupported
}

func (*Adapter) StopProxyListener(context.Context, networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	return networkenforcement.ProxyListenerLifecycleMetadata{
		Status:     networkenforcement.LifecycleStatusStopped,
		ReasonCode: networkenforcement.LifecycleReasonStopped,
	}, nil
}

func (*Adapter) Endpoint() (string, bool) {
	return "", false
}

func (*Adapter) LiveEndpoint() (LiveEndpoint, bool) { return LiveEndpoint{}, false }

func (*Adapter) ActiveLiveEndpoint(context.Context, LiveEndpoint, networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	return networkenforcement.ProxyListenerLifecycleMetadata{}, ErrUnsupported
}

func (*Adapter) StopLiveEndpoint(context.Context, LiveEndpoint, networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	return networkenforcement.ProxyListenerLifecycleMetadata{}, ErrUnsupported
}
