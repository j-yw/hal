package sshrelay

import "context"

type Registry struct{}

func NewRegistry(RegistryOptions) (*Registry, error) { return nil, errRegistryUnavailable }

func (*Registry) Acquire(context.Context, AcquireRequest) (Lease, error) {
	return nil, errRegistryUnavailable
}

func (*Registry) Close(context.Context) error { return errRegistryUnavailable }
