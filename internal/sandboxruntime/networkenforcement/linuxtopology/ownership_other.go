//go:build !linux

package linuxtopology

import "context"

type fileOwnershipStore struct{}
type fileOwnershipLease struct{}

func newFileOwnershipStore(string) (*fileOwnershipStore, error) { return nil, ErrUnsupported }
func (*fileOwnershipStore) Acquire(context.Context, Identity) (OwnershipLease, error) {
	return nil, ErrUnsupported
}
func (*fileOwnershipStore) acquire(context.Context, Identity) (*fileOwnershipLease, error) {
	return nil, ErrUnsupported
}
func (*fileOwnershipLease) Reconcile(context.Context) error { return ErrUnsupported }
func (*fileOwnershipLease) Record(context.Context, ProcessHandle, ProcessHandle, *NamespaceHandle) error {
	return ErrUnsupported
}
func (*fileOwnershipLease) Retire(Identity) error { return ErrUnsupported }
func (*fileOwnershipLease) retire(Identity) error { return ErrUnsupported }
func (*fileOwnershipLease) Release() error        { return nil }
func (*fileOwnershipLease) release() error        { return nil }
