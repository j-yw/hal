//go:build linux

package firecrackerhost

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
)

// Start can retain only claimed, sealed asset ownership. The runtime consumer
// is still unavailable; neither this handoff nor Finalize issues a receipt.
func (provider *minimalLaunchProvider) StartMinimalJob(ctx context.Context, reservation *sandboxruntime.MinimalLaunchReservation, selected sandboxruntime.MinimalLaunchSelection) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	return provider.startMinimalJob(ctx, reservation, selected, snapshotJailerRecoveryAsset)
}

// The fixed production snapshot runs inside source serialization and the lease
// borrow. It must not reenter Current, Close or Finalize, or retain its reader.
type minimalTemplateSnapshot func(context.Context, string, io.Reader, int64, string, int64) (*os.File, jailerRecoveryAsset, error)

func (provider *minimalLaunchProvider) startMinimalJob(ctx context.Context, reservation *sandboxruntime.MinimalLaunchReservation, selected sandboxruntime.MinimalLaunchSelection, snapshot minimalTemplateSnapshot) (result sandboxruntime.MinimalJobRuntimeOwner, retErr error) {
	var owner *minimalTemplateAssetOwner
	defer func() {
		if recover() != nil {
			if owner != nil {
				result = owner
			}
			retErr = sandboxruntime.ErrMinimalLaunchUnavailable
		}
	}()
	source, ok := selected.(*minimalTemplateSelection)
	if !ok || source == nil || source.self != source || provider == nil || provider.self != provider || source.provider != provider ||
		reservation == nil || ctx != reservation.Context() || snapshot == nil {
		return nil, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	if err := minimalTemplateContextError(ctx); err != nil {
		return nil, err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.closed || source.owner != nil || !source.matchesAssociation() {
		return nil, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	if err := minimalTemplateContextError(ctx); err != nil {
		return nil, err
	}
	identity, err := reservation.ClaimLaunch(ctx)
	if err != nil || identity != reservation.Identity() || !minimalTemplateClaimMatches(identity, source) {
		return nil, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	template, templateErr := reservation.TemplateIdentity()
	request, requestErr := reservation.RequestCorrelation()
	owned := reservation.OwnedContext()
	if templateErr != nil || requestErr != nil || template != source.template || template != provider.association.template || !minimalTemplateOwnerCurrent(owned) {
		return nil, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	// This original source owns the partial result before transfer or any
	// snapshot callback. Selection Close must never take that ownership back.
	p, _ := ctx.Deadline() // minimalTemplateContextError already required this exact bound.
	owner = &minimalTemplateAssetOwner{source: source, identity: identity, template: template, request: request, context: owned, preparation: ctx, preparationDeadline: p, reservation: reservation}
	owner.self = owner
	source.owner = owner
	result = owner
	if source.assets.ConfirmCurrent(ctx) != nil || minimalTemplateContextError(ctx) != nil {
		return owner, minimalTemplateFailure(ctx)
	}
	owner.lease, err = source.assets.TakeLaunchLease(ctx)
	if err != nil || owner.lease == nil || owner.lease.ConfirmCurrent(ctx) != nil {
		return owner, minimalTemplateFailure(ctx)
	}
	err = owner.lease.WithAssets(ctx, func(kernel, rootfs localresolver.L8MinimalLaunchAsset) error {
		if rootfs.SHA256 != provider.association.expected.RootfsSHA256 {
			return sandboxruntime.ErrMinimalLaunchUnavailable
		}
		for index, input := range []localresolver.L8MinimalLaunchAsset{kernel, rootfs} {
			if minimalTemplateContextError(ctx) != nil {
				return sandboxruntime.ErrMinimalLaunchUnavailable
			}
			kind, limit := "kernel", int64(128<<20)
			if index == 1 {
				kind, limit = "rootfs", 4<<30
			}
			file, measured, err := snapshot(ctx, kind, input.Source, input.SizeBytes, input.SHA256, limit)
			// A returned file is owned even alongside an error. Retain it before
			// checking metadata or invoking the next allocating callback.
			owner.files[index], owner.measured[index] = file, measured
			if err != nil || file == nil || measured.Kind != kind || measured.Size != input.SizeBytes || measured.SHA256 != input.SHA256 || minimalTemplateContextError(ctx) != nil {
				return sandboxruntime.ErrMinimalLaunchUnavailable
			}
		}
		return nil
	})
	if err != nil || owner.lease.ConfirmCurrent(ctx) != nil || minimalTemplateContextError(ctx) != nil || !minimalTemplateOwnerCurrent(owned) {
		return owner, minimalTemplateFailure(ctx)
	}
	owner.sealed = true
	return owner, sandboxruntime.ErrMinimalLaunchUnavailable
}

func minimalTemplateOwnerCurrent(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	deadline, bounded := ctx.Deadline()
	return !bounded || time.Now().Before(deadline)
}

func minimalTemplateClaimMatches(identity sandboxruntime.MinimalLaunchIdentity, source *minimalTemplateSelection) bool {
	scope, selected, hints := source.provider.association.scope, source.identity, source.hints
	return identity.PrincipalID == scope.PrincipalID && identity.WorkerID == scope.WorkerID && identity.HostID == scope.HostID &&
		identity.LaunchPolicyID == scope.PolicyID && identity.LaunchPolicyRevision == scope.Revision &&
		identity.RuntimeID == selected.RuntimeID && identity.RuntimeGeneration == selected.RuntimeGeneration && identity.PlanID == selected.PlanID &&
		identity.SandboxID == hints.SandboxID && identity.ExecutionID == hints.ExecutionID && identity.SubmissionID == hints.SubmissionID
}

// All mutable fields share source.mu with Start, Current and alias Close.
// Preparation uses reservation.Context; retained ownership uses its original
// OwnedContext, never a replacement context based on the preparation deadline.
type minimalTemplateAssetOwner struct {
	self                *minimalTemplateAssetOwner
	source              *minimalTemplateSelection
	identity            sandboxruntime.MinimalLaunchIdentity
	template            sandboxruntime.MinimalLaunchTemplateIdentity
	request             sandboxruntime.MinimalLaunchRequestCorrelation
	context             context.Context
	preparation         context.Context
	preparationDeadline time.Time
	reservation         *sandboxruntime.MinimalLaunchReservation
	attempt             *minimalPreexecAttempt
	cleanupDone         chan struct{}
	assetsClosed        bool
	lease               *localresolver.VerifiedL8MinimalLaunchLease
	files               [2]*os.File
	measured            [2]jailerRecoveryAsset
	sealed              bool
	closed              bool
	closeErr            error
}

func (owner *minimalTemplateAssetOwner) Identity() sandboxruntime.MinimalLaunchIdentity {
	if owner == nil || owner.self != owner {
		return sandboxruntime.MinimalLaunchIdentity{}
	}
	return owner.identity
}

func (owner *minimalTemplateAssetOwner) Finalize(ctx context.Context) (sandboxruntime.MinimalLaunchCleanupReceipt, error) {
	if owner == nil || owner.self != owner || owner.source == nil || minimalTemplateContextError(ctx) != nil {
		return sandboxruntime.MinimalLaunchCleanupReceipt{}, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	owner.source.mu.Lock()
	defer owner.source.mu.Unlock()
	if owner.source.owner != owner || minimalTemplateContextError(ctx) != nil {
		return sandboxruntime.MinimalLaunchCleanupReceipt{}, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	if !owner.closed {
		owner.closed = true
		for _, file := range owner.files {
			if file != nil && file.Close() != nil {
				owner.closeErr = sandboxruntime.ErrMinimalLaunchUnavailable
			}
		}
		var err error
		if owner.lease != nil {
			err = owner.lease.Close()
		} else {
			err = owner.source.assets.Close()
		}
		if err != nil {
			owner.closeErr = sandboxruntime.ErrMinimalLaunchUnavailable
		}
	}
	// Even successful asset closure is not runtime/terminal cleanup proof.
	return sandboxruntime.MinimalLaunchCleanupReceipt{}, sandboxruntime.ErrMinimalLaunchUnavailable
}

// Recovery remains cleanup-only and unavailable without its original owner.
func (provider *minimalLaunchProvider) RecoverMinimalJob(context.Context, sandboxruntime.MinimalLaunchIdentity) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	return nil, sandboxruntime.ErrMinimalLaunchUnavailable
}
