//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// This test-only delegate captures real return values and wraps the actual
// snapshot function. Acquisition/Claim/transfer are never replaced with fakes.
type minimalTemplateHandoffProbe struct {
	*minimalLaunchProvider
	source   *minimalTemplateSelection
	owner    *minimalTemplateAssetOwner
	snapshot minimalTemplateSnapshot
}

func (probe *minimalTemplateHandoffProbe) ResolveMinimalSelection(ctx context.Context, hints sandboxruntime.MinimalLaunchSelectionHints) (sandboxruntime.MinimalLaunchSelection, error) {
	selected, err := probe.minimalLaunchProvider.ResolveMinimalSelection(ctx, hints)
	probe.source, _ = selected.(*minimalTemplateSelection)
	return selected, err
}

func (probe *minimalTemplateHandoffProbe) StartMinimalJob(ctx context.Context, reservation *sandboxruntime.MinimalLaunchReservation, source sandboxruntime.MinimalLaunchSelection) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	owner, err := probe.minimalLaunchProvider.startMinimalJob(ctx, reservation, source, probe.snapshot)
	probe.owner, _ = owner.(*minimalTemplateAssetOwner)
	return owner, err
}

type minimalTemplateHandoffInputs struct {
	scope       sandboxruntime.MinimalLaunchScope
	template    []sandboxruntime.MinimalLaunchTemplateIdentity
	correlation []sandboxruntime.MinimalLaunchRequestCorrelation
	preparation time.Duration
}

func newMinimalTemplateHandoffProbe(t *testing.T, configure func(*minimalTemplateHandoffInputs)) (*minimalTemplateHandoffFixture, *minimalTemplateHandoffProbe, *sandboxruntime.MinimalLaunchReservation) {
	t.Helper()
	f := &minimalTemplateHandoffFixture{inputs: newMinimalTemplateFixture(t)}
	inputs := minimalTemplateHandoffInputs{scope: f.inputs.association.scope, template: []sandboxruntime.MinimalLaunchTemplateIdentity{f.inputs.association.template},
		correlation: []sandboxruntime.MinimalLaunchRequestCorrelation{{AdmissionGrantID: "original-admission", AdmissionGrantRevision: 7}}, preparation: 2 * time.Second}
	if configure != nil {
		configure(&inputs)
	}
	var cancel context.CancelFunc
	f.ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	f.owned, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	var err error
	f.provider, err = newMinimalLaunchProvider(f.inputs.association, f.inputs.options)
	if err != nil {
		t.Fatal(err)
	}
	probe := &minimalTemplateHandoffProbe{minimalLaunchProvider: f.provider, snapshot: snapshotJailerRecoveryAsset}
	f.binding, err = sandboxruntime.NewMinimalLaunchProviderBinding(probe)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := sandboxruntime.NewAuthenticatedWorkerPrincipalAuthority("probe-authority", "probe-authority-generation")
	if err != nil {
		t.Fatal(err)
	}
	f.principal, err = authority.IssueAuthenticatedWorkerPrincipal(inputs.scope.PrincipalID, 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	f.authorizer, err = sandboxruntime.NewMinimalLaunchAuthorizer(authority, f.binding, []sandboxruntime.MinimalLaunchScope{inputs.scope})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.authorizer.Close)
	f.selected, err = f.authorizer.ResolveSelection(f.ctx, f.principal, inputs.scope.WorkerID, minimalTemplateHints(), inputs.template...)
	if err != nil || probe.source == nil {
		t.Fatal("real probe selection", err)
	}
	t.Cleanup(func() { _ = f.selected.Close() })
	r, err := f.selected.Reserve(f.ctx, f.owned, "handoff-job", "handoff-job-generation", "request-v2-"+strings.Repeat("c", 64), time.Now().Add(inputs.preparation), inputs.correlation...)
	if err != nil || r.ArmDispatch(f.ctx, r.Identity()) != nil {
		t.Fatal("real probe reserve/arm", err)
	}
	t.Cleanup(r.Revoke)
	t.Cleanup(func() {
		if owner := probe.source.owner; owner != nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, _ = owner.Finalize(ctx)
		}
	})
	return f, probe, r
}

func startMinimalTemplateProbe(t *testing.T, f *minimalTemplateHandoffFixture, probe *minimalTemplateHandoffProbe, r *sandboxruntime.MinimalLaunchReservation) *minimalTemplateAssetOwner {
	t.Helper()
	bound, err := f.binding.Start(r, f.selected, func() error { return nil })
	if bound == nil || !errors.Is(err, sandboxruntime.ErrMinimalLaunchUnavailable) || probe.owner == nil || !probe.owner.sealed {
		t.Fatal("actual claimed/sealed owner was not retained with unavailable runtime", err)
	}
	return probe.owner
}

func assertMinimalTemplateSnapshot(t *testing.T, file *os.File, measured jailerRecoveryAsset, limit int64) {
	t.Helper()
	if file == nil {
		t.Fatal("missing real sealed file")
	}
	identity, err := validateL8RuntimeOwnerSealedRegularFD(int(file.Fd()), limit)
	if err != nil || identity.Size != measured.Size || identity.Device != measured.Device || identity.Inode != measured.Inode {
		t.Fatal("retained FD is not the actual bounded sealed snapshot", err)
	}
	value, err := io.ReadAll(io.NewSectionReader(file, 0, identity.Size))
	if err != nil || int64(len(value)) != identity.Size || sha256Hex(value) != measured.SHA256 {
		t.Fatal("independent snapshot readback differs", err)
	}
	if _, err := file.WriteAt([]byte{0}, 0); err == nil {
		t.Fatal("retained sealed snapshot remained writable")
	}
}

func TestMinimalTemplateHandoffSealedOwnershipAndAliasClose(t *testing.T) {
	f, probe, r := newMinimalTemplateHandoffProbe(t, nil)
	owner := startMinimalTemplateProbe(t, f, probe, r)
	request, _ := r.RequestCorrelation()
	if owner.Identity() != r.Identity() || owner.template != f.inputs.association.template || owner.request != request || owner.context != r.OwnedContext() || probe.source.owner != owner {
		t.Fatal("partial owner did not retain exact original claim/intent/context")
	}
	if owner.measured[1].SHA256 != f.inputs.association.expected.RootfsSHA256 || owner.measured[1].SHA256 == owner.template.RuntimeImageSHA256 {
		t.Fatal("raw rootfs digest was replaced by declared OCI image digest")
	}
	assertMinimalTemplateSnapshot(t, owner.files[0], owner.measured[0], 128<<20)
	assertMinimalTemplateSnapshot(t, owner.files[1], owner.measured[1], 4<<30)
	if probe.source.assets.ConfirmCurrent(f.ctx) == nil || f.selected.Current(f.ctx) != nil {
		t.Fatal("post-transfer Current did not switch to the one actual lease")
	}
	if again, err := probe.source.assets.TakeLaunchLease(f.ctx); again != nil || err == nil {
		t.Fatal("distribution transferred twice")
	}
	if err := probe.source.assets.Close(); err != nil {
		t.Fatal(err)
	}
	if f.selected.Close() != nil || owner.lease.ConfirmCurrent(f.ctx) != nil {
		t.Fatal("selection/distribution alias Close retired the owner lease")
	}
	assertMinimalTemplateSnapshot(t, owner.files[0], owner.measured[0], 128<<20)
	copyOwner := *owner
	if copyOwner.Identity() != (sandboxruntime.MinimalLaunchIdentity{}) {
		t.Fatal("copied owner retained identity authority")
	}
	if receipt, err := copyOwner.Finalize(f.ctx); receipt != (sandboxruntime.MinimalLaunchCleanupReceipt{}) || err == nil || owner.closed {
		t.Fatal("copied owner finalized original assets")
	}
	for range 2 {
		if receipt, err := owner.Finalize(f.ctx); receipt != (sandboxruntime.MinimalLaunchCleanupReceipt{}) || !errors.Is(err, sandboxruntime.ErrMinimalLaunchUnavailable) || owner.closeErr != nil {
			t.Fatal("actual asset close invented a receipt or lost idempotence", err)
		}
	}
	for _, file := range owner.files {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("finalized owner retained an open snapshot", err)
		}
	}
	if owner.lease.ConfirmCurrent(f.ctx) == nil || owner.Identity() != r.Identity() {
		t.Fatal("finalization retained usable inputs or lost original identity")
	}
}

func TestMinimalTemplateHandoffRejectsOriginalAuthorityMismatch(t *testing.T) {
	for _, fault := range []string{"policy", "revision", "principal", "omitted-template", "document", "manifest", "runtime-image", "omitted-request"} {
		t.Run(fault, func(t *testing.T) {
			f, probe, r := newMinimalTemplateHandoffProbe(t, func(inputs *minimalTemplateHandoffInputs) {
				switch fault {
				case "policy":
					inputs.scope.PolicyID = "other-launch-policy"
				case "revision":
					inputs.scope.Revision++
				case "principal":
					inputs.scope.PrincipalID = "other-principal"
				case "omitted-template":
					inputs.template = nil
				case "document":
					inputs.template[0].TemplateDocumentSHA256 = strings.Repeat("d", 64)
				case "manifest":
					inputs.template[0].TemplateManifestSHA256 = strings.Repeat("d", 64)
				case "runtime-image":
					inputs.template[0].RuntimeImageSHA256 = strings.Repeat("d", 64)
					inputs.template[0].RuntimeImage = "registry.example/other@sha256:" + strings.Repeat("d", 64)
				case "omitted-request":
					inputs.correlation = nil
				}
			})
			bound, err := f.binding.Start(r, f.selected, func() error { return nil })
			if bound != nil || !errors.Is(err, sandboxruntime.ErrMinimalLaunchUnavailable) || probe.source.owner != nil || probe.source.assets.ConfirmCurrent(f.ctx) != nil {
				t.Fatal("mismatched original authority transferred assets", err)
			}
		})
	}
}

func TestMinimalTemplateHandoffRejectsCopiedForeignAndLostInputs(t *testing.T) {
	for _, fault := range []string{"nil-provider", "copied-provider", "foreign-provider", "nil-source", "copied-source", "foreign-source", "nil-reservation", "copied-reservation", "nil-context", "wrapped-context", "replayed", "revoked", "closed-source",
		"changed-worker", "changed-host", "changed-template-policy", "changed-workspace-policy", "changed-network-policy", "changed-plan", "changed-runtime", "changed-sandbox", "changed-execution", "changed-submission"} {
		t.Run(fault, func(t *testing.T) {
			f, probe, r := newMinimalTemplateHandoffProbe(t, nil)
			provider, source, reservation, ctx := f.provider, sandboxruntime.MinimalLaunchSelection(probe.source), r, r.Context()
			switch fault {
			case "nil-provider":
				provider = nil
			case "copied-provider":
				copy := *provider
				provider = &copy
			case "foreign-provider":
				provider, _ = newMinimalLaunchProvider(f.inputs.association, f.inputs.options)
			case "nil-source":
				source = nil
			case "copied-source":
				copy := &minimalTemplateSelection{}
				reflect.ValueOf(copy).Elem().Set(reflect.ValueOf(probe.source).Elem())
				source = copy
			case "foreign-source":
				var err error
				source, err = provider.ResolveMinimalSelection(f.ctx, minimalTemplateHints())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = source.Close() })
			case "nil-reservation":
				reservation = nil
			case "copied-reservation":
				reservation = new(sandboxruntime.MinimalLaunchReservation)
				reflect.ValueOf(reservation).Elem().Set(reflect.ValueOf(r).Elem())
			case "nil-context":
				ctx = nil
			case "wrapped-context":
				ctx = context.WithValue(ctx, minimalTemplateHandoffContextKey{}, "same-parent-but-not-original")
			case "replayed":
				if _, err := r.ClaimLaunch(ctx); err != nil {
					t.Fatal(err)
				}
			case "revoked":
				r.Revoke()
			case "closed-source":
				_ = source.Close()
			// These are negative mutations after genuine acquisition, never
			// supplied as accepted selection authority or fake workflow results.
			case "changed-worker":
				probe.source.identity.WorkerID = "other-worker"
			case "changed-host":
				probe.source.identity.HostID = "other-host"
			case "changed-template-policy":
				probe.source.identity.TemplatePolicyID = "other-template"
			case "changed-workspace-policy":
				probe.source.identity.WorkspacePolicyID = "other-workspace"
			case "changed-network-policy":
				probe.source.identity.NetworkPolicyID = "other-network"
			case "changed-plan":
				probe.source.identity.PlanID, probe.source.hints.PlanID = "other-plan", "other-plan"
			case "changed-runtime":
				probe.source.identity.RuntimeID, probe.source.hints.RuntimeID = "other-runtime", "other-runtime"
			case "changed-sandbox":
				probe.source.hints.SandboxID = "other-sandbox"
			case "changed-execution":
				probe.source.hints.ExecutionID = "other-execution"
			case "changed-submission":
				probe.source.hints.SubmissionID = "other-submission"
			}
			owner, err := provider.StartMinimalJob(ctx, reservation, source)
			if owner != nil || !errors.Is(err, sandboxruntime.ErrMinimalLaunchUnavailable) || probe.source.owner != nil {
				t.Fatal("invalid original input retained asset ownership", err)
			}
			if fault != "closed-source" && probe.source.assets.ConfirmCurrent(f.ctx) != nil {
				t.Fatal("invalid input transferred or closed original files")
			}
		})
	}
}

func TestMinimalTemplateHandoffPreparationExpiryIsNotOwnerExpiry(t *testing.T) {
	f, probe, r := newMinimalTemplateHandoffProbe(t, func(inputs *minimalTemplateHandoffInputs) { inputs.preparation = 500 * time.Millisecond })
	owner := startMinimalTemplateProbe(t, f, probe, r)
	<-r.Context().Done()
	if r.OwnedContext().Err() != nil || f.selected.Current(f.ctx) != nil || owner.context != r.OwnedContext() {
		t.Fatal("preparation expiry rebased or revoked original retained ownership")
	}
	r.Revoke()
	if f.selected.Current(f.ctx) == nil || owner.context.Err() != context.Canceled || owner.closed {
		t.Fatal("explicit revocation lost retained uncertain cleanup ownership")
	}
	if receipt, err := owner.Finalize(f.ctx); receipt != (sandboxruntime.MinimalLaunchCleanupReceipt{}) || err == nil || !owner.closed || owner.closeErr != nil {
		t.Fatal("revoked original owner could not close partial assets without a receipt")
	}
}
