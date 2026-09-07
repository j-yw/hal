package sandboxworker

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestMinimalLaunchServiceTemplateIdentityReachesOriginalClaim(t *testing.T) {
	for _, mutation := range []string{"none", "Resolve", "last Current"} {
		t.Run(mutation, func(t *testing.T) {
			f := newMinimalLaunchDispatchFixture(t)
			want := minimalLaunchTemplateRequest(t, f)
			// Keep the existing provider's independent record oracle immutable.
			input := f.request
			start := *f.request.JobStartV2
			metadata := *start.Exec.Target.Runtime.Metadata
			metadata.TemplateLock = sandboxruntime.CloneRuntimeTemplateLockMetadata(metadata.TemplateLock)
			start.Exec.Target.Runtime.Metadata = &metadata
			input.JobStartV2 = &start
			p := &minimalLaunchTemplateObserver{minimalLaunchDispatchProvider: f.provider, input: input.JobStartV2, mutation: mutation}
			s := minimalLaunchRequestService(t, f, p)
			key, err := jobRequestKeyV2(input.DriverID, "principal-l8-worker", l8WorkerV2DaemonGeneration, *input.JobStartV2)
			if err != nil {
				t.Fatal(err)
			}
			response := s.HandleAuthenticatedRequest(context.Background(), f.principal, input)
			if response.OK || p.startCalls != 1 || !p.checkedDispatch || p.reservation == nil || p.resolveCalls != 1 || p.recoverCalls != 0 || p.currentCalls != 3 {
				t.Fatal("fixture did not reach original provider Claim after actual durable dispatch")
			}
			if p.reservation.Identity().RequestKey != key {
				t.Fatal("callback changed the original pre-resolution request key")
			}
			if p.mutated != (mutation != "none") {
				t.Fatal("genuine callback mutation prerequisite was not reached")
			}
			if p.observationErr != nil || p.observed != want {
				t.Fatalf("actual claimed provider lost original template tuple: got=%+v err=%v", p.observed, p.observationErr)
			}
			// These follow the unavailable-accessor RED and are not prior evidence.
			if p.reservation.Context().Err() == nil || p.reservation.OwnedContext().Err() == nil {
				t.Fatal("partial failed Start lost existing revocation")
			}
			if got, err := p.reservation.TemplateIdentity(); err != nil || got != want {
				t.Fatal("uncertain Start erased original template correlation")
			}
		})
	}
}

func TestMinimalLaunchServiceTemplateIdentityRejectsMalformedBeforeProvider(t *testing.T) {
	for _, fixture := range []struct {
		name   string
		mutate func(*RuntimeTarget)
	}{
		{"missing image", func(r *RuntimeTarget) { r.Image = "" }},
		{"missing metadata", func(r *RuntimeTarget) { r.Metadata = nil }},
		{"missing lock", func(r *RuntimeTarget) { r.Metadata.TemplateLock = nil }},
		{"empty lock", func(r *RuntimeTarget) { r.Metadata.TemplateLock = &sandboxruntime.RuntimeTemplateLockMetadata{} }},
		{"missing document", func(r *RuntimeTarget) { r.Metadata.TemplateLock.Document = nil }},
		{"missing manifest", func(r *RuntimeTarget) { r.Metadata.TemplateLock.TemplateReference = nil }},
		{"missing runtime digest", func(r *RuntimeTarget) { r.Metadata.TemplateLock.RuntimeImage = nil }},
		{"document wrong source", func(r *RuntimeTarget) { r.Metadata.TemplateLock.Document.SourceKind = "local_file" }},
		{"document wrong reference", func(r *RuntimeTarget) { r.Metadata.TemplateLock.Document.ReferenceKind = "local" }},
		{"manifest wrong role", func(r *RuntimeTarget) { r.Metadata.TemplateLock.TemplateReference.SourceKind = "runtime_image" }},
		{"manifest wrong kind", func(r *RuntimeTarget) { r.Metadata.TemplateLock.TemplateReference.ReferenceKind = "oci_image" }},
		{"runtime wrong role", func(r *RuntimeTarget) { r.Metadata.TemplateLock.RuntimeImage.SourceKind = "template_reference" }},
		{"runtime wrong kind", func(r *RuntimeTarget) { r.Metadata.TemplateLock.RuntimeImage.ReferenceKind = "oci_artifact" }},
		{"unlocked document", func(r *RuntimeTarget) { r.Metadata.TemplateLock.Document.Status = "unresolved" }},
		{"unlocked manifest", func(r *RuntimeTarget) { r.Metadata.TemplateLock.TemplateReference.Status = "unresolved" }},
		{"unlocked runtime", func(r *RuntimeTarget) { r.Metadata.TemplateLock.RuntimeImage.Status = "unresolved" }},
		{"wrong algorithm", func(r *RuntimeTarget) { r.Metadata.TemplateLock.Document.DigestAlgorithm = "sha512" }},
		{"uppercase digest", func(r *RuntimeTarget) {
			r.Metadata.TemplateLock.TemplateReference.DigestValue = strings.Repeat("B", 64)
		}},
		{"short digest", func(r *RuntimeTarget) { r.Metadata.TemplateLock.Document.DigestValue = strings.Repeat("a", 63) }},
		{"image suffix mismatch", func(r *RuntimeTarget) { r.Metadata.TemplateLock.RuntimeImage.DigestValue = strings.Repeat("d", 64) }},
		{"mutable image", func(r *RuntimeTarget) { r.Image = "registry.test/hal/minimal:stable" }},
		{"host path", func(r *RuntimeTarget) { r.Image = "/task/minimal@sha256:" + strings.Repeat("c", 64) }},
		{"URL scheme", func(r *RuntimeTarget) { r.Image = "https://" + r.Image }},
		{"extra at", func(r *RuntimeTarget) { r.Image = "user@" + r.Image }},
		{"space", func(r *RuntimeTarget) { r.Image = " " + r.Image }},
		{"control", func(r *RuntimeTarget) { r.Image = "bad\x00" + r.Image }},
		{"shell punctuation", func(r *RuntimeTarget) { r.Image = "bad;" + r.Image }},
		{"oversize", func(r *RuntimeTarget) {
			r.Image = strings.Repeat("i", 4097-len("@sha256:")-64) + "@sha256:" + strings.Repeat("c", 64)
		}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			f := newMinimalLaunchDispatchFixture(t)
			minimalLaunchTemplateRequest(t, f)
			fixture.mutate(&f.request.JobStartV2.Exec.Target.Runtime)
			if err := f.request.Validate(); err != nil {
				t.Fatalf("fixture did not reach missing selected-template validation: %v", err)
			}
			t.Cleanup(f.authorizer.Close)
			s := f.service(t)
			response := s.HandleAuthenticatedRequest(context.Background(), f.principal, f.request)
			if response.OK || response.Error == nil || response.Error.Code != ErrorCodeMalformedRequest || f.provider.resolveCalls != 0 || f.provider.startCalls != 0 || len(minimalLaunchRecordFiles(t, f.stateDir)) != 0 {
				t.Fatal("malformed provided template entered provider or persisted a reservation")
			}
		})
	}
}

func TestMinimalLaunchServiceTemplateIdentityIndependentControls(t *testing.T) {
	for _, mode := range []string{"valid three-role lock", "original omission", "foreign issuer", "foreign principal"} {
		t.Run(mode, func(t *testing.T) {
			f := newMinimalLaunchDispatchFixture(t)
			if mode != "original omission" {
				minimalLaunchTemplateRequest(t, f)
			}
			t.Cleanup(f.authorizer.Close)
			s := f.service(t)
			principal := f.principal
			switch mode {
			case "foreign issuer":
				_, principal = l8D6WorkerPrincipal(t)
			case "foreign principal":
				var err error
				principal, err = f.authority.IssueAuthenticatedWorkerPrincipal("foreign-template-principal", 1000, 1000)
				if err != nil {
					t.Fatal(err)
				}
			}
			response := s.HandleAuthenticatedRequest(context.Background(), principal, f.request)
			if response.OK {
				t.Fatal("incomplete fake provider manufactured job success")
			}
			if mode == "valid three-role lock" || mode == "original omission" {
				if f.provider.startCalls != 1 || !f.provider.checkedDispatch || f.provider.resolveCalls != 1 {
					t.Fatal("independent actual Start/Claim/durable readback control was not reached")
				}
			} else {
				f.assertNoProviderOrRecord(t)
			}
		})
	}
}

func TestMinimalLaunchServiceTemplateIdentityKeyControls(t *testing.T) {
	f := newMinimalLaunchDispatchFixture(t)
	t.Cleanup(f.authorizer.Close)
	minimalLaunchTemplateRequest(t, f)
	key, err := jobRequestKeyV2(f.request.DriverID, "principal-l8-worker", l8WorkerV2DaemonGeneration, *f.request.JobStartV2)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"image", "document", "manifest", "runtime"} {
		t.Run(field, func(t *testing.T) {
			start := *f.request.JobStartV2
			metadata := *start.Exec.Target.Runtime.Metadata
			metadata.TemplateLock = sandboxruntime.CloneRuntimeTemplateLockMetadata(metadata.TemplateLock)
			start.Exec.Target.Runtime.Metadata = &metadata
			switch field {
			case "image":
				start.Exec.Target.Runtime.Image = "other.test/hal/minimal@sha256:" + strings.Repeat("c", 64)
			case "document":
				metadata.TemplateLock.Document.DigestValue = strings.Repeat("d", 64)
			case "manifest":
				metadata.TemplateLock.TemplateReference.DigestValue = strings.Repeat("d", 64)
			case "runtime":
				metadata.TemplateLock.RuntimeImage.DigestValue = strings.Repeat("d", 64)
			}
			changed, err := jobRequestKeyV2(f.request.DriverID, "principal-l8-worker", l8WorkerV2DaemonGeneration, start)
			if err != nil || changed == key {
				t.Fatal("existing canonical key did not distinguish this original template field")
			}
		})
	}
}

type minimalLaunchTemplateObserver struct {
	*minimalLaunchDispatchProvider
	input          *JobStartRequestV2
	mutation       string
	currentCalls   int
	mutated        bool
	reservation    *sandboxruntime.MinimalLaunchReservation
	observed       sandboxruntime.MinimalLaunchTemplateIdentity
	observationErr error
}

func (p *minimalLaunchTemplateObserver) ResolveMinimalSelection(ctx context.Context, hints sandboxruntime.MinimalLaunchSelectionHints) (sandboxruntime.MinimalLaunchSelection, error) {
	if _, err := p.minimalLaunchDispatchProvider.ResolveMinimalSelection(ctx, hints); err != nil {
		return nil, err
	}
	if p.mutation == "Resolve" {
		p.mutateCaller()
	}
	return p, nil
}

func (p *minimalLaunchTemplateObserver) Current(ctx context.Context) (sandboxruntime.MinimalLaunchSelectionIdentity, error) {
	p.currentCalls++
	if p.mutation == "last Current" && p.currentCalls == 3 {
		p.mutateCaller()
	}
	return p.selection.Current(ctx)
}

func (p *minimalLaunchTemplateObserver) Close() error { return p.selection.Close() }

func (p *minimalLaunchTemplateObserver) StartMinimalJob(ctx context.Context, r *sandboxruntime.MinimalLaunchReservation, selected sandboxruntime.MinimalLaunchSelection) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	if selected != p {
		return nil, errors.New("test-only original selection mismatch")
	}
	// Preserve the original fixture's actual Claim and independent disk oracle;
	// it owns the wrapped selection and intentionally returns uncertain failure.
	owner, err := p.minimalLaunchDispatchProvider.StartMinimalJob(ctx, r, p.selection)
	p.reservation = r
	p.observed, p.observationErr = r.TemplateIdentity()
	return owner, err
}

func (p *minimalLaunchTemplateObserver) mutateCaller() {
	p.mutated = true
	r := &p.input.Exec.Target.Runtime
	r.Image = "changed.test/hal/minimal@sha256:" + strings.Repeat("f", 64)
	r.Metadata.TemplateLock.Document.DigestValue = strings.Repeat("d", 64)
	r.Metadata.TemplateLock.TemplateReference.DigestValue = strings.Repeat("e", 64)
	r.Metadata.TemplateLock.RuntimeImage.DigestValue = strings.Repeat("f", 64)
}

func minimalLaunchTemplateRequest(t *testing.T, f *minimalLaunchDispatchFixture) sandboxruntime.MinimalLaunchTemplateIdentity {
	t.Helper()
	want := sandboxruntime.MinimalLaunchTemplateIdentity{RuntimeImage: "registry.test/hal/minimal:locked@sha256:" + strings.Repeat("c", 64), TemplateDocumentSHA256: strings.Repeat("a", 64), TemplateManifestSHA256: strings.Repeat("b", 64), RuntimeImageSHA256: strings.Repeat("c", 64)}
	lock := &sandboxruntime.RuntimeTemplateLockMetadata{
		Document:          &sandboxruntime.RuntimeTemplateLockEntryMetadata{SourceKind: "oci_artifact", ReferenceKind: "oci_artifact", Status: "locked", DigestAlgorithm: "sha256", DigestValue: want.TemplateDocumentSHA256},
		TemplateReference: &sandboxruntime.RuntimeTemplateLockEntryMetadata{SourceKind: "template_reference", ReferenceKind: "oci_artifact", Status: "locked", DigestAlgorithm: "sha256", DigestValue: want.TemplateManifestSHA256},
		RuntimeImage:      &sandboxruntime.RuntimeTemplateLockEntryMetadata{SourceKind: "runtime_image", ReferenceKind: "oci_image", Status: "locked", DigestAlgorithm: "sha256", DigestValue: want.RuntimeImageSHA256},
		TrustPolicy:       &sandboxruntime.RuntimeTemplateTrustPolicyMetadata{Mode: "strict", Decision: "trusted", SourceKind: "oci_artifact", ReferenceKind: "oci_artifact", Status: "locked", DigestAlgorithm: "sha256", DigestValue: want.TemplateManifestSHA256},
	}
	if !reflect.DeepEqual(lock, sandboxruntime.SanitizeRuntimeTemplateLockMetadata(lock)) || want.TemplateDocumentSHA256 == want.TemplateManifestSHA256 || want.TemplateManifestSHA256 == want.RuntimeImageSHA256 {
		t.Fatal("fixture's distinct selected OCI roles are not stable canonical metadata")
	}
	f.request.JobStartV2.Exec.Target.Runtime.Image = want.RuntimeImage
	f.request.JobStartV2.Exec.Target.Runtime.Metadata = &sandboxruntime.RuntimeMetadata{TemplateLock: lock}
	if err := f.request.Validate(); err != nil {
		t.Fatal(err)
	}
	return want
}
