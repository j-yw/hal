package sandboxworker

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestMinimalLaunchServiceTemplateIdentityAfterPreparation(t *testing.T) {
	for _, action := range []string{"cancel", "service", "authority"} {
		t.Run(action, func(t *testing.T) {
			f := newMinimalLaunchOwnedContextFixture(t, 750*time.Millisecond)
			want := minimalLaunchTemplateRequest(t, f.base)
			f.start(t, context.Background())
			waitMinimalLaunchOwnedContext(t, f.provider.ctx)
			if got, err := f.provider.reservation.TemplateIdentity(); err != nil || got != want {
				t.Fatal("P erased actual accepted template")
			}
			switch action {
			case "cancel":
				if response := f.service.HandleAuthenticatedRequest(context.Background(), f.base.principal, f.cancelRequest(t)); response.OK {
					t.Fatal("cancel manufactured terminal completion")
				}
			case "service":
				f.service.Close()
			case "authority":
				f.base.authorizer.Close()
			}
			waitMinimalLaunchOwnedContext(t, f.provider.reservation.OwnedContext())
			if got, err := f.provider.reservation.TemplateIdentity(); err != nil || got != want {
				t.Fatal("actual service ownership loss erased original template")
			}
			f.assertRetained(t, action == "cancel")
		})
	}
}

func TestMinimalLaunchServiceTemplateIdentityDuplicateExactness(t *testing.T) {
	for _, mode := range []string{"same request", "image", "document", "manifest", "runtime", "omission"} {
		t.Run(mode, func(t *testing.T) {
			f := newMinimalLaunchOwnedContextFixture(t, time.Minute)
			want := minimalLaunchTemplateRequest(t, f.base)
			f.start(t, context.Background())
			before := f.recordBytes(t)
			request := f.base.request
			start := *request.JobStartV2
			metadata := *start.Exec.Target.Runtime.Metadata
			metadata.TemplateLock = sandboxruntime.CloneRuntimeTemplateLockMetadata(metadata.TemplateLock)
			start.Exec.Target.Runtime.Metadata, request.JobStartV2 = &metadata, &start
			switch mode {
			case "image":
				start.Exec.Target.Runtime.Image = "different.test/minimal@sha256:" + want.RuntimeImageSHA256
			case "document":
				metadata.TemplateLock.Document.DigestValue = strings.Repeat("d", 64)
			case "manifest":
				metadata.TemplateLock.TemplateReference.DigestValue = strings.Repeat("d", 64)
			case "runtime":
				metadata.TemplateLock.RuntimeImage.DigestValue = strings.Repeat("d", 64)
				start.Exec.Target.Runtime.Image = "registry.test/hal/minimal:locked@sha256:" + strings.Repeat("d", 64)
			case "omission":
				start.Exec.Target.Runtime.Image, metadata.TemplateLock = "", nil
			}
			response := f.service.HandleAuthenticatedRequest(context.Background(), f.base.principal, request)
			if mode == "same request" {
				if !response.OK || response.JobV2 == nil || response.JobV2.ID != f.provider.reservation.Identity().WorkerJobID || response.JobV2.State != JobStateQueued || response.JobV2.FinishedAt != nil || response.JobV2.StartedAt != nil {
					t.Fatal("exact duplicate did not resolve original queued job")
				}
			} else if response.OK {
				t.Fatal("changed original template reused accepted submission")
			}
			if f.provider.starts != 1 || f.provider.base.resolveCalls != 1 || !bytes.Equal(before, f.recordBytes(t)) {
				t.Fatal("duplicate or conflict resolved, allocated or wrote again")
			}
			if got, err := f.provider.reservation.TemplateIdentity(); err != nil || got != want {
				t.Fatal("duplicate request relabeled original template")
			}
		})
	}
}

func TestMinimalLaunchServiceTemplateIdentityExactSizeAndOmittedMetadata(t *testing.T) {
	for _, mode := range []string{"4096", "4097", "unrelated metadata omission"} {
		t.Run(mode, func(t *testing.T) {
			f := newMinimalLaunchOwnedContextFixture(t, time.Minute)
			var want sandboxruntime.MinimalLaunchTemplateIdentity
			if mode == "unrelated metadata omission" {
				f.base.request.JobStartV2.Exec.Target.Runtime.Metadata = &sandboxruntime.RuntimeMetadata{}
			} else {
				want = minimalLaunchTemplateRequest(t, f.base)
				length := 4096
				if mode == "4097" {
					length++
				}
				want.RuntimeImage = strings.Repeat("i", length-len("@sha256:")-64) + "@sha256:" + want.RuntimeImageSHA256
				f.base.request.JobStartV2.Exec.Target.Runtime.Image = want.RuntimeImage
			}
			if err := f.base.request.Validate(); err != nil {
				t.Fatal("fixture missed selected intake", err)
			}
			if mode == "4097" {
				response := f.service.HandleAuthenticatedRequest(context.Background(), f.base.principal, f.base.request)
				if response.OK || response.Error == nil || response.Error.Code != ErrorCodeMalformedRequest || f.provider.starts != 0 || f.provider.base.resolveCalls != 0 || len(minimalLaunchRecordFiles(t, f.base.stateDir)) != 0 {
					t.Fatal("oversize original identity entered provider")
				}
				return
			}
			f.start(t, context.Background())
			got, err := f.provider.reservation.TemplateIdentity()
			if mode == "4096" && (err != nil || got != want) || mode == "unrelated metadata omission" && (err == nil || got != want) {
				t.Fatal("boundary or unrelated metadata changed exact optional identity")
			}
		})
	}
}

type minimalLaunchTemplatePartialProvider struct {
	*minimalLaunchOwnedContextProvider
}

func (p *minimalLaunchTemplatePartialProvider) StartMinimalJob(ctx context.Context, r *sandboxruntime.MinimalLaunchReservation, selected sandboxruntime.MinimalLaunchSelection) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	owner, err := p.minimalLaunchOwnedContextProvider.StartMinimalJob(ctx, r, selected)
	if err != nil {
		return owner, err
	}
	return owner, sandboxruntime.ErrMinimalLaunchUnavailable // Retain genuine partial ownership.
}

func TestMinimalLaunchServiceTemplateIdentityPartialOwnerRetained(t *testing.T) {
	f := newMinimalLaunchDispatchFixture(t)
	want := minimalLaunchTemplateRequest(t, f)
	p := &minimalLaunchTemplatePartialProvider{&minimalLaunchOwnedContextProvider{base: f.provider}}
	s := minimalLaunchRequestService(t, f, p)
	response := s.HandleAuthenticatedRequest(context.Background(), f.principal, f.request)
	if response.OK || p.starts != 1 || p.reservation == nil || p.reservation.OwnedContext().Err() == nil {
		t.Fatal("partial Start did not reach original revoked reservation")
	}
	id := p.reservation.Identity()
	s.jobs.mu.Lock()
	entry, state := s.jobs.minimalLive[id.WorkerJobID], s.jobs.states[id.WorkerJobID]
	s.jobs.mu.Unlock()
	if entry == nil || entry.reservation != p.reservation || entry.owner == nil || state.JobV2.State != JobStateQueued || state.JobV2.FinishedAt != nil || state.MinimalLaunch.Phase != "dispatching" {
		t.Fatal("uncertain partial owner was released or marked terminal")
	}
	select {
	case <-entry.dispatchDone:
	default:
		t.Fatal("partial owner publication did not precede joined dispatch")
	}
	if got, err := p.reservation.TemplateIdentity(); err != nil || got != want {
		t.Fatal("retained partial owner lost original template")
	}
	s.Close()
	if got, err := p.reservation.TemplateIdentity(); err != nil || got != want {
		t.Fatal("service close erased retained partial-owner intent")
	}
}
