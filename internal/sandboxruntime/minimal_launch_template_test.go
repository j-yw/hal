package sandboxruntime

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMinimalReservationTemplateIdentitySyntaxBoundaries(t *testing.T) {
	suffix := "@sha256:" + strings.Repeat("c", 64)
	for _, fixture := range []struct {
		name, prefix string
		valid        bool
	}{
		{"one byte", "a", true},
		{"selected alphabet", "A0._-:5000/path/image:tag", true},
		{"4096 bytes", strings.Repeat("i", 4096-len(suffix)), true},
		{"4097 bytes", strings.Repeat("i", 4097-len(suffix)), false},
		{"missing prefix", "", false},
		{"leading dash", "-image", false},
		{"leading dot", ".image", false},
		{"leading underscore", "_image", false},
		{"leading slash", "/image", false},
		{"URL", "https://registry/image", false},
		{"query", "image?query", false},
		{"fragment", "image#fragment", false},
		{"extra delimiter", "user@image", false},
		{"backslash", "image\\path", false},
		{"line feed", "image\n", false},
		{"tab", "image\t", false},
		{"space", "image ", false},
		{"nul", "image\x00", false},
		{"unicode", "image-é", false},
		{"shell", "image$(value)", false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			f := newMinimalTemplateIdentityFixture(t)
			want := minimalTemplateIdentityValue()
			want.RuntimeImage = fixture.prefix + suffix
			s, err := f.authorizer.ResolveSelection(context.Background(), f.principal, "template-worker", f.hints, want)
			if !fixture.valid {
				if s != nil || !errors.Is(err, ErrMinimalLaunchUnavailable) || f.provider.resolves != 0 {
					t.Fatal("invalid selected syntax entered the resolver")
				}
				return
			}
			if err != nil || s == nil || f.provider.resolves != 1 {
				t.Fatal("valid bounded syntax did not resolve", err)
			}
			t.Cleanup(func() { _ = s.Close() })
			r := f.start(t, s)
			if got, err := r.TemplateIdentity(); err != nil || got != want {
				t.Fatal("valid exact image was truncated or normalized")
			}
		})
	}
	for _, field := range []string{"document", "manifest", "runtime"} {
		for _, digest := range []string{strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("1", 63), strings.Repeat("1", 65)} {
			t.Run(field+"/"+digest, func(t *testing.T) {
				f := newMinimalTemplateIdentityFixture(t)
				value := minimalTemplateIdentityValue()
				switch field {
				case "document":
					value.TemplateDocumentSHA256 = digest
				case "manifest":
					value.TemplateManifestSHA256 = digest
				case "runtime":
					value.RuntimeImageSHA256 = digest
					value.RuntimeImage = "image@sha256:" + digest
				}
				if s, err := f.authorizer.ResolveSelection(context.Background(), f.principal, "template-worker", f.hints, value); s != nil || !errors.Is(err, ErrMinimalLaunchUnavailable) || f.provider.resolves != 0 {
					t.Fatal("invalid digest role entered the resolver")
				}
			})
		}
	}
}

func TestMinimalReservationTemplateIdentityRetainsAcrossPreparationAndCopies(t *testing.T) {
	f := newMinimalTemplateIdentityFixture(t)
	want := minimalTemplateIdentityValue()
	s, err := f.authorizer.ResolveSelection(context.Background(), f.principal, "template-worker", f.hints, want)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	r, err := s.Reserve(context.Background(), context.Background(), "template-job", "template-generation", "request-v2-"+strings.Repeat("a", 64), time.Now().Add(400*time.Millisecond))
	if err != nil || r.ArmDispatch(context.Background(), r.Identity()) != nil {
		t.Fatal("actual reservation did not arm", err)
	}
	t.Cleanup(r.Revoke)
	if owner, err := f.binding.Start(r, s, func() error { return nil }); err != nil || owner == nil {
		t.Fatal("actual provider did not claim before P", err)
	}
	copied := new(MinimalLaunchReservation)
	reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(r).Elem())
	for _, invalid := range []*MinimalLaunchReservation{nil, new(MinimalLaunchReservation), copied} {
		if got, err := invalid.TemplateIdentity(); got != (MinimalLaunchTemplateIdentity{}) || !errors.Is(err, ErrMinimalLaunchUnavailable) {
			t.Fatal("copied or unissued handle exposed template")
		}
	}
	select {
	case <-r.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("preparation did not expire")
	}
	if r.Context().Err() != context.DeadlineExceeded || r.OwnedContext().Err() != nil {
		t.Fatal("fixture did not reach preparation-only expiry")
	}
	if got, err := r.TemplateIdentity(); err != nil || got != want {
		t.Fatal("preparation expiry erased original template")
	}
	var readers sync.WaitGroup
	for range 8 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 32 {
				got, err := r.TemplateIdentity()
				if err != nil || got != want {
					t.Error("concurrent original observation changed")
				}
				got.RuntimeImage = "returned copy"
			}
		}()
	}
	r.Revoke()
	f.authorizer.Close()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	readers.Wait()
	if got, err := r.TemplateIdentity(); err != nil || got != want || r.OwnedContext().Err() == nil {
		t.Fatal("original intent did not survive all ownership losses")
	}
	if owner, err := f.binding.Start(r, s, func() error { t.Error("revoked barrier invoked"); return nil }); owner != nil || err == nil || f.provider.starts != 1 {
		t.Fatal("reading intent revived launch")
	}
}

func TestMinimalReservationTemplateIdentityEqualDigestsAreNotRoleProof(t *testing.T) {
	f := newMinimalTemplateIdentityFixture(t)
	want := minimalTemplateIdentityValue()
	want.TemplateDocumentSHA256, want.TemplateManifestSHA256 = want.RuntimeImageSHA256, want.RuntimeImageSHA256
	s, err := f.authorizer.ResolveSelection(context.Background(), f.principal, "template-worker", f.hints, want)
	if err != nil {
		t.Fatal("value intake invented cross-role object inequality", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if got, err := f.start(t, s).TemplateIdentity(); err != nil || got != want {
		t.Fatal("equal candidate bytes lost their separate roles")
	}
}
