package credentialsource

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8CredentialSourceAuthorizesExactHostAdminGrantBeforeLookup(t *testing.T) {
	registry, keyctl, _ := l8Registry(t)
	principal, request := l8AuthorizedRequest()
	authorization, err := registry.AuthorizeJobCredentials(context.Background(), principal, request)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if len(keyctl.calls) != 0 {
		t.Fatalf("authorization touched keyring: %v", keyctl.calls)
	}
	if _, err := registry.ResolveAuthorizedSource(context.Background(), authorization, "source-primary"); err != nil {
		t.Fatalf("resolve authorized source: %v", err)
	}
	if len(keyctl.calls) != 0 {
		t.Fatalf("source resolution read keyring before use: %v", keyctl.calls)
	}

	denials := []struct {
		name   string
		mutate func(*sandboxruntime.AuthenticatedWorkerPrincipal, *sandboxruntime.JobCredentialAdmissionRequest)
	}{
		{name: "missing principal", mutate: func(p *sandboxruntime.AuthenticatedWorkerPrincipal, _ *sandboxruntime.JobCredentialAdmissionRequest) {
			*p = sandboxruntime.AuthenticatedWorkerPrincipal{}
		}},
		{name: "wrong uid", mutate: func(p *sandboxruntime.AuthenticatedWorkerPrincipal, _ *sandboxruntime.JobCredentialAdmissionRequest) {
			p.UID++
		}},
		{name: "wrong gid", mutate: func(p *sandboxruntime.AuthenticatedWorkerPrincipal, _ *sandboxruntime.JobCredentialAdmissionRequest) {
			p.GID++
		}},
		{name: "caller principal substitution", mutate: func(p *sandboxruntime.AuthenticatedWorkerPrincipal, _ *sandboxruntime.JobCredentialAdmissionRequest) {
			p.ID = "caller-controlled"
		}},
		{name: "grant substitution", mutate: func(_ *sandboxruntime.AuthenticatedWorkerPrincipal, r *sandboxruntime.JobCredentialAdmissionRequest) {
			r.GrantID = "grant-neighbor"
		}},
		{name: "grant revision", mutate: func(_ *sandboxruntime.AuthenticatedWorkerPrincipal, r *sandboxruntime.JobCredentialAdmissionRequest) {
			r.GrantRevision++
		}},
		{name: "source", mutate: func(_ *sandboxruntime.AuthenticatedWorkerPrincipal, r *sandboxruntime.JobCredentialAdmissionRequest) {
			r.SourceReferenceIDs = []string{"source-neighbor"}
		}},
		{name: "plan", mutate: func(_ *sandboxruntime.AuthenticatedWorkerPrincipal, r *sandboxruntime.JobCredentialAdmissionRequest) {
			r.PlanID = "plan-neighbor"
		}},
		{name: "binding", mutate: func(_ *sandboxruntime.AuthenticatedWorkerPrincipal, r *sandboxruntime.JobCredentialAdmissionRequest) {
			r.Bindings[0].ID = "binding-neighbor"
		}},
		{name: "mode", mutate: func(_ *sandboxruntime.AuthenticatedWorkerPrincipal, r *sandboxruntime.JobCredentialAdmissionRequest) {
			r.Bindings[0].Mode = sandboxruntime.JobCredentialDeliveryModeFileTmpfs
		}},
		{name: "template", mutate: func(_ *sandboxruntime.AuthenticatedWorkerPrincipal, r *sandboxruntime.JobCredentialAdmissionRequest) {
			r.TemplatePolicyID = "template-neighbor"
		}},
		{name: "workspace", mutate: func(_ *sandboxruntime.AuthenticatedWorkerPrincipal, r *sandboxruntime.JobCredentialAdmissionRequest) {
			r.WorkspacePolicyID = "workspace-neighbor"
		}},
		{name: "host", mutate: func(_ *sandboxruntime.AuthenticatedWorkerPrincipal, r *sandboxruntime.JobCredentialAdmissionRequest) {
			r.Identity.HostID = "host-neighbor"
		}},
		{name: "runtime", mutate: func(_ *sandboxruntime.AuthenticatedWorkerPrincipal, r *sandboxruntime.JobCredentialAdmissionRequest) {
			r.Identity.RuntimeGeneration = "runtime-neighbor"
		}},
	}
	for _, tt := range denials {
		t.Run(tt.name, func(t *testing.T) {
			p, r := l8AuthorizedRequest()
			tt.mutate(&p, &r)
			before := len(keyctl.calls)
			_, err := registry.AuthorizeJobCredentials(context.Background(), p, r)
			if !errors.Is(err, ErrCredentialAdmissionDenied) {
				t.Fatalf("error = %v, want admission denied", err)
			}
			if len(keyctl.calls) != before {
				t.Fatalf("denied request touched keyring: %v", keyctl.calls[before:])
			}
			for _, forbidden := range []string{"source-primary", "grant-primary", "principal-owner", "host-owner"} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatalf("denial enumerated private registry identity %q", forbidden)
				}
			}
		})
	}
}

func TestL8CredentialSourceDirectKeyctlSizeReadAndLockedBorrow(t *testing.T) {
	registry, keyctl, memoryOps := l8Registry(t)
	principal, request := l8AuthorizedRequest()
	authorization, err := registry.AuthorizeJobCredentials(context.Background(), principal, request)
	if err != nil {
		t.Fatal(err)
	}
	source, err := registry.ResolveAuthorizedSource(context.Background(), authorization, "source-primary")
	if err != nil {
		t.Fatal(err)
	}
	canary := []byte("l8-keyring-canary")
	keyctl.value = canary
	sink := &l8SecretSink{limit: 64}
	if err := source.FillSecret(context.Background(), sink); err != nil {
		t.Fatalf("fill secret: %v", err)
	}
	if !reflect.DeepEqual(sink.value, canary) {
		t.Fatal("sink did not receive exact keyring payload")
	}
	wantCalls := []string{"inspect", "size", "inspect", "read", "inspect"}
	if !reflect.DeepEqual(keyctl.calls, wantCalls) {
		t.Fatalf("keyctl calls = %v, want %v", keyctl.calls, wantCalls)
	}
	if !memoryOps.locked || !memoryOps.unlocked || !memoryOps.unmapped {
		t.Fatalf("memory lifecycle incomplete: locked=%t unlocked=%t unmapped=%t", memoryOps.locked, memoryOps.unlocked, memoryOps.unmapped)
	}
	if !l8AllZero(memoryOps.unlockSnapshot) || len(memoryOps.unlockSnapshot) != 64 {
		t.Fatal("keyring mapping was not overwritten across full capacity before unlock")
	}
}

func TestL8CredentialSourceReplacementRevocationPermissionAndCancellationFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*l8Keyctl)
		ctx    func() context.Context
	}{
		{name: "replacement after size", mutate: func(k *l8Keyctl) { k.replaceAtInspect = 2 }},
		{name: "replacement after read", mutate: func(k *l8Keyctl) { k.replaceAtInspect = 3 }},
		{name: "permission change", mutate: func(k *l8Keyctl) { k.permissionAtInspect = 3 }},
		{name: "owner uid change", mutate: func(k *l8Keyctl) { k.ownerUIDAtInspect = 3 }},
		{name: "owner gid change", mutate: func(k *l8Keyctl) { k.ownerGIDAtInspect = 3 }},
		{name: "revoked during size", mutate: func(k *l8Keyctl) {
			k.sizeErr = errors.New("backend-private key serial 41 revoked at /raw/keyring l8-race-canary")
		}},
		{name: "revoked during read", mutate: func(k *l8Keyctl) {
			k.readErr = errors.New("backend-private key serial 41 revoked at /raw/keyring l8-race-canary")
		}},
		{name: "permission denied", mutate: func(k *l8Keyctl) {
			k.readErr = errors.New("backend-private permission for source-primary grant-primary serial 41 l8-race-canary")
		}},
		{name: "oversized size", mutate: func(k *l8Keyctl) { k.reportedSize = MaxProductionSecretBytes + 1 }},
		{name: "short read", mutate: func(k *l8Keyctl) { k.shortRead = true }},
		{name: "canceled", ctx: func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry, keyctl, memoryOps := l8Registry(t)
			keyctl.value = []byte("l8-race-canary")
			if tt.mutate != nil {
				tt.mutate(keyctl)
			}
			principal, request := l8AuthorizedRequest()
			authorization, err := registry.AuthorizeJobCredentials(context.Background(), principal, request)
			if err != nil {
				t.Fatal(err)
			}
			source, err := registry.ResolveAuthorizedSource(context.Background(), authorization, "source-primary")
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if tt.ctx != nil {
				ctx = tt.ctx()
			}
			sink := &l8SecretSink{limit: 64}
			err = source.FillSecret(ctx, sink)
			if err == nil {
				t.Fatal("source race/failure unexpectedly succeeded")
			}
			if len(sink.value) != 0 {
				t.Fatal("failed source delivered partial credential bytes")
			}
			if memoryOps.unmapped && !l8AllZero(memoryOps.unmapSnapshot) {
				t.Fatal("failed source unmapped nonzero credential memory")
			}
			for _, forbidden := range []string{"l8-race-canary", "backend-private", "/raw/keyring", "serial 41", "source-primary", "grant-primary"} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatal("source error exposed sensitive backend detail")
				}
			}
			if !errors.Is(err, ErrCredentialSourceUnavailable) && !errors.Is(err, context.Canceled) {
				t.Fatal("source failure did not return a stable source-unavailable or cancellation classification")
			}
			if !errors.Is(err, context.Canceled) && err.Error() != ErrCredentialSourceUnavailable.Error() {
				t.Fatal("source failure did not return the stable generic source-unavailable message")
			}
		})
	}
}

func TestL8CredentialSourceGrantRevisionAndDaemonGenerationCannotReplay(t *testing.T) {
	registry, _, _ := l8Registry(t)
	principal, request := l8AuthorizedRequest()
	authorization, err := registry.AuthorizeJobCredentials(context.Background(), principal, request)
	if err != nil {
		t.Fatal(err)
	}

	restarted, _, _ := l8RegistryWithGeneration(t, "daemon-generation-2")
	if _, err := restarted.ResolveAuthorizedSource(context.Background(), authorization, "source-primary"); !errors.Is(err, ErrCredentialAdmissionDenied) {
		t.Fatalf("pre-restart authorization error = %v, want admission denied", err)
	}

	request.GrantRevision++
	if _, err := registry.AuthorizeJobCredentials(context.Background(), principal, request); !errors.Is(err, ErrCredentialAdmissionDenied) {
		t.Fatalf("changed grant revision error = %v, want admission denied", err)
	}
}

func TestL8CredentialSourceRegistryCopiesConfigurationDeeply(t *testing.T) {
	principal, request := l8AuthorizedRequest()
	keyIdentity := KeyIdentity{Serial: 41, OwnerUID: principal.UID, OwnerGID: principal.GID, Permissions: OwnerReadPermission, Generation: 7}
	sources := []SourceRegistration{{ReferenceID: "source-primary", Key: keyIdentity}}
	sourceReferences := append([]string(nil), request.SourceReferenceIDs...)
	bindings := append([]sandboxruntime.JobCredentialBindingRequest(nil), request.Bindings...)
	grants := []AdmissionGrantRegistration{{
		GrantID:            request.GrantID,
		Revision:           request.GrantRevision,
		Principal:          principal,
		HostID:             request.Identity.HostID,
		RuntimeDriver:      request.Identity.RuntimeDriver,
		RuntimeID:          request.Identity.RuntimeID,
		RuntimeGeneration:  request.Identity.RuntimeGeneration,
		TemplatePolicyID:   request.TemplatePolicyID,
		WorkspacePolicyID:  request.WorkspacePolicyID,
		PlanID:             request.PlanID,
		SourceReferenceIDs: sourceReferences,
		Bindings:           bindings,
	}}
	keyctl := &l8Keyctl{identity: keyIdentity}
	memoryOps := &l8LockedMapping{region: make([]byte, 64), locked: true}
	registry, err := newRegistry(RegistryConfig{
		DaemonGeneration: "daemon-generation-1",
		OwnerUID:         principal.UID,
		OwnerGID:         principal.GID,
		Sources:          sources,
		Grants:           grants,
	}, registryDeps{
		Keyctl: keyctl,
		NewLockedMapping: func(capacity int) (lockedSecretMapping, error) {
			memoryOps.region = make([]byte, capacity)
			return memoryOps, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	sources[0].ReferenceID = "mutated-source"
	sources[0].Key.Generation++
	grants[0].GrantID = "mutated-grant"
	grants[0].Principal.ID = "mutated-principal"
	sourceReferences[0] = "mutated-source"
	bindings[0].ID = "mutated-binding"
	bindings[0].SourceReferenceID = "mutated-source"

	authorization, err := registry.AuthorizeJobCredentials(context.Background(), principal, request)
	if err != nil {
		t.Fatalf("post-construction caller mutation changed authorization: %v", err)
	}
	if _, err := registry.ResolveAuthorizedSource(context.Background(), authorization, "source-primary"); err != nil {
		t.Fatalf("post-construction caller mutation changed source registry: %v", err)
	}
	mutated := request
	mutated.GrantID = "mutated-grant"
	if _, err := registry.AuthorizeJobCredentials(context.Background(), principal, mutated); !errors.Is(err, ErrCredentialAdmissionDenied) {
		t.Fatalf("mutated grant unexpectedly authorized: %v", err)
	}
}

func TestL8CredentialSourceRegistryDoesNotExposeEnumerationOrMutation(t *testing.T) {
	constructor := reflect.TypeOf(NewRegistry)
	if got := constructor.NumIn(); got != 1 {
		t.Fatalf("NewRegistry accepts %d inputs; want immutable config only", got)
	}
	typeOfRegistry := reflect.TypeOf((*Registry)(nil))
	for _, forbidden := range []string{"List", "ListSources", "ListGrants", "Sources", "Grants", "Register", "Replace", "Update", "Delete"} {
		if _, ok := typeOfRegistry.MethodByName(forbidden); ok {
			t.Fatalf("registry exposes forbidden enumeration/mutation method %s", forbidden)
		}
	}
	var _ sandboxruntime.CredentialAdmissionAuthorizer = (*Registry)(nil)
	var _ sandboxruntime.AuthorizedCredentialSourceRegistry = (*Registry)(nil)
}

func l8Registry(t *testing.T) (*Registry, *l8Keyctl, *l8LockedMapping) {
	t.Helper()
	return l8RegistryWithGeneration(t, "daemon-generation-1")
}

func l8RegistryWithGeneration(t *testing.T, daemonGeneration string) (*Registry, *l8Keyctl, *l8LockedMapping) {
	t.Helper()
	principal, request := l8AuthorizedRequest()
	principal.DaemonGeneration = daemonGeneration
	keyctl := &l8Keyctl{identity: KeyIdentity{Serial: 41, OwnerUID: principal.UID, OwnerGID: principal.GID, Permissions: OwnerReadPermission, Generation: 7}}
	memoryOps := &l8LockedMapping{region: make([]byte, 64), locked: true}
	registry, err := newRegistry(RegistryConfig{
		DaemonGeneration: daemonGeneration,
		OwnerUID:         principal.UID,
		OwnerGID:         principal.GID,
		Sources: []SourceRegistration{{
			ReferenceID: "source-primary",
			Key:         keyctl.identity,
		}},
		Grants: []AdmissionGrantRegistration{{
			GrantID:            request.GrantID,
			Revision:           request.GrantRevision,
			Principal:          principal,
			HostID:             request.Identity.HostID,
			RuntimeDriver:      request.Identity.RuntimeDriver,
			RuntimeID:          request.Identity.RuntimeID,
			RuntimeGeneration:  request.Identity.RuntimeGeneration,
			TemplatePolicyID:   request.TemplatePolicyID,
			WorkspacePolicyID:  request.WorkspacePolicyID,
			PlanID:             request.PlanID,
			SourceReferenceIDs: append([]string(nil), request.SourceReferenceIDs...),
			Bindings:           append([]sandboxruntime.JobCredentialBindingRequest(nil), request.Bindings...),
		}},
	}, registryDeps{
		Keyctl: keyctl,
		NewLockedMapping: func(capacity int) (lockedSecretMapping, error) {
			memoryOps.region = make([]byte, capacity)
			return memoryOps, nil
		},
	})
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}
	return registry, keyctl, memoryOps
}

func l8AuthorizedRequest() (sandboxruntime.AuthenticatedWorkerPrincipal, sandboxruntime.JobCredentialAdmissionRequest) {
	now := time.Date(2026, time.August, 3, 4, 0, 0, 0, time.UTC)
	principal := sandboxruntime.AuthenticatedWorkerPrincipal{
		ID:               "principal-owner",
		UID:              1001,
		GID:              1002,
		DaemonGeneration: "daemon-generation-1",
	}
	request := sandboxruntime.JobCredentialAdmissionRequest{
		Identity: sandboxruntime.JobCredentialIdentity{
			SandboxID:         "sandbox-1",
			ExecutionID:       "execution-1",
			WorkerID:          "worker-1",
			HostID:            "host-owner",
			RuntimeDriver:     "microvm",
			RuntimeID:         "runtime-1",
			RuntimeGeneration: "runtime-generation-1",
			WorkerJobID:       "job-1",
			SubmissionID:      "submission-1",
			IssuedAt:          now,
		},
		GrantID:            "grant-primary",
		GrantRevision:      9,
		PlanID:             "plan-primary",
		TemplatePolicyID:   "template-primary",
		WorkspacePolicyID:  "workspace-primary",
		SourceReferenceIDs: []string{"source-primary"},
		Bindings: []sandboxruntime.JobCredentialBindingRequest{{
			ID:                "binding-primary",
			Mode:              sandboxruntime.JobCredentialDeliveryModeHTTPProxy,
			SourceReferenceID: "source-primary",
			ServiceID:         "azure-openai-responses-v1",
		}},
	}
	return principal, request
}

type l8Keyctl struct {
	calls               []string
	identity            KeyIdentity
	value               []byte
	reportedSize        int
	sizeErr             error
	readErr             error
	shortRead           bool
	inspectCount        int
	replaceAtInspect    int
	permissionAtInspect int
	ownerUIDAtInspect   int
	ownerGIDAtInspect   int
}

func (keyctl *l8Keyctl) Inspect(_ context.Context, _ int32) (KeyIdentity, error) {
	keyctl.calls = append(keyctl.calls, "inspect")
	keyctl.inspectCount++
	identity := keyctl.identity
	if keyctl.replaceAtInspect == keyctl.inspectCount {
		identity.Generation++
	}
	if keyctl.permissionAtInspect == keyctl.inspectCount {
		identity.Permissions = 0
	}
	if keyctl.ownerUIDAtInspect == keyctl.inspectCount {
		identity.OwnerUID++
	}
	if keyctl.ownerGIDAtInspect == keyctl.inspectCount {
		identity.OwnerGID++
	}
	return identity, nil
}

func (keyctl *l8Keyctl) ReadSize(_ context.Context, _ int32) (int, error) {
	keyctl.calls = append(keyctl.calls, "size")
	if keyctl.sizeErr != nil {
		return 0, keyctl.sizeErr
	}
	if keyctl.reportedSize != 0 {
		return keyctl.reportedSize, nil
	}
	return len(keyctl.value), nil
}

func (keyctl *l8Keyctl) ReadInto(_ context.Context, _ int32, dst []byte) (int, error) {
	keyctl.calls = append(keyctl.calls, "read")
	if keyctl.readErr != nil {
		return 0, keyctl.readErr
	}
	copy(dst, keyctl.value)
	if keyctl.shortRead && len(keyctl.value) > 0 {
		return len(keyctl.value) - 1, nil
	}
	return len(keyctl.value), nil
}

type l8LockedMapping struct {
	region         []byte
	length         int
	locked         bool
	unlocked       bool
	unmapped       bool
	unlockSnapshot []byte
	unmapSnapshot  []byte
}

func (mapping *l8LockedMapping) Load(ctx context.Context, reader func([]byte) (int, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	length, err := reader(mapping.region)
	if err != nil {
		for i := range mapping.region {
			mapping.region[i] = 0
		}
		return err
	}
	mapping.length = length
	return nil
}

func (mapping *l8LockedMapping) WriteTo(ctx context.Context, sink sandboxruntime.JobCredentialSecretSink) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sink.MaxCredentialBytes() < mapping.length {
		return errors.New("sink capacity exceeded")
	}
	return sink.WriteCredential(mapping.region[:mapping.length])
}

func (mapping *l8LockedMapping) Destroy() error {
	for i := range mapping.region {
		mapping.region[i] = 0
	}
	mapping.unlocked = true
	mapping.unlockSnapshot = append([]byte(nil), mapping.region...)
	mapping.unmapped = true
	mapping.unmapSnapshot = append([]byte(nil), mapping.region...)
	return nil
}

type l8SecretSink struct {
	limit int
	value []byte
}

func (sink *l8SecretSink) MaxCredentialBytes() int { return sink.limit }
func (sink *l8SecretSink) WriteCredential(value []byte) error {
	sink.value = append([]byte(nil), value...)
	return nil
}

func l8AllZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}
