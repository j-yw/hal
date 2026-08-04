package credentialsource

import (
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8CredentialSourceAuthorizesExactHostAdminGrantBeforeLookup(t *testing.T) {
	registry, keyctl, _, authority, principal := l8Registry(t)
	request := l8AdmissionRequest()
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

	type admissionDenial struct {
		name   string
		mutate func(*testing.T, sandboxruntime.AuthenticatedWorkerPrincipal, *sandboxruntime.JobCredentialAdmissionRequest) sandboxruntime.AuthenticatedWorkerPrincipal
	}
	denials := []admissionDenial{
		{name: "missing principal", mutate: func(_ *testing.T, _ sandboxruntime.AuthenticatedWorkerPrincipal, _ *sandboxruntime.JobCredentialAdmissionRequest) sandboxruntime.AuthenticatedWorkerPrincipal {
			var zero sandboxruntime.AuthenticatedWorkerPrincipal
			return zero
		}},
		{name: "wrong uid", mutate: func(t *testing.T, _ sandboxruntime.AuthenticatedWorkerPrincipal, _ *sandboxruntime.JobCredentialAdmissionRequest) sandboxruntime.AuthenticatedWorkerPrincipal {
			return l8Principal(t, authority, "principal-owner", 1002, 1002)
		}},
		{name: "wrong gid", mutate: func(t *testing.T, _ sandboxruntime.AuthenticatedWorkerPrincipal, _ *sandboxruntime.JobCredentialAdmissionRequest) sandboxruntime.AuthenticatedWorkerPrincipal {
			return l8Principal(t, authority, "principal-owner", 1001, 1003)
		}},
		{name: "authenticated principal substitution", mutate: func(t *testing.T, _ sandboxruntime.AuthenticatedWorkerPrincipal, _ *sandboxruntime.JobCredentialAdmissionRequest) sandboxruntime.AuthenticatedWorkerPrincipal {
			return l8Principal(t, authority, "caller-controlled", 1001, 1002)
		}},
		{name: "reissued principal with identical visible fields from same authority", mutate: func(t *testing.T, _ sandboxruntime.AuthenticatedWorkerPrincipal, _ *sandboxruntime.JobCredentialAdmissionRequest) sandboxruntime.AuthenticatedWorkerPrincipal {
			return l8Principal(t, authority, "principal-owner", 1001, 1002)
		}},
		{name: "issuer substitution", mutate: func(t *testing.T, _ sandboxruntime.AuthenticatedWorkerPrincipal, _ *sandboxruntime.JobCredentialAdmissionRequest) sandboxruntime.AuthenticatedWorkerPrincipal {
			other := l8PrincipalAuthority(t, "caller-issuer", "daemon-generation-1")
			return l8Principal(t, other, "principal-owner", 1001, 1002)
		}},
		{name: "issuer generation substitution", mutate: func(t *testing.T, _ sandboxruntime.AuthenticatedWorkerPrincipal, _ *sandboxruntime.JobCredentialAdmissionRequest) sandboxruntime.AuthenticatedWorkerPrincipal {
			other := l8PrincipalAuthority(t, "peercred-owner", "daemon-generation-neighbor")
			return l8Principal(t, other, "principal-owner", 1001, 1002)
		}},
		{name: "identical visible issuer from different authority", mutate: func(t *testing.T, _ sandboxruntime.AuthenticatedWorkerPrincipal, _ *sandboxruntime.JobCredentialAdmissionRequest) sandboxruntime.AuthenticatedWorkerPrincipal {
			other := l8PrincipalAuthority(t, "peercred-owner", "daemon-generation-1")
			return l8Principal(t, other, "principal-owner", 1001, 1002)
		}},
	}
	for _, identityMutation := range l8AdmissionIdentityMutations() {
		mutation := identityMutation
		denials = append(denials,
			admissionDenial{name: "missing identity " + mutation.name, mutate: func(_ *testing.T, p sandboxruntime.AuthenticatedWorkerPrincipal, r *sandboxruntime.JobCredentialAdmissionRequest) sandboxruntime.AuthenticatedWorkerPrincipal {
				mutation.clear(&r.Identity)
				return p
			}},
			admissionDenial{name: "mismatched identity " + mutation.name, mutate: func(_ *testing.T, p sandboxruntime.AuthenticatedWorkerPrincipal, r *sandboxruntime.JobCredentialAdmissionRequest) sandboxruntime.AuthenticatedWorkerPrincipal {
				mutation.mutate(&r.Identity)
				return p
			}},
		)
	}
	for _, requestMutation := range l8AdmissionRequestMutations() {
		mutation := requestMutation
		denials = append(denials,
			admissionDenial{name: "missing request " + mutation.name, mutate: func(_ *testing.T, p sandboxruntime.AuthenticatedWorkerPrincipal, r *sandboxruntime.JobCredentialAdmissionRequest) sandboxruntime.AuthenticatedWorkerPrincipal {
				mutation.clear(r)
				return p
			}},
			admissionDenial{name: "mismatched request " + mutation.name, mutate: func(_ *testing.T, p sandboxruntime.AuthenticatedWorkerPrincipal, r *sandboxruntime.JobCredentialAdmissionRequest) sandboxruntime.AuthenticatedWorkerPrincipal {
				mutation.mutate(r)
				return p
			}},
		)
	}
	for _, tt := range denials {
		t.Run(tt.name, func(t *testing.T) {
			p := principal
			r := l8AdmissionRequest()
			p = tt.mutate(t, p, &r)
			before := len(keyctl.calls)
			_, err := registry.AuthorizeJobCredentials(context.Background(), p, r)
			if !errors.Is(err, ErrCredentialAdmissionDenied) || err.Error() != ErrCredentialAdmissionDenied.Error() {
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

func TestL8CredentialSourceRegistryConfigRejectsOversizedGrantSet(t *testing.T) {
	authority := l8PrincipalAuthority(t, "peercred-owner", "daemon-generation-1")
	principal := l8Principal(t, authority, "principal-owner", 1001, 1002)
	source, err := NewSourceRegistration("source-primary", l8KeyIdentity(t, 41, principal.UID(), principal.GID(), "hal-primary"))
	if err != nil {
		t.Fatal(err)
	}
	grants := make([]AdmissionGrantRegistration, 65)
	for index := range grants {
		request := l8AdmissionRequest()
		request.GrantID = fmt.Sprintf("grant-%d", index)
		grants[index], err = NewAdmissionGrantRegistration(authority, principal, request, []string{"source-primary"})
		if err != nil {
			t.Fatalf("new grant %d: %v", index, err)
		}
	}
	if _, err := NewRegistryConfig(authority, principal.UID(), principal.GID(), []SourceRegistration{source}, grants); !errors.Is(err, ErrCredentialSourceRegistration) {
		t.Fatalf("oversized grant set error = %v, want registration rejected", err)
	}
}

func TestL8CredentialSourceDirectKeyctlSizeReadAndLockedBorrow(t *testing.T) {
	registry, keyctl, memoryOps, _, principal := l8Registry(t)
	request := l8AdmissionRequest()
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
	if sink.count != 1 || sink.size != len(canary) || sink.digest != sha256.Sum256(canary) {
		t.Fatal("sink did not receive exact keyring payload")
	}
	wantCalls := []string{"describe_size", "describe", "read_size", "describe_size", "describe", "read", "describe_size", "describe"}
	if !reflect.DeepEqual(keyctl.calls, wantCalls) {
		t.Fatalf("keyctl calls = %v, want %v", keyctl.calls, wantCalls)
	}
	if wantSerials := []int32{41, 41, 41, 41, 41, 41, 41, 41}; !reflect.DeepEqual(keyctl.serials, wantSerials) {
		t.Fatalf("keyctl serials = %v, want exact registered serial %v", keyctl.serials, wantSerials)
	}
	if !memoryOps.locked || !memoryOps.unlocked || !memoryOps.unmapped {
		t.Fatalf("memory lifecycle incomplete: locked=%t unlocked=%t unmapped=%t", memoryOps.locked, memoryOps.unlocked, memoryOps.unmapped)
	}
	if !l8AllZero(memoryOps.unlockSnapshot) || len(memoryOps.unlockSnapshot) != 64 {
		t.Fatal("keyring mapping was not overwritten across full capacity before unlock")
	}
	for _, descriptorBuffer := range keyctl.describeBuffers {
		if !l8AllZero(descriptorBuffer) {
			t.Fatal("keyctl descriptor buffer was not zeroized after identity inspection")
		}
	}
}

func TestL8CredentialSourceKeyIdentityUsesExactRealDescriptorAndImmutablePermissions(t *testing.T) {
	permissions := l8ImmutableKeyPermissions()
	identity, err := NewKeyIdentity(41, "user", 1001, 1002, permissions, "hal-primary")
	if err != nil {
		t.Fatalf("valid registered key identity: %v", err)
	}
	descriptor, err := NewKeyDescriptor("user", 1001, 1002, permissions, "hal-primary")
	if err != nil {
		t.Fatalf("valid key descriptor: %v", err)
	}
	for label, value := range map[string]any{"key identity": identity, "key descriptor": descriptor} {
		typeOfValue := reflect.TypeOf(value)
		if _, ok := typeOfValue.FieldByName("Generation"); ok {
			t.Fatalf("%s models a synthetic payload generation", label)
		}
		for fieldIndex := 0; fieldIndex < typeOfValue.NumField(); fieldIndex++ {
			if field := typeOfValue.Field(fieldIndex); field.IsExported() {
				t.Fatalf("%s exposes live key field %s", label, field.Name)
			}
		}
	}
	descriptorType := reflect.TypeOf(descriptor)
	for fieldIndex := 0; fieldIndex < descriptorType.NumField(); fieldIndex++ {
		if strings.Contains(strings.ToLower(descriptorType.Field(fieldIndex).Name), "serial") {
			t.Fatal("KEYCTL_DESCRIBE result invents a serial instead of correlating the registered syscall argument")
		}
	}

	for _, tt := range []struct {
		name        string
		serial      int32
		keyType     string
		permissions KeyPermission
		description string
	}{
		{name: "zero serial", keyType: "user", permissions: permissions, description: "hal-primary"},
		{name: "wrong type", serial: 41, keyType: "logon", permissions: permissions, description: "hal-primary"},
		{name: "empty description", serial: 41, keyType: "user", permissions: permissions},
		{name: "missing exact read permission", serial: 41, keyType: "user", permissions: permissions &^ KeyPermissionUserRead, description: "hal-primary"},
		{name: "possessor authority", serial: 41, keyType: "user", permissions: permissions | KeyPermission(0x01000000), description: "hal-primary"},
		{name: "group authority", serial: 41, keyType: "user", permissions: permissions | KeyPermission(0x00000100), description: "hal-primary"},
		{name: "other authority", serial: 41, keyType: "user", permissions: permissions | KeyPermission(0x00000001), description: "hal-primary"},
		{name: "possessor write", serial: 41, keyType: "user", permissions: permissions | KeyPermission(0x04000000), description: "hal-primary"},
		{name: "user write", serial: 41, keyType: "user", permissions: permissions | KeyPermission(0x00040000), description: "hal-primary"},
		{name: "group write", serial: 41, keyType: "user", permissions: permissions | KeyPermission(0x00000400), description: "hal-primary"},
		{name: "other write", serial: 41, keyType: "user", permissions: permissions | KeyPermission(0x00000004), description: "hal-primary"},
		{name: "possessor setattr", serial: 41, keyType: "user", permissions: permissions | KeyPermission(0x20000000), description: "hal-primary"},
		{name: "user setattr", serial: 41, keyType: "user", permissions: permissions | KeyPermission(0x00200000), description: "hal-primary"},
		{name: "group setattr", serial: 41, keyType: "user", permissions: permissions | KeyPermission(0x00002000), description: "hal-primary"},
		{name: "other setattr", serial: 41, keyType: "user", permissions: permissions | KeyPermission(0x00000020), description: "hal-primary"},
		{name: "possessor link", serial: 41, keyType: "user", permissions: permissions | KeyPermission(0x10000000), description: "hal-primary"},
		{name: "user link", serial: 41, keyType: "user", permissions: permissions | KeyPermission(0x00100000), description: "hal-primary"},
		{name: "group link", serial: 41, keyType: "user", permissions: permissions | KeyPermission(0x00001000), description: "hal-primary"},
		{name: "other link", serial: 41, keyType: "user", permissions: permissions | KeyPermission(0x00000010), description: "hal-primary"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewKeyIdentity(tt.serial, tt.keyType, 1001, 1002, tt.permissions, tt.description)
			if !errors.Is(err, ErrCredentialSourceRegistration) || err.Error() != ErrCredentialSourceRegistration.Error() {
				t.Fatalf("invalid key identity error = %v, want registration failure", err)
			}
		})
	}
}

func TestL8CredentialSourceParsesBoundedCanonicalRawKeyctlDescriptor(t *testing.T) {
	if MaxKeyctlDescribeBytes < len("user;1001;1002;00030000;hal-primary\x00") || MaxKeyctlDescribeBytes > 64<<10 {
		t.Fatalf("MaxKeyctlDescribeBytes = %d, want finite descriptor bound", MaxKeyctlDescribeBytes)
	}
	parsed, err := parseKeyctlDescribe([]byte("user;1001;1002;00030000;hal-primary\x00"))
	if err != nil {
		t.Fatalf("parse canonical descriptor: %v", err)
	}
	expected, err := NewKeyDescriptor("user", 1001, 1002, KeyPermission(0x00030000), "hal-primary")
	if err != nil {
		t.Fatal(err)
	}
	if !keyDescriptorsEqual(parsed, expected) {
		t.Fatal("canonical raw descriptor did not preserve exact type/UID/GID/permissions/description")
	}

	oversized := append([]byte("user;1001;1002;00030000;"), make([]byte, MaxKeyctlDescribeBytes)...)
	oversized = append(oversized, 0)
	for _, tt := range []struct {
		name string
		raw  []byte
	}{
		{name: "empty", raw: nil},
		{name: "oversized", raw: oversized},
		{name: "missing nul", raw: []byte("user;1001;1002;00030000;hal-primary")},
		{name: "trailing after nul", raw: []byte("user;1001;1002;00030000;hal-primary\x00trailing")},
		{name: "truncated fields", raw: []byte("user;1001;1002;00030000\x00")},
		{name: "empty type", raw: []byte(";1001;1002;00030000;hal-primary\x00")},
		{name: "wrong type", raw: []byte("logon;1001;1002;00030000;hal-primary\x00")},
		{name: "negative uid", raw: []byte("user;-1;1002;00030000;hal-primary\x00")},
		{name: "nondigit uid", raw: []byte("user;owner;1002;00030000;hal-primary\x00")},
		{name: "overflow uid", raw: []byte("user;4294967296;1002;00030000;hal-primary\x00")},
		{name: "negative gid", raw: []byte("user;1001;-1;00030000;hal-primary\x00")},
		{name: "nondigit gid", raw: []byte("user;1001;group;00030000;hal-primary\x00")},
		{name: "overflow gid", raw: []byte("user;1001;4294967296;00030000;hal-primary\x00")},
		{name: "nonhex permissions", raw: []byte("user;1001;1002;permission;hal-primary\x00")},
		{name: "short permissions", raw: []byte("user;1001;1002;30000;hal-primary\x00")},
		{name: "overflow permissions", raw: []byte("user;1001;1002;100030000;hal-primary\x00")},
		{name: "empty description", raw: []byte("user;1001;1002;00030000;\x00")},
		{name: "unsafe description", raw: []byte("user;1001;1002;00030000;../hal-primary\x00")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseKeyctlDescribe(tt.raw); !errors.Is(err, ErrCredentialSourceDescriptor) || err.Error() != ErrCredentialSourceDescriptor.Error() {
				t.Fatalf("descriptor parse error = %v, want stable descriptor denial", err)
			}
		})
	}
}

func TestL8CredentialSourceReplacementRevocationPermissionAndCancellationFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*l8Keyctl)
		ctx    func() context.Context
	}{
		{name: "replacement before size", mutate: func(k *l8Keyctl) { k.replaceAtInspect = 1 }},
		{name: "replacement after size", mutate: func(k *l8Keyctl) { k.replaceAtInspect = 2 }},
		{name: "replacement after read", mutate: func(k *l8Keyctl) { k.replaceAtInspect = 3 }},
		{name: "permission invalid before size", mutate: func(k *l8Keyctl) { k.permissionAtInspect = 1 }},
		{name: "permission change after size", mutate: func(k *l8Keyctl) { k.permissionAtInspect = 2 }},
		{name: "permission change", mutate: func(k *l8Keyctl) { k.permissionAtInspect = 3 }},
		{name: "type replacement before size", mutate: func(k *l8Keyctl) { k.typeAtInspect = 1 }},
		{name: "type replacement after read", mutate: func(k *l8Keyctl) { k.typeAtInspect = 3 }},
		{name: "description replacement after size", mutate: func(k *l8Keyctl) { k.descriptionAtInspect = 2 }},
		{name: "description replacement after read", mutate: func(k *l8Keyctl) { k.descriptionAtInspect = 3 }},
		{name: "owner uid change", mutate: func(k *l8Keyctl) { k.ownerUIDAtInspect = 3 }},
		{name: "owner gid change", mutate: func(k *l8Keyctl) { k.ownerGIDAtInspect = 3 }},
		{name: "describe size failure", mutate: func(k *l8Keyctl) {
			k.describeSizeErr = errors.New("backend-private describe size serial 41 /raw/keyring l8-race-canary")
		}},
		{name: "describe read failure", mutate: func(k *l8Keyctl) {
			k.describeErr = errors.New("backend-private describe serial 41 /raw/keyring l8-race-canary")
		}},
		{name: "zero describe size", mutate: func(k *l8Keyctl) { k.forceDescribeReportedSize = true }},
		{name: "negative describe size", mutate: func(k *l8Keyctl) {
			k.forceDescribeReportedSize = true
			k.describeReportedSize = -1
		}},
		{name: "oversized describe size", mutate: func(k *l8Keyctl) {
			k.forceDescribeReportedSize = true
			k.describeReportedSize = MaxKeyctlDescribeBytes + 1
		}},
		{name: "short describe", mutate: func(k *l8Keyctl) { k.shortDescribe = true }},
		{name: "malformed describe", mutate: func(k *l8Keyctl) {
			k.rawDescriptorOverride = []byte("user;1001;1002;00030000;missing-nul")
		}},
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
		{name: "zero read size", mutate: func(k *l8Keyctl) { k.forceReportedSize = true }},
		{name: "negative read size", mutate: func(k *l8Keyctl) {
			k.forceReportedSize = true
			k.reportedSize = -1
		}},
		{name: "short read", mutate: func(k *l8Keyctl) { k.shortRead = true }},
		{name: "canceled", ctx: func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry, keyctl, memoryOps, _, principal := l8Registry(t)
			keyctl.value = []byte("l8-race-canary")
			if tt.mutate != nil {
				tt.mutate(keyctl)
			}
			request := l8AdmissionRequest()
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
			if sink.count != 0 {
				t.Fatal("failed source delivered partial credential bytes")
			}
			if memoryOps.unmapped && !l8AllZero(memoryOps.unmapSnapshot) {
				t.Fatal("failed source unmapped nonzero credential memory")
			}
			for _, descriptorBuffer := range keyctl.describeBuffers {
				if !l8AllZero(descriptorBuffer) {
					t.Fatal("failed source retained a raw keyctl descriptor buffer")
				}
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
			for _, raw := range []error{keyctl.describeSizeErr, keyctl.describeErr, keyctl.sizeErr, keyctl.readErr} {
				if raw != nil && errors.Is(err, raw) {
					t.Fatal("source failure unwrapped a raw backend cause")
				}
			}
			if errors.Is(err, context.Canceled) && len(keyctl.calls) != 0 {
				t.Fatalf("pre-canceled source touched keyctl: %v", keyctl.calls)
			}
		})
	}
}

func TestL8CredentialSourceVariableLengthSyscallCountsFailClosedAndWipe(t *testing.T) {
	for _, tt := range []struct {
		name        string
		mutate      func(*l8Keyctl)
		wantMapping bool
	}{
		{
			name: "positive describe size followed by larger count",
			mutate: func(keyctl *l8Keyctl) {
				keyctl.forceDescribeReportedSize = true
				keyctl.describeReportedSize = 8
			},
		},
		{
			name: "describe count zero",
			mutate: func(keyctl *l8Keyctl) {
				keyctl.forceDescribeIntoN = true
			},
		},
		{
			name: "describe count negative",
			mutate: func(keyctl *l8Keyctl) {
				keyctl.forceDescribeIntoN = true
				keyctl.describeIntoN = -1
			},
		},
		{
			name: "describe count over destination",
			mutate: func(keyctl *l8Keyctl) {
				keyctl.forceDescribeIntoN = true
				keyctl.describeIntoN = MaxKeyctlDescribeBytes + 1
			},
		},
		{
			name: "positive read size followed by larger count",
			mutate: func(keyctl *l8Keyctl) {
				keyctl.forceReportedSize = true
				keyctl.reportedSize = 4
			},
			wantMapping: true,
		},
		{
			name: "read count zero",
			mutate: func(keyctl *l8Keyctl) {
				keyctl.forceReadIntoN = true
			},
			wantMapping: true,
		},
		{
			name: "read count negative",
			mutate: func(keyctl *l8Keyctl) {
				keyctl.forceReadIntoN = true
				keyctl.readIntoN = -1
			},
			wantMapping: true,
		},
		{
			name: "read count over destination",
			mutate: func(keyctl *l8Keyctl) {
				keyctl.forceReadIntoN = true
				keyctl.readIntoN = MaxProductionSecretBytes + 1
			},
			wantMapping: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			registry, keyctl, memoryOps, _, principal := l8Registry(t)
			keyctl.value = []byte("variable-length-canary")
			tt.mutate(keyctl)
			authorization, err := registry.AuthorizeJobCredentials(context.Background(), principal, l8AdmissionRequest())
			if err != nil {
				t.Fatal(err)
			}
			source, err := registry.ResolveAuthorizedSource(context.Background(), authorization, "source-primary")
			if err != nil {
				t.Fatal(err)
			}
			sink := &l8SecretSink{limit: MaxProductionSecretBytes}
			err = source.FillSecret(context.Background(), sink)
			if !errors.Is(err, ErrCredentialSourceUnavailable) || err.Error() != ErrCredentialSourceUnavailable.Error() {
				t.Fatalf("variable-length syscall error = %v, want stable unavailable", err)
			}
			if sink.count != 0 {
				t.Fatal("variable-length syscall race delivered bytes to sink")
			}
			if memoryOps.unmapped != tt.wantMapping {
				t.Fatalf("mapping cleanup = %t, want %t", memoryOps.unmapped, tt.wantMapping)
			}
			if memoryOps.unmapped && (!l8AllZero(memoryOps.unlockSnapshot) || !l8AllZero(memoryOps.unmapSnapshot)) {
				t.Fatal("variable-length syscall race did not wipe mapping before cleanup")
			}
			for _, descriptorBuffer := range keyctl.describeBuffers {
				if !l8AllZero(descriptorBuffer) {
					t.Fatal("variable-length syscall race retained descriptor bytes")
				}
			}
		})
	}
}

func TestL8CredentialSourceCancellationCheckpointsStopBeforeNextKeyctlBoundary(t *testing.T) {
	for _, tt := range []struct {
		name        string
		cancelCall  string
		occurrence  int
		wantCalls   []string
		wantMapping bool
	}{
		{name: "after initial describe", cancelCall: "describe", occurrence: 1, wantCalls: []string{"describe_size", "describe"}},
		{name: "after secret size", cancelCall: "read_size", occurrence: 1, wantCalls: []string{"describe_size", "describe", "read_size"}},
		{name: "after pre-read reinspection", cancelCall: "describe", occurrence: 2, wantCalls: []string{"describe_size", "describe", "read_size", "describe_size", "describe"}, wantMapping: true},
		{name: "after secret read before final reinspection", cancelCall: "read", occurrence: 1, wantCalls: []string{"describe_size", "describe", "read_size", "describe_size", "describe", "read"}, wantMapping: true},
		{name: "after final reinspection before sink", cancelCall: "describe", occurrence: 3, wantCalls: []string{"describe_size", "describe", "read_size", "describe_size", "describe", "read", "describe_size", "describe"}, wantMapping: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			registry, keyctl, memoryOps, _, principal := l8Registry(t)
			request := l8AdmissionRequest()
			authorization, err := registry.AuthorizeJobCredentials(context.Background(), principal, request)
			if err != nil {
				t.Fatal(err)
			}
			source, err := registry.ResolveAuthorizedSource(context.Background(), authorization, "source-primary")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			seen := 0
			keyctl.afterCall = func(call string) {
				if call != tt.cancelCall {
					return
				}
				seen++
				if seen == tt.occurrence {
					cancel()
				}
			}
			keyctl.value = []byte("l8-cancel-checkpoint-canary")
			sink := &l8SecretSink{limit: 64}
			err = source.FillSecret(ctx, sink)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("checkpoint error = %v, want canceled", err)
			}
			if !reflect.DeepEqual(keyctl.calls, tt.wantCalls) {
				t.Fatalf("keyctl calls = %v, want bounded prefix %v", keyctl.calls, tt.wantCalls)
			}
			if sink.count != 0 {
				t.Fatal("canceled checkpoint exposed credential bytes to sink")
			}
			if memoryOps.unmapped != tt.wantMapping {
				t.Fatalf("canceled checkpoint mapping cleanup = %t, want %t", memoryOps.unmapped, tt.wantMapping)
			}
			if memoryOps.unmapped && (!l8AllZero(memoryOps.unlockSnapshot) || !l8AllZero(memoryOps.unmapSnapshot)) {
				t.Fatal("canceled checkpoint retained credential bytes in mapping cleanup")
			}
			for _, descriptorBuffer := range keyctl.describeBuffers {
				if !l8AllZero(descriptorBuffer) {
					t.Fatal("canceled checkpoint retained descriptor bytes")
				}
			}
		})
	}
}

func TestL8CredentialSourceGrantRevisionAndDaemonGenerationCannotReplay(t *testing.T) {
	registry, _, _, _, principal := l8Registry(t)
	request := l8AdmissionRequest()
	authorization, err := registry.AuthorizeJobCredentials(context.Background(), principal, request)
	if err != nil {
		t.Fatal(err)
	}

	restarted, _, _, _, _ := l8RegistryWithGeneration(t, "daemon-generation-2")
	if _, err := restarted.ResolveAuthorizedSource(context.Background(), authorization, "source-primary"); !errors.Is(err, ErrCredentialAdmissionDenied) {
		t.Fatalf("pre-restart authorization error = %v, want admission denied", err)
	}

	request.GrantRevision++
	if _, err := registry.AuthorizeJobCredentials(context.Background(), principal, request); !errors.Is(err, ErrCredentialAdmissionDenied) {
		t.Fatalf("changed grant revision error = %v, want admission denied", err)
	}
}

func TestL8CredentialSourceAuthorizationIsRegistryBoundUntamperableAndAnExactSetIntersection(t *testing.T) {
	registry, keyctl, _, _, principal := l8Registry(t)
	request := l8AdmissionRequest()
	authorization, err := registry.AuthorizeJobCredentials(context.Background(), principal, request)
	if err != nil {
		t.Fatal(err)
	}
	issued, ok := authorization.(*registryAuthorization)
	if !ok {
		t.Fatalf("authorization concrete type = %T, want registry-owned sealed authorization", authorization)
	}
	copied := *issued
	var zero sandboxruntime.CredentialAdmissionAuthorization
	for _, tt := range []struct {
		name          string
		authorization sandboxruntime.CredentialAdmissionAuthorization
		referenceID   string
	}{
		{name: "nil", authorization: zero, referenceID: "source-primary"},
		{name: "zero", authorization: &registryAuthorization{}, referenceID: "source-primary"},
		{name: "copied or tampered", authorization: &copied, referenceID: "source-primary"},
		{name: "grant allowed but not requested", authorization: authorization, referenceID: "source-secondary"},
		{name: "registered but not grant authorized", authorization: authorization, referenceID: "source-ungranted"},
		{name: "unknown", authorization: authorization, referenceID: "source-unknown"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := len(keyctl.calls)
			_, err := registry.ResolveAuthorizedSource(context.Background(), tt.authorization, tt.referenceID)
			if !errors.Is(err, ErrCredentialAdmissionDenied) || err.Error() != ErrCredentialAdmissionDenied.Error() {
				t.Fatalf("resolve error = %v, want admission denied", err)
			}
			for _, private := range []string{tt.referenceID, "source-primary", "source-secondary", "source-ungranted", "grant-primary", "principal-owner"} {
				if private != "" && strings.Contains(err.Error(), private) {
					t.Fatalf("resolve denial enumerated private registry identity %q", private)
				}
			}
			if len(keyctl.calls) != before {
				t.Fatalf("denied source was inspected/read: %v", keyctl.calls[before:])
			}
		})
	}

	restarted, _, _, _, _ := l8RegistryWithGeneration(t, "daemon-generation-1")
	if _, err := restarted.ResolveAuthorizedSource(context.Background(), authorization, "source-primary"); !errors.Is(err, ErrCredentialAdmissionDenied) {
		t.Fatalf("cross-registry authorization error = %v, want admission denied", err)
	}

	extraRequest := request
	extraRequest.SourceReferenceIDs = []string{"source-primary", "source-ungranted"}
	extraRequest.Bindings = append([]sandboxruntime.JobCredentialBindingRequest(nil), request.Bindings...)
	extraRequest.Bindings = append(extraRequest.Bindings, sandboxruntime.JobCredentialBindingRequest{
		ID:                "binding-ungranted",
		Mode:              sandboxruntime.JobCredentialDeliveryModeHTTPProxy,
		SourceReferenceID: "source-ungranted",
		ServiceID:         "azure-openai-responses-v1",
	})
	before := len(keyctl.calls)
	if _, err := registry.AuthorizeJobCredentials(context.Background(), principal, extraRequest); !errors.Is(err, ErrCredentialAdmissionDenied) {
		t.Fatalf("request/grant set expansion error = %v, want admission denied", err)
	}
	if len(keyctl.calls) != before {
		t.Fatal("request/grant set expansion inspected a source before denial")
	}
}

func TestL8CredentialSourceRegistryCopiesConfigurationDeeply(t *testing.T) {
	authority := l8PrincipalAuthority(t, "peercred-owner", "daemon-generation-1")
	principal := l8Principal(t, authority, "principal-owner", 1001, 1002)
	request := l8AdmissionRequest()
	keyIdentity := l8KeyIdentity(t, 41, principal.UID(), principal.GID(), "hal-primary")
	primary, err := NewSourceRegistration("source-primary", keyIdentity)
	if err != nil {
		t.Fatal(err)
	}
	sources := []SourceRegistration{primary}
	sourceReferences := append([]string(nil), request.SourceReferenceIDs...)
	bindings := append([]sandboxruntime.JobCredentialBindingRequest(nil), request.Bindings...)
	grantRequest := request
	grantRequest.SourceReferenceIDs = sourceReferences
	grantRequest.Bindings = bindings
	grant, err := NewAdmissionGrantRegistration(authority, principal, grantRequest, sourceReferences)
	if err != nil {
		t.Fatal(err)
	}
	grants := []AdmissionGrantRegistration{grant}
	config, err := NewRegistryConfig(authority, principal.UID(), principal.GID(), sources, grants)
	if err != nil {
		t.Fatal(err)
	}
	keyctl := &l8Keyctl{descriptor: l8KeyDescriptor(t, principal.UID(), principal.GID(), "hal-primary")}
	memoryOps := &l8LockedMapping{region: make([]byte, 64), locked: true}
	registry, err := newRegistry(config, registryDeps{
		keyctl: keyctl,
		newLockedMapping: func(capacity int) (lockedSecretMapping, error) {
			memoryOps.region = make([]byte, capacity)
			return memoryOps, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	mutatedIdentity := l8KeyIdentity(t, 99, principal.UID(), principal.GID(), "hal-mutated")
	sources[0], err = NewSourceRegistration("mutated-source", mutatedIdentity)
	if err != nil {
		t.Fatal(err)
	}
	mutatedRequest := request
	mutatedRequest.GrantID = "mutated-grant"
	grants[0], err = NewAdmissionGrantRegistration(authority, principal, mutatedRequest, []string{"mutated-source"})
	if err != nil {
		t.Fatal(err)
	}
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
	wantMethods := map[string]bool{
		"AuthorizeJobCredentials": true,
		"ResolveAuthorizedSource": true,
		"String":                  true,
		"GoString":                true,
		"Format":                  true,
		"MarshalJSON":             true,
		"MarshalText":             true,
	}
	if typeOfRegistry.NumMethod() != len(wantMethods) {
		t.Fatalf("Registry exposes %d public methods, want exact allowlist %v", typeOfRegistry.NumMethod(), reflect.ValueOf(wantMethods).MapKeys())
	}
	for methodIndex := 0; methodIndex < typeOfRegistry.NumMethod(); methodIndex++ {
		method := typeOfRegistry.Method(methodIndex)
		if !wantMethods[method.Name] {
			t.Fatalf("Registry exposes unapproved public method %s", method.Name)
		}
	}
	registryStruct := typeOfRegistry.Elem()
	for fieldIndex := 0; fieldIndex < registryStruct.NumField(); fieldIndex++ {
		if field := registryStruct.Field(fieldIndex); field.IsExported() {
			t.Fatalf("Registry exposes live field %s", field.Name)
		}
	}
	var _ sandboxruntime.CredentialAdmissionAuthorizer = (*Registry)(nil)
	var _ sandboxruntime.AuthorizedCredentialSourceRegistry = (*Registry)(nil)
}

func TestL8CredentialSourceLiveStateAndConfigurationCannotLeakThroughSerializationOrFormatting(t *testing.T) {
	registry, _, _, authority, principal := l8Registry(t)
	request := l8AdmissionRequest()
	authorization, err := registry.AuthorizeJobCredentials(context.Background(), principal, request)
	if err != nil {
		t.Fatal(err)
	}
	source, err := registry.ResolveAuthorizedSource(context.Background(), authorization, "source-primary")
	if err != nil {
		t.Fatal(err)
	}
	identity := l8KeyIdentity(t, 41, principal.UID(), principal.GID(), "hal-primary")
	descriptor, err := NewKeyDescriptor("user", principal.UID(), principal.GID(), l8ImmutableKeyPermissions(), "hal-primary")
	if err != nil {
		t.Fatal(err)
	}
	registration, err := NewSourceRegistration("source-primary", identity)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := NewAdmissionGrantRegistration(authority, principal, request, []string{"source-primary"})
	if err != nil {
		t.Fatal(err)
	}
	config, err := NewRegistryConfig(authority, principal.UID(), principal.GID(), []SourceRegistration{registration}, []AdmissionGrantRegistration{grant})
	if err != nil {
		t.Fatal(err)
	}

	for _, liveValue := range []struct {
		label          string
		value          any
		expectedFormat string
	}{
		{label: "registry", value: registry, expectedFormat: "<credentialsource.Registry>"},
		{label: "authorization", value: authorization, expectedFormat: "<credentialsource.registryAuthorization>"},
		{label: "live source", value: source, expectedFormat: "<credentialsource.keyringLiveSecretSource>"},
		{label: "registry config", value: config, expectedFormat: "<credentialsource.RegistryConfig>"},
		{label: "source registration", value: registration, expectedFormat: "<credentialsource.SourceRegistration>"},
		{label: "grant registration", value: grant, expectedFormat: "<credentialsource.AdmissionGrantRegistration>"},
		{label: "key identity", value: identity, expectedFormat: "<credentialsource.KeyIdentity>"},
		{label: "key descriptor", value: descriptor, expectedFormat: "<credentialsource.KeyDescriptor>"},
	} {
		l8AssertCredentialSourceLiveValue(t, liveValue.label, liveValue.value, liveValue.expectedFormat, []string{
			"41", "42", "43", "1001", "1002", "hal-primary", "hal-secondary", "hal-ungranted",
			"source-primary", "source-secondary", "source-ungranted", "grant-primary",
			"principal-owner", "peercred-owner", "daemon-generation-1", "runtime-generation-1",
		})
		typeOfValue := reflect.TypeOf(liveValue.value)
		if typeOfValue.Kind() == reflect.Pointer {
			typeOfValue = typeOfValue.Elem()
		}
		for fieldIndex := 0; fieldIndex < typeOfValue.NumField(); fieldIndex++ {
			if field := typeOfValue.Field(fieldIndex); field.IsExported() {
				t.Fatalf("%s exposes live field %s", liveValue.label, field.Name)
			}
		}
	}

	requestType := reflect.TypeOf(request)
	for fieldIndex := 0; fieldIndex < requestType.NumField(); fieldIndex++ {
		fieldName := strings.ToLower(requestType.Field(fieldIndex).Name)
		for _, forbidden := range []string{"principal", "issuer", "uid", "gid", "serial", "secretvalue", "endpoint", "socket", "hostname", "authority", "seal", "token", "credentialvalue"} {
			if strings.Contains(fieldName, forbidden) {
				t.Fatalf("admission request exposes raw/live field %s", requestType.Field(fieldIndex).Name)
			}
		}
	}
	encodedRequest, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal safe admission request: %v", err)
	}
	for _, forbidden := range []string{"principal", "authority", "issuer", "seal", "uid", "gid"} {
		if strings.Contains(strings.ToLower(string(encodedRequest)), forbidden) {
			t.Fatalf("admission request JSON can supply forbidden %s claim: %s", forbidden, encodedRequest)
		}
	}

	sinkType := reflect.TypeOf((*sandboxruntime.JobCredentialSecretSink)(nil)).Elem()
	wantSinkMethods := map[string]bool{"MaxCredentialBytes": true, "WriteCredential": true}
	if sinkType.NumMethod() != len(wantSinkMethods) {
		t.Fatalf("approved sink exposes %d methods, want exact bounded callback interface", sinkType.NumMethod())
	}
	for methodIndex := 0; methodIndex < sinkType.NumMethod(); methodIndex++ {
		if method := sinkType.Method(methodIndex); !wantSinkMethods[method.Name] {
			t.Fatalf("approved sink exposes raw retrieval method %s", method.Name)
		}
	}
}

func l8AssertCredentialSourceLiveValue(t *testing.T, label string, value any, expectedFormat string, forbidden []string) {
	t.Helper()
	jsonCodec, ok := value.(json.Marshaler)
	if !ok {
		t.Fatalf("%s does not explicitly deny JSON marshaling", label)
	}
	if encoded, err := jsonCodec.MarshalJSON(); encoded != nil || !errors.Is(err, ErrCredentialSourceSerialization) || err.Error() != ErrCredentialSourceSerialization.Error() {
		t.Fatalf("%s JSON codec did not return stable denial", label)
	}
	if encoded, err := json.Marshal(value); encoded != nil || !errors.Is(err, ErrCredentialSourceSerialization) {
		t.Fatalf("%s was serializable through encoding/json", label)
	}
	textCodec, ok := value.(encoding.TextMarshaler)
	if !ok {
		t.Fatalf("%s does not explicitly deny text marshaling", label)
	}
	if encoded, err := textCodec.MarshalText(); encoded != nil || !errors.Is(err, ErrCredentialSourceSerialization) || err.Error() != ErrCredentialSourceSerialization.Error() {
		t.Fatalf("%s text codec did not return stable denial", label)
	}
	l8AssertCredentialSourceAllVerbFormatting(t, label, value, expectedFormat, forbidden)
}

func l8AssertCredentialSourceAllVerbFormatting(t *testing.T, label string, value any, expectedFormat string, forbidden []string) {
	t.Helper()
	for _, variant := range l8CredentialSourceFormattingVariants(value) {
		if _, ok := variant.value.(fmt.Formatter); !ok {
			t.Fatalf("%s %s lacks fmt.Formatter", label, variant.name)
		}
		if rendered := l8CredentialSourceSafeSprintf(t, label+" "+variant.name+" %v", "%v", variant.value); rendered != expectedFormat {
			t.Fatalf("%s %s formatter output = %q, want exact %q", label, variant.name, rendered, expectedFormat)
		}
		for _, format := range l8CredentialSourceFormatterVerbs() {
			rendered := l8CredentialSourceSafeSprintf(t, label+" "+variant.name+" "+format, format, variant.value)
			if rendered != expectedFormat {
				t.Fatalf("%s %s formatting %s = %q, want fixed %q", label, variant.name, format, rendered, expectedFormat)
			}
			l8CredentialSourceRejectFormattingPoison(t, label+" "+variant.name+" "+format, rendered, forbidden)
		}
		renderedType := l8CredentialSourceSafeSprintf(t, label+" "+variant.name+" %T", "%T", variant.value)
		l8CredentialSourceRejectFormattingPoison(t, label+" "+variant.name+" %T", renderedType, forbidden)
		renderedPointer := l8CredentialSourceSafeSprintf(t, label+" "+variant.name+" %p", "%p", variant.value)
		l8CredentialSourceRejectPointerFormattingPoison(t, label+" "+variant.name+" %p", renderedPointer, forbidden)
		stringer, ok := variant.value.(fmt.Stringer)
		if !ok || l8CredentialSourceSafeFormatCall(t, label+" "+variant.name+" String", stringer.String) != expectedFormat {
			t.Fatalf("%s %s String output is not the fixed formatter output", label, variant.name)
		}
		goStringer, ok := variant.value.(fmt.GoStringer)
		if !ok || l8CredentialSourceSafeFormatCall(t, label+" "+variant.name+" GoString", goStringer.GoString) != expectedFormat {
			t.Fatalf("%s %s GoString output is not the fixed formatter output", label, variant.name)
		}
	}
}

type l8CredentialSourceFormattingVariant struct {
	name       string
	value      any
	nilPointer bool
}

func l8CredentialSourceFormattingVariants(value any) []l8CredentialSourceFormattingVariant {
	valueOf := reflect.ValueOf(value)
	variants := []l8CredentialSourceFormattingVariant{{name: "interface", value: value}}
	if valueOf.Kind() == reflect.Pointer {
		variants = append(variants, l8CredentialSourceFormattingVariant{name: "nil-pointer", value: reflect.Zero(valueOf.Type()).Interface(), nilPointer: true})
		return variants
	}
	pointer := reflect.New(valueOf.Type())
	pointer.Elem().Set(valueOf)
	variants = append(variants, l8CredentialSourceFormattingVariant{name: "pointer", value: pointer.Interface()})
	return variants
}

func l8CredentialSourceFormatterVerbs() []string {
	return []string{
		"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%o", "%O", "%b", "%U",
		"%e", "%E", "%f", "%F", "%g", "%G", "%c", "%t", "% 32v", "%-32v", "%032v", "%.3v", "%+32.3v", "%#q",
	}
}

func l8CredentialSourceSafeSprintf(t *testing.T, label, format string, value any) (rendered string) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("%s panicked: %v", label, recovered)
		}
	}()
	return fmt.Sprintf(format, value)
}

func l8CredentialSourceSafeFormatCall(t *testing.T, label string, format func() string) (rendered string) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("%s panicked: %v", label, recovered)
		}
	}()
	return format()
}

func l8CredentialSourceRejectFormattingPoison(t *testing.T, label, rendered string, forbidden []string) {
	t.Helper()
	for _, poison := range forbidden {
		if poison != "" && strings.Contains(rendered, poison) {
			t.Fatalf("%s exposed formatting poison %q in %q", label, poison, rendered)
		}
	}
}

func l8CredentialSourceRejectPointerFormattingPoison(t *testing.T, label, rendered string, forbidden []string) {
	t.Helper()
	// fmt handles %p before fmt.Formatter. Allocator addresses are non-secret
	// hexadecimal values, so a short numeric canary can occur by coincidence.
	// Keep deterministic semantic identity checks without making address layout
	// part of the credential redaction contract.
	for _, poison := range forbidden {
		if poison != "" && !l8CredentialSourceAllDecimal(poison) && strings.Contains(rendered, poison) {
			t.Fatalf("%s exposed formatting poison %q in %q", label, poison, rendered)
		}
	}
}

func l8CredentialSourceAllDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func l8Registry(t *testing.T) (*Registry, *l8Keyctl, *l8LockedMapping, *sandboxruntime.AuthenticatedWorkerPrincipalAuthority, sandboxruntime.AuthenticatedWorkerPrincipal) {
	t.Helper()
	return l8RegistryWithGeneration(t, "daemon-generation-1")
}

func l8RegistryWithGeneration(t *testing.T, daemonGeneration string) (*Registry, *l8Keyctl, *l8LockedMapping, *sandboxruntime.AuthenticatedWorkerPrincipalAuthority, sandboxruntime.AuthenticatedWorkerPrincipal) {
	t.Helper()
	request := l8AdmissionRequest()
	authority := l8PrincipalAuthority(t, "peercred-owner", daemonGeneration)
	principal := l8Principal(t, authority, "principal-owner", 1001, 1002)
	primaryKey := l8KeyIdentity(t, 41, principal.UID(), principal.GID(), "hal-primary")
	secondaryKey := l8KeyIdentity(t, 43, principal.UID(), principal.GID(), "hal-secondary")
	ungrantedKey := l8KeyIdentity(t, 42, principal.UID(), principal.GID(), "hal-ungranted")
	primarySource, err := NewSourceRegistration("source-primary", primaryKey)
	if err != nil {
		t.Fatal(err)
	}
	secondarySource, err := NewSourceRegistration("source-secondary", secondaryKey)
	if err != nil {
		t.Fatal(err)
	}
	ungrantedSource, err := NewSourceRegistration("source-ungranted", ungrantedKey)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := NewAdmissionGrantRegistration(authority, principal, request, []string{"source-primary", "source-secondary"})
	if err != nil {
		t.Fatal(err)
	}
	config, err := NewRegistryConfig(
		authority,
		principal.UID(),
		principal.GID(),
		[]SourceRegistration{primarySource, secondarySource, ungrantedSource},
		[]AdmissionGrantRegistration{grant},
	)
	if err != nil {
		t.Fatal(err)
	}
	keyctl := &l8Keyctl{descriptor: l8KeyDescriptor(t, principal.UID(), principal.GID(), "hal-primary")}
	memoryOps := &l8LockedMapping{region: make([]byte, 64), locked: true}
	registry, err := newRegistry(config, registryDeps{
		keyctl: keyctl,
		newLockedMapping: func(capacity int) (lockedSecretMapping, error) {
			memoryOps.region = make([]byte, capacity)
			return memoryOps, nil
		},
	})
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}
	return registry, keyctl, memoryOps, authority, principal
}

func l8AdmissionRequest() sandboxruntime.JobCredentialAdmissionRequest {
	now := time.Date(2026, time.August, 3, 4, 0, 0, 0, time.UTC)
	request := sandboxruntime.JobCredentialAdmissionRequest{
		Identity: sandboxruntime.JobCredentialAdmissionIdentity{
			SandboxID:                    "sandbox-1",
			ExecutionID:                  "execution-1",
			WorkerID:                     "worker-1",
			HostID:                       "host-owner",
			RuntimeDriver:                "microvm",
			RuntimeID:                    "runtime-1",
			RuntimeGeneration:            "runtime-generation-1",
			FirecrackerProcessGeneration: "process-generation-1",
			VsockGeneration:              "vsock-generation-1",
			WorkerJobID:                  "job-1",
			SubmissionID:                 "submission-1",
			PlanID:                       "plan-primary",
			ActivationGeneration:         "activation-generation-1",
			CredentialGeneration:         "credential-generation-1",
			NetworkPlanID:                "network-plan-1",
			PolicySnapshotID:             "policy-snapshot-1",
			ProxySessionID:               "proxy-session-1",
			ProxyGenerationID:            "proxy-generation-1",
			TopologyGenerationID:         "topology-generation-1",
			RuleGenerationID:             "rule-generation-1",
			IssuedAt:                     now,
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
	return request
}

type l8AdmissionIdentityMutation struct {
	name   string
	clear  func(*sandboxruntime.JobCredentialAdmissionIdentity)
	mutate func(*sandboxruntime.JobCredentialAdmissionIdentity)
}

type l8AdmissionRequestMutation struct {
	name   string
	clear  func(*sandboxruntime.JobCredentialAdmissionRequest)
	mutate func(*sandboxruntime.JobCredentialAdmissionRequest)
}

func l8AdmissionRequestMutations() []l8AdmissionRequestMutation {
	stringField := func(name string, selectField func(*sandboxruntime.JobCredentialAdmissionRequest) *string) l8AdmissionRequestMutation {
		return l8AdmissionRequestMutation{
			name:   name,
			clear:  func(value *sandboxruntime.JobCredentialAdmissionRequest) { *selectField(value) = "" },
			mutate: func(value *sandboxruntime.JobCredentialAdmissionRequest) { *selectField(value) += "-neighbor" },
		}
	}
	return []l8AdmissionRequestMutation{
		stringField("grant_id", func(value *sandboxruntime.JobCredentialAdmissionRequest) *string { return &value.GrantID }),
		{
			name:   "grant_revision",
			clear:  func(value *sandboxruntime.JobCredentialAdmissionRequest) { value.GrantRevision = 0 },
			mutate: func(value *sandboxruntime.JobCredentialAdmissionRequest) { value.GrantRevision++ },
		},
		stringField("plan_id", func(value *sandboxruntime.JobCredentialAdmissionRequest) *string { return &value.PlanID }),
		stringField("template_policy_id", func(value *sandboxruntime.JobCredentialAdmissionRequest) *string { return &value.TemplatePolicyID }),
		stringField("workspace_policy_id", func(value *sandboxruntime.JobCredentialAdmissionRequest) *string { return &value.WorkspacePolicyID }),
		{
			name:  "source_reference_ids",
			clear: func(value *sandboxruntime.JobCredentialAdmissionRequest) { value.SourceReferenceIDs = nil },
			mutate: func(value *sandboxruntime.JobCredentialAdmissionRequest) {
				value.SourceReferenceIDs = []string{"source-neighbor"}
			},
		},
		{
			name:  "bindings",
			clear: func(value *sandboxruntime.JobCredentialAdmissionRequest) { value.Bindings = nil },
			mutate: func(value *sandboxruntime.JobCredentialAdmissionRequest) {
				value.Bindings = append(value.Bindings, value.Bindings[0])
			},
		},
		{
			name:   "binding_id",
			clear:  func(value *sandboxruntime.JobCredentialAdmissionRequest) { value.Bindings[0].ID = "" },
			mutate: func(value *sandboxruntime.JobCredentialAdmissionRequest) { value.Bindings[0].ID = "binding-neighbor" },
		},
		{
			name:  "binding_mode",
			clear: func(value *sandboxruntime.JobCredentialAdmissionRequest) { value.Bindings[0].Mode = "" },
			mutate: func(value *sandboxruntime.JobCredentialAdmissionRequest) {
				value.Bindings[0].Mode = sandboxruntime.JobCredentialDeliveryModeFileTmpfs
			},
		},
		{
			name:  "binding_source_reference_id",
			clear: func(value *sandboxruntime.JobCredentialAdmissionRequest) { value.Bindings[0].SourceReferenceID = "" },
			mutate: func(value *sandboxruntime.JobCredentialAdmissionRequest) {
				value.Bindings[0].SourceReferenceID = "source-neighbor"
			},
		},
		{
			name:  "binding_service_id",
			clear: func(value *sandboxruntime.JobCredentialAdmissionRequest) { value.Bindings[0].ServiceID = "" },
			mutate: func(value *sandboxruntime.JobCredentialAdmissionRequest) {
				value.Bindings[0].ServiceID = "service-neighbor"
			},
		},
	}
}

func l8AdmissionIdentityMutations() []l8AdmissionIdentityMutation {
	stringField := func(name string, selectField func(*sandboxruntime.JobCredentialAdmissionIdentity) *string) l8AdmissionIdentityMutation {
		return l8AdmissionIdentityMutation{
			name:   name,
			clear:  func(value *sandboxruntime.JobCredentialAdmissionIdentity) { *selectField(value) = "" },
			mutate: func(value *sandboxruntime.JobCredentialAdmissionIdentity) { *selectField(value) += "-neighbor" },
		}
	}
	return []l8AdmissionIdentityMutation{
		stringField("sandbox_id", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string { return &value.SandboxID }),
		stringField("execution_id", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string { return &value.ExecutionID }),
		stringField("worker_id", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string { return &value.WorkerID }),
		stringField("host_id", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string { return &value.HostID }),
		stringField("runtime_driver", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string { return &value.RuntimeDriver }),
		stringField("runtime_id", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string { return &value.RuntimeID }),
		stringField("runtime_generation", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string { return &value.RuntimeGeneration }),
		stringField("firecracker_process_generation", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string {
			return &value.FirecrackerProcessGeneration
		}),
		stringField("vsock_generation", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string { return &value.VsockGeneration }),
		stringField("worker_job_id", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string { return &value.WorkerJobID }),
		stringField("submission_id", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string { return &value.SubmissionID }),
		stringField("plan_id", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string { return &value.PlanID }),
		stringField("activation_generation", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string { return &value.ActivationGeneration }),
		stringField("credential_generation", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string { return &value.CredentialGeneration }),
		stringField("network_plan_id", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string { return &value.NetworkPlanID }),
		stringField("policy_snapshot_id", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string { return &value.PolicySnapshotID }),
		stringField("proxy_session_id", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string { return &value.ProxySessionID }),
		stringField("proxy_generation_id", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string { return &value.ProxyGenerationID }),
		stringField("topology_generation_id", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string { return &value.TopologyGenerationID }),
		stringField("rule_generation_id", func(value *sandboxruntime.JobCredentialAdmissionIdentity) *string { return &value.RuleGenerationID }),
		{
			name:  "issued_at",
			clear: func(value *sandboxruntime.JobCredentialAdmissionIdentity) { value.IssuedAt = time.Time{} },
			mutate: func(value *sandboxruntime.JobCredentialAdmissionIdentity) {
				value.IssuedAt = value.IssuedAt.Add(time.Second)
			},
		},
	}
}

func l8PrincipalAuthority(t *testing.T, id, generation string) *sandboxruntime.AuthenticatedWorkerPrincipalAuthority {
	t.Helper()
	authority, err := sandboxruntime.NewAuthenticatedWorkerPrincipalAuthority(id, generation)
	if err != nil {
		t.Fatalf("new authenticated principal authority: %v", err)
	}
	return authority
}

func l8Principal(t *testing.T, authority *sandboxruntime.AuthenticatedWorkerPrincipalAuthority, id string, uid, gid uint32) sandboxruntime.AuthenticatedWorkerPrincipal {
	t.Helper()
	principal, err := authority.IssueAuthenticatedWorkerPrincipal(id, uid, gid)
	if err != nil {
		t.Fatalf("issue authenticated principal: %v", err)
	}
	return principal
}

func l8ImmutableKeyPermissions() KeyPermission {
	return KeyPermissionUserView |
		KeyPermissionUserRead
}

func l8KeyIdentity(t *testing.T, serial int32, uid, gid uint32, description string) KeyIdentity {
	t.Helper()
	identity, err := NewKeyIdentity(serial, "user", uid, gid, l8ImmutableKeyPermissions(), description)
	if err != nil {
		t.Fatalf("new key identity: %v", err)
	}
	return identity
}

func l8KeyDescriptor(t *testing.T, uid, gid uint32, description string) l8KeyDescriptorFixture {
	t.Helper()
	return l8KeyDescriptorFixture{
		keyType:     "user",
		ownerUID:    uid,
		ownerGID:    gid,
		permissions: l8ImmutableKeyPermissions(),
		description: description,
	}
}

type l8Keyctl struct {
	calls                     []string
	serials                   []int32
	descriptor                l8KeyDescriptorFixture
	pendingDescriptor         []byte
	describeBuffers           [][]byte
	rawDescriptorOverride     []byte
	value                     []byte
	reportedSize              int
	forceReportedSize         bool
	describeReportedSize      int
	forceDescribeReportedSize bool
	describeIntoN             int
	forceDescribeIntoN        bool
	readIntoN                 int
	forceReadIntoN            bool
	describeSizeErr           error
	describeErr               error
	shortDescribe             bool
	sizeErr                   error
	readErr                   error
	shortRead                 bool
	afterCall                 func(string)
	inspectCount              int
	replaceAtInspect          int
	permissionAtInspect       int
	typeAtInspect             int
	descriptionAtInspect      int
	ownerUIDAtInspect         int
	ownerGIDAtInspect         int
}

func (keyctl *l8Keyctl) DescribeSize(_ context.Context, serial int32) (int, error) {
	keyctl.calls = append(keyctl.calls, "describe_size")
	keyctl.serials = append(keyctl.serials, serial)
	defer keyctl.finishCall("describe_size")
	keyctl.inspectCount++
	if keyctl.describeSizeErr != nil {
		return 0, keyctl.describeSizeErr
	}
	descriptor := keyctl.descriptor
	if keyctl.replaceAtInspect == keyctl.inspectCount {
		descriptor.description = "hal-replaced"
	}
	if keyctl.permissionAtInspect == keyctl.inspectCount {
		descriptor.permissions |= KeyPermissionUserWrite
	}
	if keyctl.typeAtInspect == keyctl.inspectCount {
		descriptor.keyType = "logon"
	}
	if keyctl.descriptionAtInspect == keyctl.inspectCount {
		descriptor.description = "hal-description-neighbor"
	}
	if keyctl.ownerUIDAtInspect == keyctl.inspectCount {
		descriptor.ownerUID++
	}
	if keyctl.ownerGIDAtInspect == keyctl.inspectCount {
		descriptor.ownerGID++
	}
	keyctl.pendingDescriptor = l8RawKeyDescriptor(descriptor)
	if keyctl.rawDescriptorOverride != nil {
		keyctl.pendingDescriptor = append([]byte(nil), keyctl.rawDescriptorOverride...)
	}
	if keyctl.forceDescribeReportedSize {
		return keyctl.describeReportedSize, nil
	}
	return len(keyctl.pendingDescriptor), nil
}

func (keyctl *l8Keyctl) DescribeInto(_ context.Context, serial int32, dst []byte) (int, error) {
	keyctl.calls = append(keyctl.calls, "describe")
	keyctl.serials = append(keyctl.serials, serial)
	defer keyctl.finishCall("describe")
	keyctl.describeBuffers = append(keyctl.describeBuffers, dst)
	copy(dst, keyctl.pendingDescriptor)
	if keyctl.describeErr != nil {
		return 0, keyctl.describeErr
	}
	if keyctl.forceDescribeIntoN {
		return keyctl.describeIntoN, nil
	}
	if keyctl.shortDescribe && len(keyctl.pendingDescriptor) > 0 {
		return len(keyctl.pendingDescriptor) - 1, nil
	}
	return len(keyctl.pendingDescriptor), nil
}

func (keyctl *l8Keyctl) ReadSize(_ context.Context, serial int32) (int, error) {
	keyctl.calls = append(keyctl.calls, "read_size")
	keyctl.serials = append(keyctl.serials, serial)
	defer keyctl.finishCall("read_size")
	if keyctl.sizeErr != nil {
		return 0, keyctl.sizeErr
	}
	if keyctl.forceReportedSize || keyctl.reportedSize != 0 {
		return keyctl.reportedSize, nil
	}
	return len(keyctl.value), nil
}

func (keyctl *l8Keyctl) ReadInto(_ context.Context, serial int32, dst []byte) (int, error) {
	keyctl.calls = append(keyctl.calls, "read")
	keyctl.serials = append(keyctl.serials, serial)
	defer keyctl.finishCall("read")
	copy(dst, keyctl.value)
	if keyctl.readErr != nil {
		return 0, keyctl.readErr
	}
	if keyctl.forceReadIntoN {
		return keyctl.readIntoN, nil
	}
	if keyctl.shortRead && len(keyctl.value) > 0 {
		return len(keyctl.value) - 1, nil
	}
	return len(keyctl.value), nil
}

func (keyctl *l8Keyctl) finishCall(name string) {
	if keyctl.afterCall != nil {
		keyctl.afterCall(name)
	}
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

func (mapping *l8LockedMapping) Borrow(ctx context.Context, callback func(lockedSecretBorrowedView) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	view := &l8CredentialBorrowedView{mapping: mapping, active: true}
	err := callback(view)
	view.active = false
	return err
}

type l8CredentialBorrowedView struct {
	mapping *l8LockedMapping
	active  bool
}

func (view *l8CredentialBorrowedView) WriteTo(ctx context.Context, sink sandboxruntime.JobCredentialSecretSink) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !view.active {
		return errors.New("expired test view")
	}
	if sink.MaxCredentialBytes() < view.mapping.length {
		return errors.New("sink capacity exceeded")
	}
	return sink.WriteCredential(view.mapping.region[:view.mapping.length])
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
	limit  int
	count  int
	size   int
	digest [sha256.Size]byte
}

func (sink *l8SecretSink) MaxCredentialBytes() int { return sink.limit }
func (sink *l8SecretSink) WriteCredential(value []byte) error {
	// The callback-scoped window is inspected immediately. The sink retains no
	// credential bytes, only non-reversible test evidence.
	sink.count++
	sink.size = len(value)
	sink.digest = sha256.Sum256(value)
	return nil
}

type l8KeyDescriptorFixture struct {
	keyType     string
	ownerUID    uint32
	ownerGID    uint32
	permissions KeyPermission
	description string
}

func l8RawKeyDescriptor(descriptor l8KeyDescriptorFixture) []byte {
	return []byte(fmt.Sprintf("%s;%d;%d;%08x;%s\x00", descriptor.keyType, descriptor.ownerUID, descriptor.ownerGID, uint32(descriptor.permissions), descriptor.description))
}

func l8AllZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}
