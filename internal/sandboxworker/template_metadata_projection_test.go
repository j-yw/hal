package sandboxworker

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestUS005WorkerProtocolCarriesTemplateMetadataStates(t *testing.T) {
	tests := []struct {
		name           string
		metadata       *sandboxruntime.RuntimeMetadata
		wantPresent    bool
		wantLockStatus string
		wantDecision   string
	}{
		{
			name:           "locked trusted",
			metadata:       us005WorkerRuntimeMetadata(us005WorkerTemplateLockTrusted()),
			wantPresent:    true,
			wantLockStatus: "locked",
			wantDecision:   "trusted",
		},
		{
			name:           "unresolved unavailable",
			metadata:       us005WorkerRuntimeMetadata(us005WorkerTemplateLockUnresolved()),
			wantPresent:    true,
			wantLockStatus: "unresolved",
			wantDecision:   "unavailable",
		},
		{
			name:           "rejected locked",
			metadata:       us005WorkerRuntimeMetadata(us005WorkerTemplateLockRejected()),
			wantPresent:    true,
			wantLockStatus: "locked",
			wantDecision:   "rejected",
		},
		{
			name:        "absent",
			metadata:    nil,
			wantPresent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := Status{
				ProtocolVersion:         ProtocolVersion,
				WorkerID:                "worker-us005",
				HostKind:                HostKindLocal,
				SupportedRuntimeDrivers: []string{RuntimeDriverMicroVM},
				Health:                  WorkerHealth{Status: HealthStatusHealthy},
				Capacity:                WorkerCapacity{MaxConcurrentSandboxes: 1},
				Security:                honestSecurityPolicy(),
				Metadata:                tt.metadata,
			}
			capabilities := Capabilities{
				ProtocolVersion: ProtocolVersion,
				WorkerID:        "worker-us005",
				RuntimeDrivers: []RuntimeDriver{{
					ID:             RuntimeDriverMicroVM,
					HostKind:       HostKindLocal,
					IsolationLevel: IsolationLevelVM,
					Operations:     []string{OperationCreate, OperationInspect},
					Security:       honestSecurityPolicy(),
					Metadata:       tt.metadata,
				}},
				Security: honestSecurityPolicy(),
				Metadata: tt.metadata,
			}
			target := Target{
				ID:     "target-us005",
				Name:   "template-status-target",
				Status: "running",
				Runtime: RuntimeTarget{
					Driver:         RuntimeDriverMicroVM,
					RuntimeID:      "runtime-us005",
					WorkerID:       "worker-us005",
					IsolationLevel: IsolationLevelVM,
					Metadata:       tt.metadata,
				},
			}
			for _, payload := range []struct {
				name  string
				value any
			}{
				{name: "status", value: status},
				{name: "capabilities", value: capabilities},
				{name: "target", value: target},
			} {
				t.Run(payload.name, func(t *testing.T) {
					data, err := json.Marshal(payload.value)
					if err != nil {
						t.Fatalf("Marshal(%s) error = %v", payload.name, err)
					}
					publicText := string(data)
					assertUS005WorkerTemplateProjectionNoUnsafeFragments(t, payload.name, publicText)
					if !tt.wantPresent {
						if strings.Contains(publicText, `"templateStatus"`) || strings.Contains(publicText, `"templateLock"`) {
							t.Fatalf("%s JSON unexpectedly carried absent template metadata: %s", payload.name, publicText)
						}
						return
					}
					for _, want := range []string{
						`"metadata":`,
						`"templateLock":`,
						`"templateStatus":`,
						`"lockStatus":"` + tt.wantLockStatus + `"`,
						`"trustDecision":"` + tt.wantDecision + `"`,
					} {
						if !strings.Contains(publicText, want) {
							t.Fatalf("%s JSON %s missing %s", payload.name, publicText, want)
						}
					}
				})
			}
		})
	}
}

func TestUS005WorkerServiceProjectsTemplateMetadataThroughStatusAndCapabilities(t *testing.T) {
	registry := &DriverRegistry{}
	if err := registry.Register(&fakeWorkerRuntimeDriver{id: RuntimeDriverMicroVM}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-us005-service",
		Registry: registry,
		RuntimeDrivers: map[string]RuntimeDriver{
			RuntimeDriverMicroVM: {
				ID:             RuntimeDriverMicroVM,
				HostKind:       HostKindLocal,
				IsolationLevel: IsolationLevelVM,
				Operations:     []string{OperationCreate, OperationInspect},
				Security:       honestSecurityPolicy(),
				Metadata:       us005WorkerRuntimeMetadata(us005WorkerTemplateLockRejected()),
			},
		},
		Metadata: us005WorkerRuntimeMetadata(us005WorkerTemplateLockUnresolved()),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	status := service.Status()
	if status.Metadata == nil || status.Metadata.TemplateStatus == nil || status.Metadata.TemplateStatus.LockStatus != "unresolved" {
		t.Fatalf("service status metadata = %#v, want unresolved selected-template metadata", status.Metadata)
	}
	capabilities := service.Capabilities()
	if capabilities.Metadata == nil || capabilities.Metadata.TemplateStatus == nil || capabilities.Metadata.TemplateStatus.LockStatus != "unresolved" {
		t.Fatalf("service capabilities metadata = %#v, want worker selected-template metadata", capabilities.Metadata)
	}
	if len(capabilities.RuntimeDrivers) != 1 {
		t.Fatalf("runtime drivers = %d, want 1", len(capabilities.RuntimeDrivers))
	}
	driverMetadata := capabilities.RuntimeDrivers[0].Metadata
	if driverMetadata == nil || driverMetadata.TemplateStatus == nil || driverMetadata.TemplateStatus.TrustDecision != "rejected" {
		t.Fatalf("runtime driver metadata = %#v, want rejected selected-template metadata", driverMetadata)
	}
}

func TestUS005WorkerTargetRoundTripPreservesRuntimeTemplateMetadata(t *testing.T) {
	runtimeTarget := sandboxruntime.Target{
		ID:     "target-us005",
		Name:   "runtime-target-us005",
		Status: "running",
		Runtime: sandboxruntime.RuntimeState{
			Driver:         sandboxruntime.DriverMicroVM,
			RuntimeID:      "runtime-us005",
			WorkerID:       "worker-us005",
			IsolationLevel: IsolationLevelVM,
			Metadata:       us005WorkerRuntimeMetadata(us005WorkerTemplateLockTrusted()),
		},
	}

	workerTarget := workerTargetFromRuntimeTarget(runtimeTarget, RuntimeDriverMicroVM)
	if workerTarget.Runtime.Metadata == nil || workerTarget.Runtime.Metadata.TemplateStatus == nil {
		t.Fatalf("worker target metadata = %#v, want template status", workerTarget.Runtime.Metadata)
	}
	if got := workerTarget.Runtime.Metadata.TemplateStatus.TrustDecision; got != "trusted" {
		t.Fatalf("worker target trustDecision = %q, want trusted", got)
	}

	roundTrip := runtimeTargetFromWorkerTarget(workerTarget)
	if roundTrip.Runtime.Metadata == nil || roundTrip.Runtime.Metadata.TemplateStatus == nil {
		t.Fatalf("runtime round-trip metadata = %#v, want template status", roundTrip.Runtime.Metadata)
	}
	if got := roundTrip.Runtime.Metadata.TemplateStatus.LockStatus; got != "locked" {
		t.Fatalf("runtime round-trip lockStatus = %q, want locked", got)
	}
}

func us005WorkerRuntimeMetadata(lock *sandboxruntime.RuntimeTemplateLockMetadata) *sandboxruntime.RuntimeMetadata {
	return &sandboxruntime.RuntimeMetadata{TemplateLock: lock}
}

func us005WorkerTemplateLockTrusted() *sandboxruntime.RuntimeTemplateLockMetadata {
	return &sandboxruntime.RuntimeTemplateLockMetadata{
		Document:          us005WorkerTemplateLockEntry("local_file", "local", "document_digest", "a", "locked"),
		TemplateReference: us005WorkerTemplateLockEntry("template_reference", "oci_artifact", "template_reference_digest", "b", "locked"),
		RuntimeImage:      us005WorkerTemplateLockEntry("runtime_image", "oci_image", "runtime_image_digest", "c", "locked"),
		SourceArtifact:    us005WorkerTemplateLockEntry("source_artifact", "git", "source_artifact_digest", "d", "locked"),
		TrustPolicy: &sandboxruntime.RuntimeTemplateTrustPolicyMetadata{
			Mode:            "strict",
			Decision:        "trusted",
			SourceKind:      "local_file",
			ReferenceKind:   "local",
			Status:          "locked",
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("e", 64),
		},
	}
}

func us005WorkerTemplateLockUnresolved() *sandboxruntime.RuntimeTemplateLockMetadata {
	lock := us005WorkerTemplateLockTrusted()
	lock.RuntimeImage = &sandboxruntime.RuntimeTemplateLockEntryMetadata{
		SourceKind:    "runtime_image",
		ReferenceKind: "oci_image",
		Status:        "unresolved",
		ReasonCode:    "unresolved_mutable_reference",
		WarningCodes:  []string{"https://registry.example.test/image:latest?token=ghp_us005_secret"},
	}
	lock.TrustPolicy.Decision = "unavailable"
	lock.TrustPolicy.Status = "unresolved"
	lock.TrustPolicy.ReasonCodes = []string{"unresolved_lock_entry", "https://registry.example.test/private"}
	return lock
}

func us005WorkerTemplateLockRejected() *sandboxruntime.RuntimeTemplateLockMetadata {
	lock := us005WorkerTemplateLockTrusted()
	lock.TrustPolicy.Decision = "rejected"
	lock.TrustPolicy.ReasonCodes = []string{"mutable_reference", "https://registry.example.test/private?token=ghp_us005_secret"}
	lock.TrustPolicy.ErrorCodes = []string{"missing_digest_pin", "/Users/alice/.cache/hal/template.yaml"}
	lock.TrustPolicy.WarningCodes = []string{"lock_provenance_mismatch", "unix:///tmp/hal-template.sock"}
	return lock
}

func us005WorkerTemplateLockEntry(sourceKind, referenceKind, reasonCode, digestSeed, status string) *sandboxruntime.RuntimeTemplateLockEntryMetadata {
	return &sandboxruntime.RuntimeTemplateLockEntryMetadata{
		SourceKind:      sourceKind,
		ReferenceKind:   referenceKind,
		Status:          status,
		DigestAlgorithm: "sha256",
		DigestValue:     strings.Repeat(digestSeed, 64),
		SizeBytes:       4096,
		LockedAt:        "2026-07-04T06:18:17Z",
		WarningCodes:    []string{reasonCode, "token=ghp_us005_secret"},
		ReasonCode:      reasonCode,
	}
}

func assertUS005WorkerTemplateProjectionNoUnsafeFragments(t *testing.T, label string, payload string) {
	t.Helper()
	for _, fragment := range []string{
		"registry.example.test",
		"token=",
		"ghp_us005_secret",
		"/Users/",
		"/tmp/",
		".sock",
		"unix://",
		"adapter",
	} {
		if strings.Contains(payload, fragment) {
			t.Fatalf("%s leaked unsafe template metadata fragment %q: %s", label, fragment, payload)
		}
	}
}
