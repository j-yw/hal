package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
	"github.com/spf13/cobra"
)

func TestUS007RuntimeStatusJSONSelectedTemplateStates(t *testing.T) {
	tests := []struct {
		name        string
		hostID      string
		lock        *sandbox.SandboxTemplateLockMetadata
		wantState   string
		wantTrust   string
		wantPresent bool
		wantBlocked string
	}{
		{
			name:        "trusted selected template",
			hostID:      "us007-trusted",
			lock:        us006CommandSelectedTemplateTrustedLock(),
			wantState:   "trusted",
			wantTrust:   sandbox.SandboxTemplateTrustPolicyDecisionTrusted,
			wantPresent: true,
		},
		{
			name:        "unresolved selected template",
			hostID:      "us007-unresolved",
			lock:        us006CommandSelectedTemplateUnresolvedLock(),
			wantState:   "unresolved",
			wantTrust:   sandbox.SandboxTemplateTrustPolicyDecisionTrusted,
			wantPresent: true,
			wantBlocked: string(sandbox.SandboxSecurityCapabilityReasonSelectedTemplateProvenanceUnresolved),
		},
		{
			name:        "rejected selected template",
			hostID:      "us007-rejected",
			lock:        us006CommandSelectedTemplateRejectedLock(),
			wantState:   "rejected",
			wantTrust:   sandbox.SandboxTemplateTrustPolicyDecisionRejected,
			wantPresent: true,
			wantBlocked: string(sandbox.SandboxSecurityCapabilityReasonSelectedTemplateTrustRejected),
		},
		{
			name:        "absent selected template",
			hostID:      "us007-absent",
			lock:        nil,
			wantState:   "absent",
			wantPresent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, output := us007RuntimeStatusJSON(t, tt.hostID, tt.lock)
			got := resp.SelectedTemplate
			if got.State != tt.wantState || got.Present != tt.wantPresent {
				t.Fatalf("selectedTemplate = %#v, want state=%q present=%t", got, tt.wantState, tt.wantPresent)
			}
			if got.TrustDecision != tt.wantTrust {
				t.Fatalf("selectedTemplate.trustDecision = %q, want %q; selectedTemplate=%#v", got.TrustDecision, tt.wantTrust, got)
			}
			if tt.wantPresent {
				if got.SourceKind == "" || got.ReferenceKind == "" {
					t.Fatalf("selectedTemplate identity = %#v, want safe source/reference identity", got)
				}
				if got.Digest == nil || got.Digest.Algorithm != "sha256" || got.Digest.Value == "" {
					t.Fatalf("selectedTemplate.digest = %#v, want locked sha256 digest", got.Digest)
				}
				if got.ProvenanceStatus == "" || len(got.ProvenanceLabels) == 0 {
					t.Fatalf("selectedTemplate provenance = %#v, want status and labels", got)
				}
			}
			if tt.wantBlocked != "" && !containsUS007String(got.BlockedReadinessReasonCodes, tt.wantBlocked) {
				t.Fatalf("selectedTemplate.blockedReadinessReasonCodes = %#v, want %q", got.BlockedReadinessReasonCodes, tt.wantBlocked)
			}
			us007AssertNoUnsafeTemplateFragments(t, output)
		})
	}
}

func TestUS007RuntimeListHumanOutputShowsTemplateTrustProvenanceAndBlockedReasons(t *testing.T) {
	resp, jsonOutput := us007RuntimeListJSON(t, "us007-list", us006CommandSelectedTemplateUnresolvedLock())
	if len(resp.Runtimes) != 1 {
		t.Fatalf("runtime entries = %d, want 1", len(resp.Runtimes))
	}
	if got := resp.Runtimes[0].SelectedTemplate; got.State != "unresolved" || !containsUS007String(got.BlockedReadinessReasonCodes, string(sandbox.SandboxSecurityCapabilityReasonSelectedTemplateProvenanceUnresolved)) {
		t.Fatalf("runtime selectedTemplate = %#v, want unresolved blocked template summary", got)
	}
	us007AssertNoUnsafeTemplateFragments(t, jsonOutput)

	humanOutput := us007RuntimeListHuman(t, "us007-list-human", us006CommandSelectedTemplateRejectedLock())
	for _, want := range []string{
		"SELECTED TEMPLATE",
		"rejected",
		"trust rejected",
		"provenance locked",
		"sha256:",
		string(sandbox.SandboxSecurityCapabilityReasonSelectedTemplateTrustRejected),
	} {
		if !strings.Contains(humanOutput, want) {
			t.Fatalf("runtime list human output missing %q:\n%s", want, humanOutput)
		}
	}
	us007AssertNoUnsafeTemplateFragments(t, humanOutput)
}

func TestUS007RuntimeStatusHumanOutputShowsAbsentSelectedTemplate(t *testing.T) {
	_, jsonOutput := us007RuntimeStatusJSON(t, "us007-status-absent", nil)
	if !strings.Contains(jsonOutput, `"selectedTemplate"`) || !strings.Contains(jsonOutput, `"state": "absent"`) {
		t.Fatalf("runtime status JSON missing absent selectedTemplate state:\n%s", jsonOutput)
	}

	humanOutput := us007RuntimeStatusHuman(t, "us007-status-human-absent", nil)
	for _, want := range []string{
		"Selected template:",
		"absent",
		"blocked reasons none",
	} {
		if !strings.Contains(humanOutput, want) {
			t.Fatalf("runtime status human output missing %q:\n%s", want, humanOutput)
		}
	}
}

func TestUS007SelectedTemplateFallbackReadinessFailsClosedWithoutDigestLockedTrustEvidence(t *testing.T) {
	tests := []struct {
		name       string
		metadata   *sandboxruntime.RuntimeMetadata
		wantReason string
	}{
		{
			name: "status-only trusted metadata is not proof",
			metadata: &sandboxruntime.RuntimeMetadata{
				TemplateStatus: &sandboxruntime.RuntimeTemplateStatusMetadata{
					LockStatus:       sandbox.SandboxTemplateLockStatusLocked,
					TrustMode:        sandbox.SandboxTemplateTrustPolicyModeStrict,
					TrustDecision:    sandbox.SandboxTemplateTrustPolicyDecisionTrusted,
					ProvenanceLabels: []string{"template_reference"},
					ReasonCodes:      []string{"https://registry.example.test/template:latest?token=ghp_us007_secret"},
				},
			},
			wantReason: string(sandbox.SandboxSecurityCapabilityReasonSelectedTemplateEvidenceMissing),
		},
		{
			name:       "trusted policy without digest is not proof",
			metadata:   us007RuntimeMetadataFromSelectedTemplateLock(us007SelectedTemplateTrustPolicyDigestMissingLock()),
			wantReason: string(sandbox.SandboxSecurityCapabilityReasonSelectedTemplateEvidenceMissing),
		},
		{
			name:       "trusted template reference without digest is not proof",
			metadata:   us007RuntimeMetadataFromSelectedTemplateLock(us007SelectedTemplateReferenceDigestMissingLock()),
			wantReason: string(sandbox.SandboxSecurityCapabilityReasonSelectedTemplateEvidenceMissing),
		},
		{
			name:       "warning-bearing trusted metadata is not proof",
			metadata:   us007RuntimeMetadataFromSelectedTemplateLock(us007SelectedTemplateWarningBearingLock()),
			wantReason: string(sandbox.SandboxSecurityCapabilityReasonWarningBearing),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := newSandboxRuntimeSelectedTemplate(tt.metadata, SandboxRuntimeSecuritySummary{})
			if !summary.Present {
				t.Fatalf("selectedTemplate = %#v, want present diagnostic metadata", summary)
			}
			if summary.ReadinessStatus != string(sandbox.SandboxSecurityCapabilityReadinessUnsupported) {
				t.Fatalf("selectedTemplate.readinessStatus = %q, want unsupported; summary=%#v", summary.ReadinessStatus, summary)
			}
			if !containsUS007String(summary.BlockedReadinessReasonCodes, tt.wantReason) {
				t.Fatalf("selectedTemplate.blockedReadinessReasonCodes = %#v, want %q", summary.BlockedReadinessReasonCodes, tt.wantReason)
			}
			us007AssertNoUnsafeTemplateFragments(t, us007MarshalSelectedTemplate(t, summary))
		})
	}
}

func TestUS007SandboxStatusHumanOutputShowsSelectedTemplate(t *testing.T) {
	setupStatusTest(t)
	saveStatusTestInstance(t, &sandbox.SandboxState{
		ID:       "us007-sandbox-status",
		Name:     "us007-sandbox-status",
		Provider: "local",
		Status:   sandbox.StatusRunning,
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			RuntimeID:      "runtime-us007",
			TemplateLock:   us006CommandSelectedTemplateTrustedLock(),
		},
	})

	var out bytes.Buffer
	if err := runSandboxStatusWithDeps("us007-sandbox-status", &out, &mockStatusProvider{statusOut: "Status: active"}); err != nil {
		t.Fatalf("runSandboxStatusWithDeps() error = %v", err)
	}
	output := out.String()
	for _, want := range []string{
		"Runtime:",
		"Driver:            rootless_podman",
		"Selected template: trusted",
		"trust trusted",
		"provenance locked",
		"sha256:",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("sandbox status output missing %q:\n%s", want, output)
		}
	}
	us007AssertNoUnsafeTemplateFragments(t, output)
}

func us007RuntimeStatusJSON(t *testing.T, hostID string, lock *sandbox.SandboxTemplateLockMetadata) (SandboxRuntimeStatusResponse, string) {
	t.Helper()
	cmd, stdout, stderr := us007RuntimeCommand(t, hostID, lock)
	cmd.SetArgs([]string{"status", hostID, sandboxworker.RuntimeDriverRootlessPodman, "--live", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("runtime status Execute() error = %v; stderr=%q", err, stderr.String())
	}
	return decodeOneSandboxRuntimeStatusJSON(t, stdout.Bytes()), stdout.String()
}

func us007RuntimeStatusHuman(t *testing.T, hostID string, lock *sandbox.SandboxTemplateLockMetadata) string {
	t.Helper()
	cmd, stdout, stderr := us007RuntimeCommand(t, hostID, lock)
	cmd.SetArgs([]string{"status", hostID, sandboxworker.RuntimeDriverRootlessPodman, "--live"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("runtime status human Execute() error = %v; stderr=%q", err, stderr.String())
	}
	return stdout.String()
}

func us007RuntimeListJSON(t *testing.T, hostID string, lock *sandbox.SandboxTemplateLockMetadata) (SandboxRuntimeListResponse, string) {
	t.Helper()
	cmd, stdout, stderr := us007RuntimeCommand(t, hostID, lock)
	cmd.SetArgs([]string{"list", hostID, "--live", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("runtime list Execute() error = %v; stderr=%q", err, stderr.String())
	}
	return decodeOneSandboxRuntimeListJSON(t, stdout.Bytes()), stdout.String()
}

func us007RuntimeListHuman(t *testing.T, hostID string, lock *sandbox.SandboxTemplateLockMetadata) string {
	t.Helper()
	cmd, stdout, stderr := us007RuntimeCommand(t, hostID, lock)
	cmd.SetArgs([]string{"list", hostID, "--live"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("runtime list human Execute() error = %v; stderr=%q", err, stderr.String())
	}
	return stdout.String()
}

func us007RuntimeCommand(t *testing.T, hostID string, lock *sandbox.SandboxTemplateLockMetadata) (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:                hostID,
		Name:              hostID + "-builder",
		Kind:              sandbox.SandboxHostKindWorker,
		Endpoint:          "unix:///tmp/us007-runtime.sock",
		SupportedRuntimes: []string{sandboxworker.RuntimeDriverRootlessPodman},
		Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 2},
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	refreshedAt := time.Date(2026, 7, 4, 6, 18, 17, 0, time.UTC)
	client := &fakeSandboxHostWorkerClient{
		status: &sandboxworker.Status{
			WorkerID:                hostID,
			HostKind:                sandboxworker.HostKindWorker,
			SupportedRuntimeDrivers: []string{sandboxworker.RuntimeDriverRootlessPodman},
			Health:                  sandboxworker.WorkerHealth{Status: sandboxworker.HealthStatusHealthy},
			Capacity:                sandboxworker.WorkerCapacity{MaxConcurrentSandboxes: 2},
		},
		capabilities: &sandboxworker.Capabilities{
			WorkerID:            hostID,
			SupportedOperations: []string{sandboxworker.OperationStatus, sandboxworker.OperationCapabilities},
			RuntimeDrivers: []sandboxworker.RuntimeDriver{{
				ID:             sandboxworker.RuntimeDriverRootlessPodman,
				HostKind:       sandboxworker.HostKindLocal,
				IsolationLevel: sandboxworker.IsolationLevelContainer,
				Operations:     []string{sandboxworker.OperationStatus},
				Metadata: &sandboxruntime.RuntimeMetadata{
					TemplateLock: sandboxRuntimeTemplateLockFromSandbox(lock),
				},
			}},
		},
	}
	deps := defaultSandboxRuntimeDeps()
	deps.now = func() time.Time { return refreshedAt }
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		return client, nil
	}
	return newTestSandboxRuntimeCommand(deps)
}

func us007RuntimeMetadataFromSelectedTemplateLock(lock *sandbox.SandboxTemplateLockMetadata) *sandboxruntime.RuntimeMetadata {
	return &sandboxruntime.RuntimeMetadata{
		TemplateLock: sandboxRuntimeTemplateLockFromSandbox(lock),
	}
}

func us007SelectedTemplateTrustPolicyDigestMissingLock() *sandbox.SandboxTemplateLockMetadata {
	lock := us006CommandSelectedTemplateTrustedLock()
	lock.TrustPolicy.DigestAlgorithm = ""
	lock.TrustPolicy.DigestValue = ""
	return sandbox.SanitizeSandboxTemplateLockMetadata(lock)
}

func us007SelectedTemplateReferenceDigestMissingLock() *sandbox.SandboxTemplateLockMetadata {
	lock := us006CommandSelectedTemplateTrustedLock()
	lock.TemplateReference.DigestAlgorithm = ""
	lock.TemplateReference.DigestValue = ""
	return sandbox.SanitizeSandboxTemplateLockMetadata(lock)
}

func us007SelectedTemplateWarningBearingLock() *sandbox.SandboxTemplateLockMetadata {
	lock := us006CommandSelectedTemplateTrustedLock()
	lock.TemplateReference.WarningCodes = []string{
		sandbox.SandboxTemplateLockReasonMutableReference,
		"https://registry.example.test/template:latest?token=ghp_us007_secret",
	}
	lock.TrustPolicy.WarningCodes = []string{
		sandbox.SandboxTemplateTrustPolicyCodeMutableReference,
		"Authorization: Bearer ghp_us007_secret",
	}
	return sandbox.SanitizeSandboxTemplateLockMetadata(lock)
}

func us007MarshalSelectedTemplate(t *testing.T, summary SandboxRuntimeSelectedTemplate) string {
	t.Helper()
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("Marshal(selectedTemplate) error = %v", err)
	}
	return string(data)
}

func containsUS007String(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func us007AssertNoUnsafeTemplateFragments(t *testing.T, output string) {
	t.Helper()
	for _, forbidden := range []string{
		"registry.example.test",
		"token=",
		"ghp_us006_secret",
		"/Users/",
		"/tmp/",
		".sock",
		"unix://",
		"Authorization",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("US-007 output leaked unsafe template fragment %q:\n%s", forbidden, output)
		}
	}
}
