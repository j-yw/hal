package cmd

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestL8CredentialDeliverySourceGuardsMetadataLayersRemainLiveBehaviorFree(t *testing.T) {
	targets := l8CredentialMetadataFiles(t)
	for _, path := range targets {
		source := readL8CredentialDeliveryFile(t, path)
		for _, marker := range []string{
			"LiveSecretSource",
			"JobCredentialRuntime",
			"guest-agent-v2",
			"sandboxjob-v2",
			"keyctl_read",
			"tls.Conn",
			"net.Listen",
			"SOCK_SEQPACKET",
			"cgroup.kill",
		} {
			if strings.Contains(source, marker) {
				t.Fatalf("metadata-only production file %s contains L8 live marker %q", filepath.ToSlash(path), marker)
			}
		}

		parsed, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse metadata-only production file %s: %v", filepath.ToSlash(path), err)
		}
		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", filepath.ToSlash(path), err)
			}
			for _, forbidden := range []string{
				"github.com/jywlabs/hal/internal/credentialmemory",
				"github.com/jywlabs/hal/internal/credentialsource",
				"github.com/jywlabs/hal/internal/credentialproxy",
				"github.com/jywlabs/hal/internal/sandboxworker",
				"github.com/jywlabs/hal/internal/sandboxruntime",
				"crypto/tls",
				"net",
				"net/http",
				"os/exec",
				"golang.org/x/sys/unix",
			} {
				if importPath == forbidden || strings.HasPrefix(importPath, forbidden+"/") {
					t.Fatalf("metadata-only production file %s imports L8 live dependency %q", filepath.ToSlash(path), importPath)
				}
			}
		}
	}
}

func TestL8CredentialDeliverySourceGuardsCommandCompositionHasNoPrematureLiveImports(t *testing.T) {
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source := readL8CredentialDeliveryFile(t, path)
		parsed, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("parse command production file %s: %w", filepath.ToSlash(path), err)
		}
		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return fmt.Errorf("unquote command import in %s: %w", filepath.ToSlash(path), err)
			}
			for _, forbidden := range []string{
				"github.com/jywlabs/hal/internal/credentialmemory",
				"github.com/jywlabs/hal/internal/credentialsource",
				"github.com/jywlabs/hal/internal/credentialproxy",
				"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol",
				"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper",
				"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session",
				"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/v2control",
				"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server/credentialclient",
				"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/l8composition",
				"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/rolebootstrap",
				"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/sshrelay",
			} {
				if importPath == forbidden || strings.HasPrefix(importPath, forbidden+"/") {
					t.Errorf("command production file %s prematurely imports L8 live package %q", filepath.ToSlash(path), importPath)
				}
			}
		}
		for _, marker := range []string{
			"NewLiveSecretSource",
			"NewJobCredentialRuntime",
			"NewCredentialProxy",
			"NewL8Firecracker",
			"l8composition.NewHelper",
			"l8composition.NewClient",
			"sshrelay.NewHelperExtension",
			"sshrelay.NewClientExtension",
			"guest-agent-v2",
		} {
			if strings.Contains(source, marker) {
				t.Errorf("command production file %s prematurely contains L8 live constructor marker %q", filepath.ToSlash(path), marker)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk command production files: %v", err)
	}
}

func TestL8CredentialDeliverySourceGuardsV1SchemasCannotCarryProductionIntent(t *testing.T) {
	checks := []struct {
		path    string
		schemas map[string][]string
	}{
		{
			path: filepath.Join("..", "internal", "sandboxruntime", "types.go"),
			schemas: map[string][]string{
				"RuntimeCredentialDeliveryMetadata": {
					`ID|string|json:"id,omitempty"`,
					`RequestID|string|json:"requestId,omitempty"`,
					`PlanID|string|json:"planId,omitempty"`,
					`ActivationID|string|json:"activationId,omitempty"`,
					`RequestedModes|[]string|json:"requestedModes,omitempty"`,
					`ActiveModes|[]string|json:"activeModes,omitempty"`,
					`ActiveProofs|[]RuntimeCredentialDeliveryProofSummary|json:"activeProofs,omitempty"`,
					`Status|string|json:"status,omitempty"`,
					`ReasonCode|string|json:"reasonCode,omitempty"`,
					`WarningCount|int|json:"warningCount,omitempty"`,
					`ErrorCount|int|json:"errorCount,omitempty"`,
				},
				"RuntimeCredentialDeliveryProofSummary": {
					`ProofID|string|json:"proofId"`,
					`BindingID|string|json:"bindingId,omitempty"`,
					`DeliveryMode|string|json:"deliveryMode"`,
					`Status|string|json:"status,omitempty"`,
					`Source|string|json:"source,omitempty"`,
				},
				"RuntimeGuestReadinessMetadata": {
					`State|RuntimeGuestReadinessState|json:"state,omitempty"`,
					`Transport|string|json:"transport,omitempty"`,
					`Labels|[]string|json:"labels,omitempty"`,
				},
				"RuntimeMetadata": {
					`Backend|string|json:"backend,omitempty"`,
					`CapabilityLabels|[]string|json:"capabilityLabels,omitempty"`,
					`PathRoles|[]string|json:"pathRoles,omitempty"`,
					`OperationPlan|*RuntimeOperationPlan|json:"operationPlan,omitempty"`,
					`ProcessLaunch|*RuntimeProcessLaunchMetadata|json:"processLaunch,omitempty"`,
					`GuestReadiness|*RuntimeGuestReadinessMetadata|json:"guestReadiness,omitempty"`,
					`NetworkEnforcement|*RuntimeNetworkEnforcementMetadata|json:"networkEnforcement,omitempty"`,
					`CredentialDelivery|*RuntimeCredentialDeliveryMetadata|json:"credentialDelivery,omitempty"`,
					`TemplateLock|*RuntimeTemplateLockMetadata|json:"templateLock,omitempty"`,
					`TemplateStatus|*RuntimeTemplateStatusMetadata|json:"templateStatus,omitempty"`,
				},
				"RuntimeNetworkEnforcementCapability": {
					`Supported|bool|json:"supported,omitempty"`,
					`Modes|[]string|json:"modes,omitempty"`,
					`SupportsDomainRules|bool|json:"supportsDomainRules,omitempty"`,
					`SupportsEndpointRules|bool|json:"supportsEndpointRules,omitempty"`,
					`SupportsPrivateRangeRules|bool|json:"supportsPrivateRangeRules,omitempty"`,
					`SupportsMetadataEndpoint|bool|json:"supportsMetadataEndpoint,omitempty"`,
					`SupportsLoopbackRules|bool|json:"supportsLoopbackRules,omitempty"`,
					`SupportsLinkLocalRules|bool|json:"supportsLinkLocalRules,omitempty"`,
					`SupportsDefaultDenyPosture|bool|json:"supportsDefaultDenyPosture,omitempty"`,
				},
				"RuntimeNetworkEnforcementLifecycleMetadata": {
					`ID|string|json:"id,omitempty"`,
					`PlanID|string|json:"planId,omitempty"`,
					`AdapterID|string|json:"adapterId,omitempty"`,
					`Status|string|json:"status,omitempty"`,
					`Mechanisms|[]string|json:"mechanisms,omitempty"`,
					`Operations|[]string|json:"operations,omitempty"`,
					`PolicySnapshotID|string|json:"policySnapshotId,omitempty"`,
					`PolicyPreset|string|json:"policyPreset,omitempty"`,
					`CapabilityLabels|[]string|json:"capabilityLabels,omitempty"`,
					`ReasonCode|string|json:"reasonCode,omitempty"`,
					`WarningCodes|[]string|json:"warningCodes,omitempty"`,
				},
				"RuntimeNetworkEnforcementMetadata": {
					`Plan|*RuntimeNetworkEnforcementPlanMetadata|json:"plan,omitempty"`,
					`Orchestration|*RuntimeNetworkEnforcementOrchestrationMetadata|json:"orchestration,omitempty"`,
					`Result|*RuntimeNetworkEnforcementResultMetadata|json:"result,omitempty"`,
				},
				"RuntimeNetworkEnforcementOrchestrationMetadata": {
					`PlanID|string|json:"planId,omitempty"`,
					`AdapterID|string|json:"adapterId,omitempty"`,
					`Status|string|json:"status,omitempty"`,
					`Mechanisms|[]string|json:"mechanisms,omitempty"`,
					`Operations|[]string|json:"operations,omitempty"`,
					`PolicySnapshotID|string|json:"policySnapshotId,omitempty"`,
					`PolicyPreset|string|json:"policyPreset,omitempty"`,
					`Proxy|*RuntimeNetworkEnforcementLifecycleMetadata|json:"proxy,omitempty"`,
					`Rules|[]RuntimeNetworkEnforcementLifecycleMetadata|json:"rules,omitempty"`,
					`CapabilityLabels|[]string|json:"capabilityLabels,omitempty"`,
					`ReasonCode|string|json:"reasonCode,omitempty"`,
					`WarningCodes|[]string|json:"warningCodes,omitempty"`,
				},
				"RuntimeNetworkEnforcementPlanMetadata": {
					`ID|string|json:"id,omitempty"`,
					`Source|string|json:"source,omitempty"`,
					`Operation|string|json:"operation,omitempty"`,
					`PolicySnapshotID|string|json:"policySnapshotId,omitempty"`,
					`PolicyPreset|string|json:"policyPreset,omitempty"`,
					`DefaultPosture|string|json:"defaultPosture,omitempty"`,
					`Mechanisms|[]string|json:"mechanisms,omitempty"`,
					`Operations|[]string|json:"operations,omitempty"`,
				},
				"RuntimeNetworkEnforcementResultMetadata": {
					`PlanID|string|json:"planId,omitempty"`,
					`AdapterID|string|json:"adapterId,omitempty"`,
					`Outcome|string|json:"outcome,omitempty"`,
					`EnforcementMode|string|json:"enforcementMode,omitempty"`,
					`Mechanisms|[]string|json:"mechanisms,omitempty"`,
					`Operations|[]string|json:"operations,omitempty"`,
					`PolicySnapshotID|string|json:"policySnapshotId,omitempty"`,
					`PolicyPreset|string|json:"policyPreset,omitempty"`,
					`Capability|*RuntimeNetworkEnforcementCapability|json:"capability,omitempty"`,
					`ReasonCode|string|json:"reasonCode,omitempty"`,
					`WarningCodes|[]string|json:"warningCodes,omitempty"`,
				},
				"RuntimeOperationArgument": {
					`Value|string|json:"value,omitempty"`,
					`PathRole|string|json:"pathRole,omitempty"`,
				},
				"RuntimeOperationEnvironment": {
					`Name|string|json:"name,omitempty"`,
					`Source|string|json:"source,omitempty"`,
				},
				"RuntimeOperationPayload": {
					`Role|string|json:"role,omitempty"`,
					`APIPath|string|json:"apiPath,omitempty"`,
					`Assets|[]RuntimeOperationPayloadAsset|json:"assets,omitempty"`,
				},
				"RuntimeOperationPayloadAsset": {
					`AssetRole|string|json:"assetRole,omitempty"`,
					`ID|string|json:"id,omitempty"`,
					`Labels|[]string|json:"labels,omitempty"`,
					`Digest|*RuntimeOperationPayloadDigest|json:"digest,omitempty"`,
				},
				"RuntimeOperationPayloadDigest": {
					`Algorithm|string|json:"algorithm,omitempty"`,
					`Value|string|json:"value,omitempty"`,
				},
				"RuntimeOperationPlan": {
					`Action|string|json:"action,omitempty"`,
					`Environment|[]RuntimeOperationEnvironment|json:"environment,omitempty"`,
					`PathRoles|[]string|json:"pathRoles,omitempty"`,
					`Payloads|[]RuntimeOperationPayload|json:"payloads,omitempty"`,
					`ProcessDescriptor|*RuntimeProcessDescriptor|json:"processDescriptor,omitempty"`,
				},
				"RuntimeProcessDescriptor": {
					`Action|string|json:"action,omitempty"`,
					`ExecutableRole|string|json:"executableRole,omitempty"`,
					`Argv|[]RuntimeOperationArgument|json:"argv"`,
					`Environment|[]RuntimeOperationEnvironment|json:"environment"`,
					`PathRoles|[]string|json:"pathRoles"`,
					`Payloads|[]RuntimeOperationPayload|json:"payloads"`,
				},
				"RuntimeProcessLaunchMetadata": {
					`State|string|json:"state,omitempty"`,
					`Labels|[]string|json:"labels,omitempty"`,
					`ProcessID|string|json:"processId,omitempty"`,
					`ProcessIDSource|string|json:"processIdSource,omitempty"`,
				},
				"RuntimeTemplateStatusMetadata": {
					`LockStatus|string|json:"lockStatus,omitempty"`,
					`TrustMode|string|json:"trustMode,omitempty"`,
					`TrustDecision|string|json:"trustDecision,omitempty"`,
					`ProvenanceLabels|[]string|json:"provenanceLabels,omitempty"`,
					`ReasonCodes|[]string|json:"reasonCodes,omitempty"`,
				},
			},
		},
		{
			path: filepath.Join("..", "internal", "sandboxruntime", "template_lock.go"),
			schemas: map[string][]string{
				"RuntimeTemplateLockEntryMetadata": {
					`SourceKind|string|json:"sourceKind,omitempty"`,
					`ReferenceKind|string|json:"referenceKind,omitempty"`,
					`Status|string|json:"status,omitempty"`,
					`DigestAlgorithm|string|json:"digestAlgorithm,omitempty"`,
					`DigestValue|string|json:"digestValue,omitempty"`,
					`SizeBytes|int64|json:"sizeBytes,omitempty"`,
					`LockedAt|string|json:"lockedAt,omitempty"`,
					`WarningCodes|[]string|json:"warningCodes,omitempty"`,
					`ReasonCode|string|json:"reasonCode,omitempty"`,
				},
				"RuntimeTemplateLockMetadata": {
					`Document|*RuntimeTemplateLockEntryMetadata|json:"document,omitempty"`,
					`TemplateReference|*RuntimeTemplateLockEntryMetadata|json:"templateReference,omitempty"`,
					`RuntimeImage|*RuntimeTemplateLockEntryMetadata|json:"runtimeImage,omitempty"`,
					`SourceArtifact|*RuntimeTemplateLockEntryMetadata|json:"sourceArtifact,omitempty"`,
					`TrustPolicy|*RuntimeTemplateTrustPolicyMetadata|json:"trustPolicy,omitempty"`,
				},
				"RuntimeTemplateTrustPolicyMetadata": {
					`Mode|string|json:"mode,omitempty"`,
					`Decision|string|json:"decision,omitempty"`,
					`SourceKind|string|json:"sourceKind,omitempty"`,
					`ReferenceKind|string|json:"referenceKind,omitempty"`,
					`Status|string|json:"status,omitempty"`,
					`DigestAlgorithm|string|json:"digestAlgorithm,omitempty"`,
					`DigestValue|string|json:"digestValue,omitempty"`,
					`WarningCodes|[]string|json:"warningCodes,omitempty"`,
					`ErrorCodes|[]string|json:"errorCodes,omitempty"`,
					`ReasonCodes|[]string|json:"reasonCodes,omitempty"`,
				},
			},
		},
		{
			path: filepath.Join("..", "internal", "sandboxworker", "types.go"),
			schemas: map[string][]string{
				"Capabilities": {
					`ProtocolVersion|string|json:"protocolVersion,omitempty"`,
					`WorkerID|string|json:"workerId"`,
					`SupportedOperations|[]string|json:"supportedOperations,omitempty"`,
					`RuntimeDrivers|[]RuntimeDriver|json:"runtimeDrivers,omitempty"`,
					`Security|SecurityPolicy|json:"security"`,
					`Metadata|*sandboxruntime.RuntimeMetadata|json:"metadata,omitempty"`,
				},
				"CreateRequest": {
					`Name|string|json:"name"`,
					`Image|string|json:"image,omitempty"`,
					`Env|map[string]string|json:"env,omitempty"`,
					`Security|SecurityPolicy|json:"security,omitempty"`,
				},
				"Error": {
					`Code|string|json:"code"`,
					`Message|string|json:"message"`,
				},
				"InspectRequest": {
					`Target|Target|json:"target"`,
				},
				"LifecycleRequest": {
					`Target|Target|json:"target"`,
				},
				"Request": {
					`ProtocolVersion|string|json:"protocolVersion,omitempty"`,
					`RequestID|string|json:"requestId,omitempty"`,
					`Operation|string|json:"operation"`,
					`DriverID|string|json:"driverId,omitempty"`,
					`Target|*Target|json:"target,omitempty"`,
					`Create|*CreateRequest|json:"create,omitempty"`,
					`Lifecycle|*LifecycleRequest|json:"lifecycle,omitempty"`,
					`Inspect|*InspectRequest|json:"inspect,omitempty"`,
					`Exec|*ExecRequest|json:"exec,omitempty"`,
					`CopyIn|*CopyInRequest|json:"copyIn,omitempty"`,
					`CopyOut|*CopyOutRequest|json:"copyOut,omitempty"`,
					`JobStart|*JobStartRequest|json:"jobStart,omitempty"`,
					`JobResolve|*JobResolveRequest|json:"jobResolve,omitempty"`,
					`JobStatus|*JobStatusRequest|json:"jobStatus,omitempty"`,
					`JobLogs|*JobLogsRequest|json:"jobLogs,omitempty"`,
					`JobCancel|*JobCancelRequest|json:"jobCancel,omitempty"`,
					`JobStartV2|*JobStartRequestV2|json:"jobStartV2,omitempty"`,
					`JobResolveV2|*JobResolveRequestV2|json:"jobResolveV2,omitempty"`,
					`JobStatusV2|*JobStatusRequestV2|json:"jobStatusV2,omitempty"`,
					`JobLogsV2|*JobLogsRequestV2|json:"jobLogsV2,omitempty"`,
					`JobCancelV2|*JobCancelRequestV2|json:"jobCancelV2,omitempty"`,
				},
				"Response": {
					`ProtocolVersion|string|json:"protocolVersion,omitempty"`,
					`RequestID|string|json:"requestId,omitempty"`,
					`Operation|string|json:"operation"`,
					`OK|bool|json:"ok"`,
					`Status|*Status|json:"status,omitempty"`,
					`Capabilities|*Capabilities|json:"capabilities,omitempty"`,
					`Target|*Target|json:"target,omitempty"`,
					`Exec|*ExecResponse|json:"exec,omitempty"`,
					`CopyIn|*CopyInResponse|json:"copyIn,omitempty"`,
					`CopyOut|*CopyOutResponse|json:"copyOut,omitempty"`,
					`Job|*Job|json:"job,omitempty"`,
					`JobLogs|*JobLogsResponse|json:"jobLogs,omitempty"`,
					`Error|*Error|json:"error,omitempty"`,
					`JobV2|*JobV2|json:"jobV2,omitempty"`,
					`JobLogsV2|*JobLogsResponseV2|json:"jobLogsV2,omitempty"`,
				},
				"RuntimeDriver": {
					`ID|string|json:"id"`,
					`HostKind|string|json:"hostKind"`,
					`IsolationLevel|string|json:"isolationLevel"`,
					`Operations|[]string|json:"operations,omitempty"`,
					`Security|SecurityPolicy|json:"security"`,
					`NetworkEnforcement|*sandboxruntime.RuntimeNetworkEnforcementMetadata|json:"networkEnforcement,omitempty"`,
					`Metadata|*sandboxruntime.RuntimeMetadata|json:"metadata,omitempty"`,
				},
				"RuntimeTarget": {
					`Driver|string|json:"driver"`,
					`RuntimeID|string|json:"runtimeId,omitempty"`,
					`Image|string|json:"image,omitempty"`,
					`WorkerID|string|json:"workerId,omitempty"`,
					`IsolationLevel|string|json:"isolationLevel,omitempty"`,
					`Metadata|*sandboxruntime.RuntimeMetadata|json:"metadata,omitempty"`,
				},
				"SecurityControls": {
					`NetworkPolicy|string|json:"networkPolicy,omitempty"`,
					`NetworkEnforcement|string|json:"networkEnforcement,omitempty"`,
					`NetworkEnforcementCapability|*sandboxruntime.RuntimeNetworkEnforcementCapability|json:"networkEnforcementCapability,omitempty"`,
					`CredentialModes|[]string|json:"credentialModes,omitempty"`,
					`CredentialDelivery|*sandboxruntime.RuntimeCredentialDeliveryMetadata|json:"credentialDelivery,omitempty"`,
					`IsolationLevel|string|json:"isolationLevel,omitempty"`,
					`CredentialProxyMode|bool|json:"credentialProxyMode,omitempty"`,
				},
				"SecurityPolicy": {
					`Requested|SecurityControls|json:"requested"`,
					`Enforced|SecurityControls|json:"enforced"`,
					`NetworkEnforcement|*sandboxruntime.RuntimeNetworkEnforcementMetadata|json:"networkEnforcement,omitempty"`,
				},
				"Status": {
					`ProtocolVersion|string|json:"protocolVersion,omitempty"`,
					`WorkerID|string|json:"workerId"`,
					`HostKind|string|json:"hostKind"`,
					`SocketPath|string|json:"socketPath,omitempty"`,
					`SupportedRuntimeDrivers|[]string|json:"supportedRuntimeDrivers,omitempty"`,
					`Health|WorkerHealth|json:"health"`,
					`Capacity|WorkerCapacity|json:"capacity"`,
					`Security|SecurityPolicy|json:"security"`,
					`Metadata|*sandboxruntime.RuntimeMetadata|json:"metadata,omitempty"`,
				},
				"Target": {
					`ID|string|json:"id,omitempty"`,
					`Name|string|json:"name"`,
					`Status|string|json:"status,omitempty"`,
					`Runtime|RuntimeTarget|json:"runtime"`,
					`Labels|map[string]string|json:"labels,omitempty"`,
				},
				"WorkerCapacity": {
					`MaxConcurrentSandboxes|int|json:"maxConcurrentSandboxes"`,
					`ActiveSandboxes|int|json:"activeSandboxes"`,
				},
				"WorkerHealth": {
					`Status|string|json:"status"`,
					`Message|string|json:"message,omitempty"`,
				},
			},
		},
		{
			path: filepath.Join("..", "internal", "sandboxworker", "exec.go"),
			schemas: map[string][]string{
				"ExecOutputPayload": {
					`Data|string|json:"data"`,
					`SizeBytes|int64|json:"sizeBytes"`,
					`LimitBytes|int64|json:"limitBytes"`,
					`Truncated|bool|json:"truncated"`,
				},
				"ExecRequest": {
					`OperationID|string|json:"operationId"`,
					`Target|Target|json:"target"`,
					`Args|[]string|json:"args"`,
					`Env|map[string]string|json:"env,omitempty"`,
					`WorkDir|string|json:"workDir,omitempty"`,
					`Stdin|*ExecStdinPayload|json:"stdin,omitempty"`,
					`StdoutLimitBytes|int64|json:"stdoutLimitBytes"`,
					`StderrLimitBytes|int64|json:"stderrLimitBytes"`,
				},
				"ExecResponse": {
					`ExitCode|int|json:"exitCode"`,
					`Stdout|ExecOutputPayload|json:"stdout"`,
					`Stderr|ExecOutputPayload|json:"stderr"`,
					`Error|*Error|json:"error,omitempty"`,
				},
				"ExecStdinPayload": {
					`Data|string|json:"data"`,
					`Encoding|string|json:"encoding"`,
					`SizeBytes|int64|json:"sizeBytes"`,
					`LimitBytes|int64|json:"limitBytes"`,
				},
			},
		},
		{
			path: filepath.Join("..", "internal", "sandboxworker", "copy.go"),
			schemas: map[string][]string{
				"CopyFilePayload": {
					`Data|string|json:"data"`,
					`Encoding|string|json:"encoding"`,
					`SizeBytes|int64|json:"sizeBytes"`,
					`LimitBytes|int64|json:"limitBytes"`,
				},
				"CopyInRequest": {
					`OperationID|string|json:"operationId"`,
					`Target|Target|json:"target"`,
					`Source|CopyPathMetadata|json:"source"`,
					`RemoteDestinationPath|string|json:"remoteDestinationPath"`,
					`Payload|CopyFilePayload|json:"payload"`,
				},
				"CopyInResponse": {
					`Status|string|json:"status"`,
					`Error|*Error|json:"error,omitempty"`,
				},
				"CopyOutRequest": {
					`OperationID|string|json:"operationId"`,
					`Target|Target|json:"target"`,
					`RemoteSourcePath|string|json:"remoteSourcePath"`,
					`Destination|CopyPathMetadata|json:"destination"`,
					`MaxPayloadBytes|int64|json:"maxPayloadBytes"`,
				},
				"CopyOutResponse": {
					`Payload|*CopyFilePayload|json:"payload,omitempty"`,
					`Truncated|bool|json:"truncated"`,
					`LimitExceeded|bool|json:"limitExceeded"`,
					`Error|*Error|json:"error,omitempty"`,
				},
				"CopyPathMetadata": {
					`DisplayPath|string|json:"displayPath"`,
				},
			},
		},
		{
			path: filepath.Join("..", "internal", "sandboxworker", "job_types.go"),
			schemas: map[string][]string{
				"Job": {
					`ContractVersion|string|json:"contractVersion"`,
					`ID|string|json:"jobId"`,
					`SubmissionKey|string|json:"submissionKey,omitempty"`,
					`WorkerID|string|json:"workerId"`,
					`HostID|string|json:"hostId,omitempty"`,
					`RuntimeDriver|string|json:"runtimeDriver"`,
					`RuntimeID|string|json:"runtimeId,omitempty"`,
					`State|string|json:"state"`,
					`SubmittedAt|time.Time|json:"submittedAt"`,
					`StartedAt|*time.Time|json:"startedAt,omitempty"`,
					`HeartbeatAt|*time.Time|json:"heartbeatAt,omitempty"`,
					`FinishedAt|*time.Time|json:"finishedAt,omitempty"`,
					`LogCursor|uint64|json:"logCursor"`,
					`LogTruncated|bool|json:"logTruncated,omitempty"`,
					`StdoutTruncated|bool|json:"stdoutTruncated,omitempty"`,
					`StderrTruncated|bool|json:"stderrTruncated,omitempty"`,
					`ExitCode|*int|json:"exitCode,omitempty"`,
					`FailureCode|string|json:"failureCode,omitempty"`,
					`CancelRequested|bool|json:"cancelRequested,omitempty"`,
					`requestKey|string|`,
				},
				"JobStartRequest": {
					`ContractVersion|string|json:"contractVersion"`,
					`SubmissionID|string|json:"submissionId"`,
					`Exec|ExecRequest|json:"exec"`,
				},
				"JobResolveRequest": {
					`ContractVersion|string|json:"contractVersion"`,
					`SubmissionID|string|json:"submissionId"`,
				},
				"JobStatusRequest": {
					`ContractVersion|string|json:"contractVersion"`,
					`JobID|string|json:"jobId"`,
				},
				"JobLogsRequest": {
					`ContractVersion|string|json:"contractVersion"`,
					`JobID|string|json:"jobId"`,
					`Cursor|uint64|json:"cursor"`,
					`LimitBytes|int64|json:"limitBytes"`,
				},
				"JobCancelRequest": {
					`ContractVersion|string|json:"contractVersion"`,
					`JobID|string|json:"jobId"`,
				},
				"JobLogRecord": {
					`Cursor|uint64|json:"cursor"`,
					`Stream|string|json:"stream"`,
					`Data|string|json:"data"`,
					`Timestamp|time.Time|json:"timestamp"`,
				},
				"JobLogsResponse": {
					`ContractVersion|string|json:"contractVersion"`,
					`JobID|string|json:"jobId"`,
					`Records|[]JobLogRecord|json:"records,omitempty"`,
					`NextCursor|uint64|json:"nextCursor"`,
					`OldestCursor|uint64|json:"oldestCursor,omitempty"`,
					`Truncated|bool|json:"truncated,omitempty"`,
				},
			},
		},
		{
			path: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "contracts.go"),
			schemas: map[string][]string{
				"EnvironmentEntry": {
					`Name|string|json:"name"`,
					`Source|EnvironmentSource|json:"source,omitempty"`,
				},
				"IsolationProof": {
					`Generation|string|json:"generation"`,
					`RuntimeGeneration|string|json:"runtimeGeneration,omitempty"`,
					`Status|IsolationProofStatus|json:"status"`,
					`RestrictedIdentity|bool|json:"restrictedIdentity,omitempty"`,
					`CapabilitiesCleared|bool|json:"capabilitiesCleared,omitempty"`,
					`NoNewPrivileges|bool|json:"noNewPrivileges,omitempty"`,
					`SupplementaryGroupsCleared|bool|json:"supplementaryGroupsCleared,omitempty"`,
					`RawPacketSocketDenied|bool|json:"rawPacketSocketDenied,omitempty"`,
					`Network|*NetworkIsolationProof|json:"network,omitempty"`,
				},
				"IsolationProofRequest": {
					`Generation|string|json:"generation"`,
					`RuntimeGeneration|string|json:"runtimeGeneration,omitempty"`,
					`RequireNetworkProof|bool|json:"requireNetworkProof,omitempty"`,
				},
				"NetworkIsolationProof": {
					`Status|IsolationProofStatus|json:"status"`,
					`SingleInterface|bool|json:"singleInterface,omitempty"`,
					`StaticRoutes|bool|json:"staticRoutes,omitempty"`,
					`ProxyReachable|bool|json:"proxyReachable,omitempty"`,
				},
				"PayloadMetadata": {
					`SizeBytes|int64|json:"sizeBytes,omitempty"`,
					`MaxBytes|int64|json:"maxBytes,omitempty"`,
					`Digest|string|json:"digest,omitempty"`,
					`Encoding|PayloadEncoding|json:"encoding,omitempty"`,
					`Data|string|json:"data,omitempty"`,
				},
				"ReadinessRequest": {
					`ProtocolVersion|ProtocolVersion|json:"protocolVersion"`,
					`Operation|Operation|json:"operation"`,
					`Timing|*TimingMetadata|json:"timing,omitempty"`,
					`IsolationProof|*IsolationProofRequest|json:"isolationProof,omitempty"`,
				},
				"ReadinessResponse": {
					`ProtocolVersion|ProtocolVersion|json:"protocolVersion"`,
					`Operation|Operation|json:"operation"`,
					`Ready|bool|json:"ready"`,
					`Status|ReadinessStatus|json:"status,omitempty"`,
					`Error|*ProtocolError|json:"error,omitempty"`,
					`IsolationProof|*IsolationProof|json:"isolationProof,omitempty"`,
				},
				"StreamMetadata": {
					`SizeBytes|int64|json:"sizeBytes,omitempty"`,
					`MaxBytes|int64|json:"maxBytes,omitempty"`,
					`Truncated|bool|json:"truncated,omitempty"`,
					`Data|string|json:"data,omitempty"`,
					`Encoding|PayloadEncoding|json:"encoding,omitempty"`,
				},
				"TimingMetadata": {
					`TimeoutMillis|int64|json:"timeoutMillis,omitempty"`,
					`DeadlineUnixMillis|int64|json:"deadlineUnixMillis,omitempty"`,
				},
				"ErrorResponse": {
					`ProtocolVersion|ProtocolVersion|json:"protocolVersion"`,
					`Operation|Operation|json:"operation,omitempty"`,
					`Error|*ProtocolError|json:"error"`,
				},
				"ExecRequest": {
					`ProtocolVersion|ProtocolVersion|json:"protocolVersion"`,
					`Operation|Operation|json:"operation"`,
					`Args|[]string|json:"args"`,
					`Env|[]EnvironmentEntry|json:"env,omitempty"`,
					`WorkDir|string|json:"workDir"`,
					`Stdin|*StreamMetadata|json:"stdin,omitempty"`,
					`Stdout|StreamMetadata|json:"stdout"`,
					`Stderr|StreamMetadata|json:"stderr"`,
					`Timing|*TimingMetadata|json:"timing,omitempty"`,
				},
				"ExecResponse": {
					`ProtocolVersion|ProtocolVersion|json:"protocolVersion"`,
					`Operation|Operation|json:"operation"`,
					`ExitCode|int|json:"exitCode"`,
					`Stdout|StreamMetadata|json:"stdout"`,
					`Stderr|StreamMetadata|json:"stderr"`,
					`Error|*ProtocolError|json:"error,omitempty"`,
				},
				"CopyInRequest": {
					`ProtocolVersion|ProtocolVersion|json:"protocolVersion"`,
					`Operation|Operation|json:"operation"`,
					`DestinationPath|string|json:"destinationPath"`,
					`Payload|PayloadMetadata|json:"payload"`,
					`Timing|*TimingMetadata|json:"timing,omitempty"`,
				},
				"CopyInResponse": {
					`ProtocolVersion|ProtocolVersion|json:"protocolVersion"`,
					`Operation|Operation|json:"operation"`,
					`Written|PayloadMetadata|json:"written"`,
					`Error|*ProtocolError|json:"error,omitempty"`,
				},
				"CopyOutRequest": {
					`ProtocolVersion|ProtocolVersion|json:"protocolVersion"`,
					`Operation|Operation|json:"operation"`,
					`SourcePath|string|json:"sourcePath"`,
					`Payload|PayloadMetadata|json:"payload"`,
					`Timing|*TimingMetadata|json:"timing,omitempty"`,
				},
				"CopyOutResponse": {
					`ProtocolVersion|ProtocolVersion|json:"protocolVersion"`,
					`Operation|Operation|json:"operation"`,
					`Payload|PayloadMetadata|json:"payload"`,
					`Error|*ProtocolError|json:"error,omitempty"`,
				},
			},
		},
		{
			path: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "errors.go"),
			schemas: map[string][]string{
				"ProtocolError": {
					`Code|ErrorCode|json:"code"`,
					`Operation|Operation|json:"operation,omitempty"`,
					`Field|string|json:"field,omitempty"`,
					`Message|string|json:"message,omitempty"`,
					`Err|error|json:"-"`,
				},
			},
		},
	}

	for _, check := range checks {
		fileSet := token.NewFileSet()
		parsed, err := parser.ParseFile(fileSet, check.path, nil, 0)
		if err != nil {
			t.Fatalf("parse v1 schema %s: %v", filepath.ToSlash(check.path), err)
		}
		wanted := make(map[string]bool, len(check.schemas))
		for name := range check.schemas {
			wanted[name] = true
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			typeSpec, ok := node.(*ast.TypeSpec)
			if !ok || !wanted[typeSpec.Name.Name] {
				return true
			}
			wanted[typeSpec.Name.Name] = false
			structure, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				t.Fatalf("v1 schema %s in %s is not a struct", typeSpec.Name.Name, filepath.ToSlash(check.path))
			}
			got := l8V1StructSchema(t, fileSet, structure)
			want := check.schemas[typeSpec.Name.Name]
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Fatalf("v1 schema %s in %s changed\ngot:  %q\nwant: %q", typeSpec.Name.Name, filepath.ToSlash(check.path), got, want)
			}
			return false
		})
		for name, missing := range wanted {
			if missing {
				t.Fatalf("v1 schema guard did not find %s in %s", name, filepath.ToSlash(check.path))
			}
		}
	}
}

func l8V1StructSchema(t *testing.T, fileSet *token.FileSet, structure *ast.StructType) []string {
	t.Helper()
	fields := make([]string, 0, len(structure.Fields.List))
	for _, field := range structure.Fields.List {
		if len(field.Names) != 1 {
			t.Fatal("v1 schemas cannot contain grouped or embedded fields")
		}
		var typeSource bytes.Buffer
		if err := format.Node(&typeSource, fileSet, field.Type); err != nil {
			t.Fatalf("render v1 schema field type: %v", err)
		}
		tag := ""
		if field.Tag != nil {
			unquoted, err := strconv.Unquote(field.Tag.Value)
			if err != nil {
				t.Fatalf("unquote v1 schema field tag: %v", err)
			}
			tag = unquoted
		}
		fields = append(fields, field.Names[0].Name+"|"+typeSource.String()+"|"+tag)
	}
	return fields
}

func TestL8CredentialDeliverySourceGuardsV1NamedWireTypesCannotCarryProductionIntent(t *testing.T) {
	checks := []struct {
		path  string
		types map[string]string
	}{
		{
			path: filepath.Join("..", "internal", "sandboxruntime", "guest_readiness.go"),
			types: map[string]string{
				"RuntimeGuestReadinessState": "string",
			},
		},
		{
			path: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "contracts.go"),
			types: map[string]string{
				"EnvironmentSource":    "string",
				"ErrorCode":            "string",
				"IsolationProofStatus": "string",
				"Operation":            "string",
				"PayloadEncoding":      "string",
				"ProtocolVersion":      "string",
				"ReadinessStatus":      "string",
			},
		},
	}

	for _, check := range checks {
		fileSet := token.NewFileSet()
		parsed, err := parser.ParseFile(fileSet, check.path, nil, 0)
		if err != nil {
			t.Fatalf("parse v1 named wire types %s: %v", filepath.ToSlash(check.path), err)
		}
		found := make(map[string]bool, len(check.types))
		for _, declaration := range parsed.Decls {
			generic, ok := declaration.(*ast.GenDecl)
			if !ok || generic.Tok != token.TYPE {
				continue
			}
			for _, spec := range generic.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				want, locked := check.types[typeSpec.Name.Name]
				if !locked {
					continue
				}
				var rendered bytes.Buffer
				if err := format.Node(&rendered, fileSet, typeSpec.Type); err != nil {
					t.Fatalf("render v1 named wire type %s: %v", typeSpec.Name.Name, err)
				}
				if got := rendered.String(); got != want {
					t.Fatalf("v1 named wire type %s in %s changed: got %q, want %q", typeSpec.Name.Name, filepath.ToSlash(check.path), got, want)
				}
				found[typeSpec.Name.Name] = true
			}
		}
		for name := range check.types {
			if !found[name] {
				t.Fatalf("v1 named wire type guard did not find %s in %s", name, filepath.ToSlash(check.path))
			}
		}
	}
}

func TestL8CredentialDeliverySourceGuardsV1CustomJSONMethodsCannotCarryProductionIntent(t *testing.T) {
	// Hash the go/format AST for the pre-L8 sanitizing marshalers. Locking
	// only struct fields would still let later JSON or encoding.TextMarshaler
	// methods emit hidden production intent without changing a field, type, or
	// JSON tag.
	checks := []struct {
		root   string
		locked map[string]bool
		want   map[string]string
	}{
		{
			root: filepath.Join("..", "internal", "sandboxruntime"),
			locked: l8LockedV1TypeNames(
				"RuntimeCredentialDeliveryMetadata", "RuntimeCredentialDeliveryProofSummary",
				"RuntimeGuestReadinessMetadata", "RuntimeGuestReadinessState", "RuntimeMetadata", "RuntimeNetworkEnforcementCapability",
				"RuntimeNetworkEnforcementLifecycleMetadata", "RuntimeNetworkEnforcementMetadata",
				"RuntimeNetworkEnforcementOrchestrationMetadata", "RuntimeNetworkEnforcementPlanMetadata",
				"RuntimeNetworkEnforcementResultMetadata", "RuntimeOperationArgument",
				"RuntimeOperationEnvironment", "RuntimeOperationPayload", "RuntimeOperationPayloadAsset",
				"RuntimeOperationPayloadDigest", "RuntimeOperationPlan", "RuntimeProcessDescriptor",
				"RuntimeProcessLaunchMetadata", "RuntimeTemplateLockEntryMetadata",
				"RuntimeTemplateLockMetadata", "RuntimeTemplateStatusMetadata",
				"RuntimeTemplateTrustPolicyMetadata",
			),
			want: map[string]string{
				"RuntimeCredentialDeliveryMetadata.MarshalJSON":              "8f05764ea9c6cc8f8634998dfd379975a23735675bc970f79e82ac620c0168fd",
				"RuntimeCredentialDeliveryMetadata.UnmarshalJSON":            "d89a4e54ea98a7072ddf98163ca04149b63e0ebf19e52ff12e15d3b0fe2e9a32",
				"RuntimeMetadata.MarshalJSON":                                "2aea5101af541fd2fc6294218e15a730308cedf3aebecc7f3c001516c702aac7",
				"RuntimeMetadata.UnmarshalJSON":                              "9f94ef9f6e1a699dc22e89e8966cffb497d9a0bdf3fc66c4f61c349e12755298",
				"RuntimeNetworkEnforcementCapability.MarshalJSON":            "0c5fa7070f20ef28bc35831fe9d19cb8d9b00a587f719ba8a78bacdfcaaefe54",
				"RuntimeNetworkEnforcementLifecycleMetadata.MarshalJSON":     "a1813cbac961549d6aefc337e6202cf636d7ef0dd1ff7171e301fea9cf144814",
				"RuntimeNetworkEnforcementMetadata.MarshalJSON":              "0a81082a2000b70e6662a1b38eb4b64ec2c66b970e1ad0587b835912dc5bacbc",
				"RuntimeNetworkEnforcementOrchestrationMetadata.MarshalJSON": "4f3223639b2d455b385a684b679bdb8abef0a127f4d45e31e74faebd6c772079",
				"RuntimeNetworkEnforcementPlanMetadata.MarshalJSON":          "1893e8e01cef3e5400711c269d0ba2bb262617621c8cd4b09d3859e621ef3405",
				"RuntimeNetworkEnforcementResultMetadata.MarshalJSON":        "03fbda3657b0e30947f3f8cb7932caec3e0a695cca34881bf962f8ff549e359a",
				"RuntimeTemplateLockMetadata.MarshalJSON":                    "614ace00fe1128008edab8f076c956996813264d4262ceeb720665ad19fff26d",
				"RuntimeTemplateLockMetadata.UnmarshalJSON":                  "5c426f9978b5bf0f25f47fc95ff0fb067774204c06c290f9bec4e5fcc9ec5df5",
				"RuntimeTemplateStatusMetadata.MarshalJSON":                  "bbd05f5550bd185ebef9c026e17fe763b37c68ddefe2304f8cc229bbb0df2698",
				"RuntimeTemplateStatusMetadata.UnmarshalJSON":                "3b2e5c4ad6b46766b86bfba2ab77855a0e284a2a70542755757a962e6ca7a09a",
			},
		},
		{
			root: filepath.Join("..", "internal", "sandboxworker"),
			locked: l8LockedV1TypeNames(
				"Capabilities", "CopyFilePayload", "CopyInRequest", "CopyInResponse",
				"CopyOutRequest", "CopyOutResponse", "CopyPathMetadata", "CreateRequest",
				"Error", "ExecOutputPayload", "ExecRequest", "ExecResponse", "ExecStdinPayload",
				"InspectRequest", "Job", "JobCancelRequest", "JobLogRecord", "JobLogsRequest",
				"JobLogsResponse", "JobResolveRequest", "JobStartRequest", "JobStatusRequest",
				"LifecycleRequest", "Request", "Response", "RuntimeDriver", "RuntimeTarget",
				"SecurityControls", "SecurityPolicy", "Status", "Target", "WorkerCapacity", "WorkerHealth",
			),
			want: map[string]string{
				"SecurityControls.MarshalJSON": "529c63c25e4c005ced4217d60c6626b7e564fdde7597bae2b7d1039b36492443",
				"SecurityPolicy.MarshalJSON":   "9ee8505ea508b183ffc91369b1a20341c0387cd55f575740eaf4e077ce478a82",
			},
		},
		{
			root: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent"),
			locked: l8LockedV1TypeNames(
				"CopyInRequest", "CopyInResponse", "CopyOutRequest", "CopyOutResponse",
				"EnvironmentEntry", "EnvironmentSource", "ErrorCode", "ErrorResponse", "ExecRequest",
				"ExecResponse", "IsolationProof", "IsolationProofRequest", "IsolationProofStatus",
				"NetworkIsolationProof", "Operation", "PayloadEncoding", "PayloadMetadata", "ProtocolError",
				"ProtocolVersion", "ReadinessRequest", "ReadinessResponse", "ReadinessStatus",
				"StreamMetadata", "TimingMetadata",
			),
			want: map[string]string{
				"ProtocolError.MarshalJSON": "7037ea101057d523716bdbdc5ab246cb74250a2d27cfd170b32e375a6ac35ca9",
			},
		},
	}

	for _, check := range checks {
		got := make(map[string]string)
		err := filepath.WalkDir(check.root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if path != check.root && entry.IsDir() {
				return filepath.SkipDir
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fileSet := token.NewFileSet()
			parsed, err := parser.ParseFile(fileSet, path, nil, 0)
			if err != nil {
				return err
			}
			for _, declaration := range parsed.Decls {
				method, ok := declaration.(*ast.FuncDecl)
				if !ok || method.Recv == nil || !l8V1CustomSerializationMethod(method.Name.Name) {
					continue
				}
				receiver := l8V1ReceiverName(method)
				if !check.locked[receiver] {
					continue
				}
				var rendered bytes.Buffer
				if err := format.Node(&rendered, fileSet, method); err != nil {
					return err
				}
				digest := sha256.Sum256(rendered.Bytes())
				got[receiver+"."+method.Name.Name] = fmt.Sprintf("%x", digest)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan v1 custom JSON methods in %s: %v", filepath.ToSlash(check.root), err)
		}
		if len(got) != len(check.want) {
			t.Fatalf("v1 custom JSON method count in %s changed: got %v, want %v", filepath.ToSlash(check.root), got, check.want)
		}
		for method, wantDigest := range check.want {
			if gotDigest := got[method]; gotDigest != wantDigest {
				t.Fatalf("v1 custom JSON method %s in %s changed: got %q, want %q", method, filepath.ToSlash(check.root), gotDigest, wantDigest)
			}
		}
	}
}

func l8V1CustomSerializationMethod(name string) bool {
	switch name {
	case "MarshalJSON", "UnmarshalJSON", "MarshalText", "UnmarshalText":
		return true
	default:
		return false
	}
}

func l8LockedV1TypeNames(names ...string) map[string]bool {
	locked := make(map[string]bool, len(names))
	for _, name := range names {
		locked[name] = true
	}
	return locked
}

func l8V1ReceiverName(method *ast.FuncDecl) string {
	if method == nil || method.Recv == nil || len(method.Recv.List) != 1 {
		return ""
	}
	typeExpression := method.Recv.List[0].Type
	if pointer, ok := typeExpression.(*ast.StarExpr); ok {
		typeExpression = pointer.X
	}
	identifier, _ := typeExpression.(*ast.Ident)
	if identifier == nil {
		return ""
	}
	return identifier.Name
}

func TestL8CredentialDeliverySourceGuardsLiveMarkerIsolation(t *testing.T) {
	liveTag := "l8_production_" + "credential_" + "delivery_live"
	selectedLiveTests := map[string]bool{
		"TestL8PreparedLinuxCredentialDeliveryPrerequisites": true,
		"TestL8PreparedLinuxCredentialDeliveryE2E":           true,
	}
	for _, root := range []string{"cmd", "internal", "tools"} {
		err := filepath.WalkDir(filepath.Join("..", root), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			source, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			requireExactTag := strings.Contains(string(source), liveTag)
			parsed, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
			if err != nil {
				return err
			}
			for _, declaration := range parsed.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if ok && selectedLiveTests[function.Name.Name] {
					requireExactTag = true
				}
			}
			if !requireExactTag {
				return nil
			}
			rel, err := filepath.Rel("..", path)
			if err != nil {
				return err
			}
			if !strings.HasSuffix(path, "_live_test.go") {
				t.Errorf("%s contains the L8 live marker outside an isolated live test", filepath.ToSlash(rel))
				return nil
			}
			assertL8ExactLiveBuildConstraint(t, rel, source, liveTag)
			return nil
		})
		if err != nil {
			t.Fatalf("walk L8 live-marker scope %s: %v", root, err)
		}
	}
}

func assertL8ExactLiveBuildConstraint(t *testing.T, path string, source []byte, liveTag string) {
	t.Helper()
	if err := validateL8ExactLiveBuildConstraint(source, liveTag); err != nil {
		t.Errorf("%s build constraint: %v", filepath.ToSlash(path), err)
	}
}

func validateL8ExactLiveBuildConstraint(source []byte, liveTag string) error {
	var buildLines []string
	for _, line := range strings.Split(string(source), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//go:build") {
			buildLines = append(buildLines, trimmed)
		}
		if trimmed != "" && !strings.HasPrefix(trimmed, "//") {
			break
		}
	}
	if len(buildLines) != 1 {
		return fmt.Errorf("must contain exactly one L8 go:build constraint")
	}
	expr, err := constraint.Parse(buildLines[0])
	if err != nil {
		return fmt.Errorf("parse go:build constraint: %w", err)
	}
	tag, ok := expr.(*constraint.TagExpr)
	if !ok || tag.Tag != liveTag {
		return fmt.Errorf("must be exactly %s", liveTag)
	}
	return nil
}

func TestL8CredentialDeliverySourceGuardsBuildConstraintParserRejectsAlternates(t *testing.T) {
	liveTag := "l8_production_" + "credential_" + "delivery_live"
	for _, tt := range []struct {
		name    string
		source  string
		wantErr bool
	}{
		{name: "exact", source: "//go:build " + liveTag + "\n\npackage fixture\n"},
		{name: "or linux", source: "//go:build linux || " + liveTag + "\n\npackage fixture\n", wantErr: true},
		{name: "negated", source: "//go:build !" + liveTag + "\n\npackage fixture\n", wantErr: true},
		{name: "conjoined", source: "//go:build linux && " + liveTag + "\n\npackage fixture\n", wantErr: true},
		{name: "missing", source: "package fixture\n", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateL8ExactLiveBuildConstraint([]byte(tt.source), liveTag)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validate exact L8 constraint error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestL8CredentialDeliverySourceGuardsFixtureConstructorsStayInTests(t *testing.T) {
	for _, root := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join("..", root), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			source, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, spec := range parsed.Imports {
				importPath, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					return err
				}
				lower := strings.ToLower(importPath)
				if importPath == "testing" || importPath == "net/http/httptest" ||
					strings.Contains(lower, "/testfixture") ||
					strings.Contains(lower, "/testutil") ||
					strings.Contains(lower, "/testonly") {
					t.Errorf("production file %s imports test-only dependency %q", filepath.ToSlash(path), importPath)
				}
			}
			for _, marker := range []string{
				"NewL8Fixture",
				"newL8Fixture",
				"L8FixtureRegistry",
				"l8FixtureRegistry",
			} {
				if strings.Contains(string(source), marker) {
					t.Errorf("production file %s contains test-only L8 fixture marker %q", filepath.ToSlash(path), marker)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk L8 fixture scope %s: %v", root, err)
		}
	}
}

func TestL8CredentialDeliverySourceGuardsLifecycleTestSeamStaysUnexportedAndIsolated(t *testing.T) {
	for _, tt := range []struct {
		name   string
		source string
		want   bool
	}{
		{name: "exact named", source: "func NewJobCredentialLifecycle(identity JobCredentialIdentity) (*JobCredentialLifecycle, error) {}", want: true},
		{name: "exact unnamed", source: "func NewJobCredentialLifecycle(JobCredentialIdentity) (*JobCredentialLifecycle, error) {}", want: true},
		{name: "variadic identity", source: "func NewJobCredentialLifecycle(identity ...JobCredentialIdentity) (*JobCredentialLifecycle, error) {}"},
		{name: "options argument", source: "func NewJobCredentialLifecycle(identity JobCredentialIdentity, options any) (*JobCredentialLifecycle, error) {}"},
		{name: "callback argument", source: "func NewJobCredentialLifecycle(identity JobCredentialIdentity, hook func()) (*JobCredentialLifecycle, error) {}"},
		{name: "generic", source: "func NewJobCredentialLifecycle[T any](identity JobCredentialIdentity) (*JobCredentialLifecycle, error) {}"},
		{name: "method", source: "func (factory lifecycleFactory) NewJobCredentialLifecycle(identity JobCredentialIdentity) (*JobCredentialLifecycle, error) {}"},
		{name: "value lifecycle output", source: "func NewJobCredentialLifecycle(identity JobCredentialIdentity) (JobCredentialLifecycle, error) {}"},
		{name: "extra output", source: "func NewJobCredentialLifecycle(identity JobCredentialIdentity) (*JobCredentialLifecycle, error, bool) {}"},
		{name: "wrong error output", source: "func NewJobCredentialLifecycle(identity JobCredentialIdentity) (*JobCredentialLifecycle, string) {}"},
	} {
		t.Run("constructor signature "+tt.name, func(t *testing.T) {
			parsed, err := parser.ParseFile(token.NewFileSet(), "constructor.go", "package sandboxruntime\n"+tt.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			declaration, ok := parsed.Decls[0].(*ast.FuncDecl)
			if !ok {
				t.Fatal("constructor fixture is not a function")
			}
			if got := l8JobCredentialLifecycleConstructorHasExactSignature(declaration); got != tt.want {
				t.Fatalf("exact constructor signature = %t, want %t", got, tt.want)
			}
		})
	}

	exactSeamNames := map[string]bool{
		"jobCredentialLifecycleTransition":            true,
		"jobCredentialLifecycleOptions":               true,
		"newJobCredentialLifecycleWithOptions":        true,
		"jobCredentialLifecycleTransitionRenew":       true,
		"jobCredentialLifecycleTransitionRevoke":      true,
		"jobCredentialLifecycleTransitionObserveLoss": true,
		"jobCredentialLifecycleTransitionBeginRevoke": true,
	}
	seen := map[string]bool{}
	rootRuntimeDir := filepath.Clean(filepath.Join("..", "internal", "sandboxruntime"))
	for _, root := range []string{filepath.Join("..", "internal"), "."} {
		err := filepath.WalkDir(root, func(sourcePath string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(sourcePath, ".go") || strings.HasSuffix(sourcePath, "_test.go") {
				return nil
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), sourcePath, nil, 0)
			if err != nil {
				return err
			}
			inRootRuntime := filepath.Clean(filepath.Dir(sourcePath)) == rootRuntimeDir && parsed.Name.Name == "sandboxruntime"
			ast.Inspect(parsed, func(node ast.Node) bool {
				identifier, ok := node.(*ast.Ident)
				if !ok {
					return true
				}
				if exactSeamNames[identifier.Name] {
					if !inRootRuntime {
						t.Errorf("production file %s references isolated lifecycle test seam %s", filepath.ToSlash(sourcePath), identifier.Name)
					} else {
						seen[identifier.Name] = true
					}
					return true
				}
				lower := strings.ToLower(identifier.Name)
				if inRootRuntime && (strings.Contains(lower, "jobcredentiallifecycletransition") ||
					(strings.Contains(lower, "jobcredentiallifecycle") &&
						(strings.Contains(lower, "hook") || strings.Contains(lower, "option") || strings.Contains(lower, "test") || strings.Contains(lower, "beforecommit")))) {
					t.Errorf("production lifecycle adds unapproved test seam identifier %s in %s", identifier.Name, filepath.ToSlash(sourcePath))
				}
				return true
			})
			if !inRootRuntime {
				return nil
			}
			for _, declaration := range parsed.Decls {
				switch typed := declaration.(type) {
				case *ast.FuncDecl:
					if typed.Name.Name == "NewJobCredentialLifecycle" && !l8JobCredentialLifecycleConstructorHasExactSignature(typed) {
						t.Errorf("public lifecycle constructor in %s must remain exact func(JobCredentialIdentity) (*JobCredentialLifecycle, error)", filepath.ToSlash(sourcePath))
					}
					if typed.Name.Name == "newJobCredentialLifecycleWithOptions" && typed.Name.IsExported() {
						t.Errorf("lifecycle options constructor is exported in %s", filepath.ToSlash(sourcePath))
					}
				case *ast.GenDecl:
					for _, spec := range typed.Specs {
						typeSpec, ok := spec.(*ast.TypeSpec)
						if !ok || typeSpec.Name.Name != "jobCredentialLifecycleOptions" {
							continue
						}
						if typeSpec.Name.IsExported() {
							t.Errorf("lifecycle test options are exported in %s", filepath.ToSlash(sourcePath))
						}
						structure, ok := typeSpec.Type.(*ast.StructType)
						if !ok || len(structure.Fields.List) != 1 || len(structure.Fields.List[0].Names) != 1 || structure.Fields.List[0].Names[0].Name != "beforeCommit" {
							t.Errorf("lifecycle test options in %s must contain only unexported beforeCommit", filepath.ToSlash(sourcePath))
							continue
						}
						field := structure.Fields.List[0]
						functionType, ok := field.Type.(*ast.FuncType)
						if !ok || functionType.Params == nil || len(functionType.Params.List) != 1 || functionType.Results != nil {
							t.Errorf("lifecycle beforeCommit seam in %s must be a one-way transition callback", filepath.ToSlash(sourcePath))
							continue
						}
						parameter, ok := functionType.Params.List[0].Type.(*ast.Ident)
						if !ok || parameter.Name != "jobCredentialLifecycleTransition" || field.Names[0].IsExported() {
							t.Errorf("lifecycle beforeCommit seam in %s has an unapproved signature", filepath.ToSlash(sourcePath))
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk lifecycle test seam scope %s: %v", root, err)
		}
	}
	if len(seen) > 0 {
		for name := range exactSeamNames {
			if !seen[name] {
				t.Errorf("partial lifecycle test seam omits exact identifier %s", name)
			}
		}
	}
}

func l8JobCredentialLifecycleConstructorHasExactSignature(declaration *ast.FuncDecl) bool {
	if declaration.Recv != nil || declaration.Type.TypeParams != nil || declaration.Type.Params == nil || len(declaration.Type.Params.List) != 1 {
		return false
	}
	parameter := declaration.Type.Params.List[0]
	parameterType, ok := parameter.Type.(*ast.Ident)
	if !ok || parameterType.Name != "JobCredentialIdentity" || len(parameter.Names) > 1 {
		return false
	}
	if declaration.Type.Results == nil || len(declaration.Type.Results.List) != 2 {
		return false
	}
	lifecycleResult := declaration.Type.Results.List[0]
	pointer, ok := lifecycleResult.Type.(*ast.StarExpr)
	if !ok || len(lifecycleResult.Names) > 1 {
		return false
	}
	lifecycleType, ok := pointer.X.(*ast.Ident)
	if !ok || lifecycleType.Name != "JobCredentialLifecycle" {
		return false
	}
	errorResult := declaration.Type.Results.List[1]
	errorType, ok := errorResult.Type.(*ast.Ident)
	return ok && errorType.Name == "error" && len(errorResult.Names) <= 1
}

func TestL8CredentialDeliverySourceGuardsVerificationScriptsEnforcePresenceAndNoSkip(t *testing.T) {
	focusedPath := filepath.Join("..", "tools", "microvm", "l8", "verify-focused.sh")
	livePath := filepath.Join("..", "tools", "microvm", "l8", "verify-selected-live.sh")
	for _, path := range []string{focusedPath, livePath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat L8 verification script %s: %v", filepath.ToSlash(path), err)
		}
		if info.Mode().Perm()&0o111 == 0 {
			t.Fatalf("L8 verification script %s is not executable", filepath.ToSlash(path))
		}
	}

	focused := readL8CredentialDeliveryFile(t, focusedPath)
	for _, required := range []string{
		"go test -list '^TestL8'",
		"matched no named L8 test",
		"go test -count=1 -json -timeout=240s",
		"go test -race -count=1 -json -timeout=360s",
		"go test -count=25 -json -timeout=420s",
		`\"Action\":\"skip\"`,
		"L8 tests failed or skipped",
	} {
		if !strings.Contains(focused, required) {
			t.Errorf("L8 focused verifier omits %q", required)
		}
	}
	if got, want := strings.Count(focused, "./internal/sandboxruntime/networkenforcement/applicationroute"), 4; got != want {
		t.Errorf("L8 focused verifier applicationroute selector occurrences = %d, want %d (presence, focused, race, repeated)", got, want)
	}
	for _, section := range []string{"run_l8_no_skip race", "run_l8_no_skip repeated"} {
		start := strings.Index(focused, section)
		if start < 0 {
			t.Fatalf("L8 focused verifier omits %s section", section)
		}
		end := strings.Index(focused[start+len(section):], "run_l8_no_skip ")
		body := focused[start:]
		if end >= 0 {
			body = focused[start : start+len(section)+end]
		}
		if !strings.Contains(body, "./internal/sandboxruntime \\") {
			t.Errorf("L8 focused verifier %s section omits root lifecycle selector", section)
		}
	}

	live := readL8CredentialDeliveryFile(t, livePath)
	liveTag := "l8_production_" + "credential_" + "delivery_live"
	for _, required := range []string{
		"go test -list",
		"go test -json -race -count=1",
		`\"Action\":\"skip\"`,
		"selected L8 live test did not run and pass exactly once",
		"TestL8PreparedLinuxCredentialDeliveryPrerequisites",
		"TestL8PreparedLinuxCredentialDeliveryE2E",
		liveTag,
		"http_only file_tmpfs_only ssh_agent_only all_modes failure_recovery_matrix",
	} {
		if !strings.Contains(live, required) {
			t.Errorf("L8 selected-live verifier omits %q", required)
		}
	}
	for _, forbidden := range []string{"curl ", "wget ", "docker ", "podman ", "npm ", "t.Skip"} {
		if strings.Contains(focused, forbidden) || strings.Contains(live, forbidden) {
			t.Errorf("L8 verification script contains forbidden external/live marker %q", forbidden)
		}
	}
}

func l8CredentialMetadataFiles(t *testing.T) []string {
	t.Helper()
	var paths []string
	for _, pattern := range []string{
		filepath.Join("..", "internal", "credentialdelivery", "*.go"),
		filepath.Join("..", "internal", "sandbox", "credential_proxy*.go"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob L8 metadata files %s: %v", pattern, err)
		}
		for _, path := range matches {
			if !strings.HasSuffix(path, "_test.go") {
				paths = append(paths, path)
			}
		}
	}
	if len(paths) == 0 {
		t.Fatal("L8 metadata source guard matched no production files")
	}
	return paths
}
