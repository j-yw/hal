package cmd

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
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

func TestL8CredentialDeliverySourceGuardsV1CustomJSONMethodsCannotCarryProductionIntent(t *testing.T) {

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

func l8LockedV1TypeNames(names ...string) map[string]bool {
	locked := make(map[string]bool, len(names))
	for _, name := range names {
		locked[name] = true
	}
	return locked
}

func l8V1CustomSerializationMethod(name string) bool {
	switch name {
	case "MarshalJSON", "UnmarshalJSON", "MarshalText", "UnmarshalText":
		return true
	default:
		return false
	}
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

func readL8CredentialDeliveryFile(t *testing.T, path string) string {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}
