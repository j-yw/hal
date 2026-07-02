package cmd

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	rootlesspodman "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

var phase26CredentialProxyJSONFields = []string{
	"credentialProxy",
	"credentialProxyPlan",
	"credentialProxySession",
	"credentialProxyBindings",
}

func TestRunAndAutoSandboxManifestsOmitCredentialProxyMetadataByDefault(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 12, 20, 0, 0, time.UTC)

	runStore := sandboxexecution.NewStore(t.TempDir())
	if err := saveRunSandboxManifest(runStore, runSandboxRequest{
		ExecutionID: "run-no-credential-proxy-metadata",
		ProjectDir:  "/repo",
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}
	assertSandboxManifestOmitsCredentialProxyMetadata(t, mustLoadSandboxExecutionManifest(t, runStore, "run-no-credential-proxy-metadata"))

	autoStore := sandboxexecution.NewStore(t.TempDir())
	if err := saveAutoSandboxManifest(autoStore, autoSandboxRequest{
		ExecutionID: "auto-no-credential-proxy-metadata",
		ProjectDir:  "/repo",
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}
	assertSandboxManifestOmitsCredentialProxyMetadata(t, mustLoadSandboxExecutionManifest(t, autoStore, "auto-no-credential-proxy-metadata"))
}

func TestFactoryPersistenceOmitsCredentialProxyMetadataByDefault(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 12, 45, 0, 0, time.UTC)
	_, metadata := factorySandboxPersistentMetadataFromState(factorySandboxExecutorRequest{}, factory.RunRecord{}, &sandbox.SandboxState{
		Name:     "factory-no-credential-proxy-metadata",
		Provider: "fake",
		Status:   sandbox.StatusRunning,
	})
	if metadata == nil {
		t.Fatal("factorySandboxPersistentMetadataFromState() metadata = nil")
	}
	assertJSONOmitsCredentialProxyMetadata(t, "factory sandbox metadata", metadata)

	record := factory.RunRecord{
		RunID:        "run-no-credential-proxy-metadata",
		Status:       factory.RunStatusRunning,
		ExecutorMode: factory.ExecutorModeSandbox,
		Source: factory.SourceMetadata{
			Kind: factory.SourceKindPRD,
			Path: ".hal/prd.json",
		},
		RepoPath:    "/repo",
		RepoRemote:  "origin",
		BranchName:  "hal/phase-25-credential-proxy-plan",
		BaseBranch:  "main",
		SandboxName: metadata.Name,
		Sandbox:     metadata,
		CurrentStep: "run",
		CreatedAt:   startedAt,
		UpdatedAt:   startedAt,
	}
	assertJSONOmitsCredentialProxyMetadata(t, "factory run record", record)

	event := factory.EventRecord{
		Sequence:  1,
		RunID:     record.RunID,
		EventType: factory.EventTypeRunCreated,
		Timestamp: startedAt,
		Message:   "factory run created",
		Metadata: map[string]any{
			"executorMode": factory.ExecutorModeSandbox,
			"sandboxName":  metadata.Name,
		},
	}
	assertJSONOmitsCredentialProxyMetadata(t, "factory timeline event", event)
}

func TestPhase26CredentialProxyPersistenceFieldsUseApprovedSurfaces(t *testing.T) {
	violations := findCredentialProxyPersistenceFieldViolations(t)
	if len(violations) > 0 {
		t.Fatalf("credential proxy JSON fields are only approved on sandboxexecution.Manifest and factory.SandboxMetadata:\n%s", strings.Join(violations, "\n"))
	}

	assertApprovedCredentialProxySurfaceFields(t, reflect.TypeOf(sandboxexecution.Manifest{}))
	assertApprovedCredentialProxySurfaceFields(t, reflect.TypeOf(factory.SandboxMetadata{}))
}

func TestPhase26CredentialProxyMetadataRejectedFromUnapprovedSurfaces(t *testing.T) {
	unapproved := []struct {
		label string
		typ   reflect.Type
	}{
		{label: "factory EventRecord", typ: reflect.TypeOf(factory.EventRecord{})},
		{label: "worker Status", typ: reflect.TypeOf(sandboxworker.Status{})},
		{label: "worker Capabilities", typ: reflect.TypeOf(sandboxworker.Capabilities{})},
		{label: "worker RuntimeDriver", typ: reflect.TypeOf(sandboxworker.RuntimeDriver{})},
		{label: "worker SecurityPolicy", typ: reflect.TypeOf(sandboxworker.SecurityPolicy{})},
		{label: "worker SecurityControls", typ: reflect.TypeOf(sandboxworker.SecurityControls{})},
		{label: "worker Target", typ: reflect.TypeOf(sandboxworker.Target{})},
		{label: "worker RuntimeTarget", typ: reflect.TypeOf(sandboxworker.RuntimeTarget{})},
		{label: "worker Response", typ: reflect.TypeOf(sandboxworker.Response{})},
		{label: "sandbox runtime Target", typ: reflect.TypeOf(sandboxruntime.Target{})},
		{label: "sandbox runtime RuntimeState", typ: reflect.TypeOf(sandboxruntime.RuntimeState{})},
		{label: "rootless podman RuntimeMetadata", typ: reflect.TypeOf(rootlesspodman.RuntimeMetadata{})},
		{label: "sandbox host metadata", typ: reflect.TypeOf(sandbox.SandboxHost{})},
		{label: "sandbox runtime metadata", typ: reflect.TypeOf(sandbox.SandboxRuntimeState{})},
		{label: "sandbox worker routing metadata", typ: reflect.TypeOf(sandbox.WorkerRoutingMetadata{})},
		{label: "sandbox provider config", typ: reflect.TypeOf(sandbox.ProviderConfig{})},
		{label: "daytona provider", typ: reflect.TypeOf(sandbox.DaytonaProvider{})},
		{label: "hetzner provider", typ: reflect.TypeOf(sandbox.HetznerProvider{})},
		{label: "digitalocean provider", typ: reflect.TypeOf(sandbox.DigitalOceanProvider{})},
		{label: "lightsail provider", typ: reflect.TypeOf(sandbox.LightsailProvider{})},
	}
	for _, tc := range unapproved {
		t.Run(tc.label, func(t *testing.T) {
			assertNoDirectCredentialProxyJSONFields(t, tc.label, tc.typ)
		})
	}
}

func TestPhase26CredentialProxyMetadataRejectedFromCommandResultEnvelopes(t *testing.T) {
	envelopes := []struct {
		label string
		typ   reflect.Type
	}{
		{label: "run sandbox execution result", typ: reflect.TypeOf(runSandboxExecutionResult{})},
		{label: "auto sandbox execution result", typ: reflect.TypeOf(autoSandboxExecutionResult{})},
		{label: "factory run execution result", typ: reflect.TypeOf(factoryRunExecutionResult{})},
		{label: "FactoryRunResponse", typ: reflect.TypeOf(FactoryRunResponse{})},
		{label: "FactoryStatusResponse", typ: reflect.TypeOf(FactoryStatusResponse{})},
		{label: "FactoryStatusRun", typ: reflect.TypeOf(FactoryStatusRun{})},
		{label: "FactoryArtifactsResponse", typ: reflect.TypeOf(FactoryArtifactsResponse{})},
		{label: "FactoryLogsResponse", typ: reflect.TypeOf(FactoryLogsResponse{})},
		{label: "FactoryListResponse", typ: reflect.TypeOf(FactoryListResponse{})},
		{label: "FactoryQueueAddResponse", typ: reflect.TypeOf(FactoryQueueAddResponse{})},
		{label: "FactoryQueueListResponse", typ: reflect.TypeOf(FactoryQueueListResponse{})},
		{label: "FactoryQueueWorkResponse", typ: reflect.TypeOf(FactoryQueueWorkResponse{})},
		{label: "FactoryOpenResponse", typ: reflect.TypeOf(FactoryOpenResponse{})},
		{label: "FactoryTriggerResponse", typ: reflect.TypeOf(FactoryTriggerResponse{})},
		{label: "RunResult", typ: reflect.TypeOf(RunResult{})},
		{label: "AutoResult", typ: reflect.TypeOf(AutoResult{})},
		{label: "PlanResult", typ: reflect.TypeOf(PlanResult{})},
		{label: "ConvertResult", typ: reflect.TypeOf(ConvertResult{})},
		{label: "ContinueResult", typ: reflect.TypeOf(ContinueResult{})},
		{label: "ReportResult", typ: reflect.TypeOf(ReportResult{})},
		{label: "PRDAuditResult", typ: reflect.TypeOf(PRDAuditResult{})},
		{label: "CleanupResult", typ: reflect.TypeOf(CleanupResult{})},
		{label: "RepairResult", typ: reflect.TypeOf(RepairResult{})},
		{label: "InitResult", typ: reflect.TypeOf(InitResult{})},
		{label: "LinksResult", typ: reflect.TypeOf(LinksResult{})},
		{label: "ExplodeResult", typ: reflect.TypeOf(ExplodeResult{})},
		{label: "ArchiveCreateResult", typ: reflect.TypeOf(ArchiveCreateResult{})},
		{label: "ArchiveListResult", typ: reflect.TypeOf(ArchiveListResult{})},
		{label: "SandboxListResponse", typ: reflect.TypeOf(SandboxListResponse{})},
		{label: "SandboxHostListResponse", typ: reflect.TypeOf(SandboxHostListResponse{})},
		{label: "SandboxHostStatusResponse", typ: reflect.TypeOf(SandboxHostStatusResponse{})},
		{label: "SandboxRuntimeListResponse", typ: reflect.TypeOf(SandboxRuntimeListResponse{})},
		{label: "SandboxRuntimeStatusResponse", typ: reflect.TypeOf(SandboxRuntimeStatusResponse{})},
		{label: "live status result", typ: reflect.TypeOf(liveStatusResult{})},
		{label: "sandbox auth sync result", typ: reflect.TypeOf(sandboxAuthSyncResult{})},
		{label: "sandbox delete result", typ: reflect.TypeOf(deleteResult{})},
		{label: "sandbox start result", typ: reflect.TypeOf(startResult{})},
		{label: "sandbox stop result", typ: reflect.TypeOf(stopResult{})},
		{label: "sandbox batch result", typ: reflect.TypeOf(batchResult{})},
	}
	for _, tc := range envelopes {
		t.Run(tc.label, func(t *testing.T) {
			assertNoDirectCredentialProxyJSONFields(t, tc.label, tc.typ)
		})
	}
}

func assertSandboxManifestOmitsCredentialProxyMetadata(t *testing.T, manifest *sandboxexecution.Manifest) {
	t.Helper()
	fields := sandboxManifestJSONFields(t, manifest)
	for _, field := range phase26CredentialProxyJSONFields {
		if _, ok := fields[field]; ok {
			encoded, err := json.Marshal(manifest)
			if err != nil {
				t.Fatalf("Marshal(manifest) error = %v", err)
			}
			t.Fatalf("manifest unexpectedly includes Phase 25 credential proxy field %q: %s", field, encoded)
		}
	}
}

func assertJSONOmitsCredentialProxyMetadata(t *testing.T, label string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%s) error = %v", label, err)
	}
	encoded := string(data)
	for _, field := range phase26CredentialProxyJSONFields {
		if strings.Contains(encoded, `"`+field+`"`) {
			t.Fatalf("%s unexpectedly includes credential proxy field %q: %s", label, field, encoded)
		}
	}
}

func findCredentialProxyPersistenceFieldViolations(t *testing.T) []string {
	t.Helper()
	var violations []string
	fset := token.NewFileSet()
	for _, root := range []string{".", filepath.Join("..", "internal")} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", ".hal", "vendor":
					return filepath.SkipDir
				default:
					return nil
				}
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(node ast.Node) bool {
				typeSpec, ok := node.(*ast.TypeSpec)
				if !ok {
					return true
				}
				structType, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					return false
				}
				for _, field := range structType.Fields.List {
					if field.Tag == nil {
						continue
					}
					jsonName := jsonFieldNameFromTag(field.Tag.Value)
					if !phase26IsCredentialProxyJSONField(jsonName) {
						continue
					}
					if !phase26ApprovedCredentialProxySurface(file.Name.Name, typeSpec.Name.Name) {
						pos := fset.Position(field.Pos())
						violations = append(violations, pos.String()+": "+file.Name.Name+"."+typeSpec.Name.Name+" has unapproved credential proxy JSON field "+jsonName)
					}
				}
				return false
			})
			return nil
		})
		if err != nil {
			t.Fatalf("scan %s for credential proxy JSON fields: %v", root, err)
		}
	}
	return violations
}

func assertApprovedCredentialProxySurfaceFields(t *testing.T, typ reflect.Type) {
	t.Helper()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
		if !phase26IsCredentialProxyJSONField(jsonName) {
			continue
		}
		if !phase26KnownCredentialProxyJSONField(jsonName) {
			t.Fatalf("%s.%s uses unapproved credential proxy JSON field %q", typ.Name(), field.Name, jsonName)
		}
		if !strings.Contains(","+field.Tag.Get("json")+",", ",omitempty,") {
			t.Fatalf("%s.%s json tag %q must use omitempty", typ.Name(), field.Name, field.Tag.Get("json"))
		}
		if !phase26AllowedCredentialProxyPersistenceType(jsonName, field.Type) {
			t.Fatalf("%s.%s has credential proxy field type %s, want Phase 25 sandbox credential proxy contract type or sanitized wrapper", typ.Name(), field.Name, field.Type)
		}
	}
}

func assertNoDirectCredentialProxyJSONFields(t *testing.T, label string, typ reflect.Type) {
	t.Helper()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
		if phase26IsCredentialProxyJSONField(jsonName) {
			t.Fatalf("%s must not define direct credential proxy JSON field %q on %s.%s", label, jsonName, typ.Name(), field.Name)
		}
	}
}

func phase26ApprovedCredentialProxySurface(pkgName, typeName string) bool {
	return (pkgName == "sandboxexecution" && typeName == "Manifest") ||
		(pkgName == "factory" && typeName == "SandboxMetadata")
}

func phase26IsCredentialProxyJSONField(name string) bool {
	return strings.HasPrefix(name, "credentialProxy") && name != "credentialProxyMode"
}

func phase26KnownCredentialProxyJSONField(name string) bool {
	for _, field := range phase26CredentialProxyJSONFields {
		if name == field {
			return true
		}
	}
	return false
}

func phase26AllowedCredentialProxyPersistenceType(jsonName string, typ reflect.Type) bool {
	base, plural := phase26CredentialProxyPersistenceBaseType(typ)
	if base == nil {
		return false
	}
	if base.PkgPath() != "github.com/jywlabs/hal/internal/sandbox" || !strings.HasPrefix(base.Name(), "SandboxCredentialProxy") {
		return false
	}
	switch jsonName {
	case "credentialProxyPlan":
		return !plural && strings.Contains(base.Name(), "Plan")
	case "credentialProxySession":
		return !plural && strings.Contains(base.Name(), "Session")
	case "credentialProxyBindings":
		return plural && strings.Contains(base.Name(), "Binding")
	case "credentialProxy":
		return true
	default:
		return false
	}
}

func phase26CredentialProxyPersistenceBaseType(typ reflect.Type) (reflect.Type, bool) {
	plural := false
	for {
		switch typ.Kind() {
		case reflect.Pointer:
			typ = typ.Elem()
		case reflect.Slice, reflect.Array:
			plural = true
			typ = typ.Elem()
		default:
			return typ, plural
		}
	}
}

func jsonFieldNameFromTag(rawTag string) string {
	tag := strings.Trim(rawTag, "`")
	return strings.Split(reflect.StructTag(tag).Get("json"), ",")[0]
}
