package cmd

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const phase47TemplateLockJSONField = "templateLock"

var phase47TemplateLockStructuralKeys = map[string]bool{
	"document":          true,
	"templateReference": true,
	"runtimeImage":      true,
	"sourceArtifact":    true,
}

var phase47TemplateLockLeafKeys = map[string]bool{
	"sourceKind":      true,
	"referenceKind":   true,
	"status":          true,
	"digestAlgorithm": true,
	"digestValue":     true,
	"sizeBytes":       true,
	"lockedAt":        true,
	"warningCodes":    true,
	"reasonCode":      true,
}

var phase47TemplateLockReasonCodes = map[string]bool{
	"document_digest":              true,
	"template_reference_digest":    true,
	"runtime_image_digest":         true,
	"source_artifact_digest":       true,
	"immutable_digest":             true,
	"mutable_reference":            true,
	"unresolved_mutable_reference": true,
	"resolver_unavailable":         true,
	"unsupported_source":           true,
}

func TestPhase47TemplateLockDurableSurfacesRequireOptionalMetadata(t *testing.T) {
	for _, surface := range phase47TemplateLockDurableSurfaces() {
		t.Run(surface.label, func(t *testing.T) {
			field := requirePhase47TemplateLockSurfaceField(t, surface.typ)
			if got, want := field.Tag.Get("json"), "templateLock,omitempty"; got != want {
				t.Fatalf("%s.TemplateLock json tag = %q, want %q", surface.typ.Name(), got, want)
			}
			base := phase47TemplateLockBaseType(field.Type)
			if base.Kind() != reflect.Struct {
				t.Fatalf("%s.TemplateLock type = %s, want pointer to durable metadata struct", surface.typ.Name(), field.Type)
			}
			if base.Name() == "" || base.PkgPath() == "" {
				t.Fatalf("%s.TemplateLock type = %s, want named import-neutral metadata type", surface.typ.Name(), field.Type)
			}
		})
	}
}

func TestPhase47TemplateLockExistingRecordsOmitMetadataAndLoadLegacyJSON(t *testing.T) {
	startedAt := time.Date(2026, 7, 3, 17, 27, 14, 0, time.UTC)

	assertPhase47TemplateLockOmitted(t, "sandbox runtime state", sandbox.SandboxRuntimeState{
		Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
		IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		RuntimeID:      "runtime-01",
		Image:          "ghcr.io/acme/go-agent:1.2.0",
		WorkerID:       "worker-01",
	})
	assertPhase47TemplateLockOmitted(t, "sandbox execution manifest", sandboxexecution.Manifest{
		ID:          "run-template-lock-legacy",
		Purpose:     sandboxexecution.PurposeRun,
		SandboxName: "template-lock-legacy",
		Status:      sandboxexecution.StatusRunning,
		StartedAt:   startedAt,
	})
	assertPhase47TemplateLockOmitted(t, "factory sandbox metadata", factory.SandboxMetadata{
		Name:     "factory-template-lock-legacy",
		Provider: "fake",
		Status:   sandbox.StatusRunning,
	})
	assertPhase47TemplateLockOmitted(t, "runtime metadata", sandboxruntime.RuntimeMetadata{
		Backend: "rootless_podman",
	})

	var runtimeState sandbox.SandboxRuntimeState
	mustUnmarshalPhase47TemplateLockLegacyJSON(t, "sandbox runtime state", `{
		"driver": "rootless_podman",
		"isolationLevel": "container",
		"runtimeId": "runtime-01",
		"image": "ghcr.io/acme/go-agent:1.2.0",
		"workerId": "worker-01"
	}`, &runtimeState)
	assertPhase47TemplateLockOmitted(t, "legacy sandbox runtime state", runtimeState)

	var manifest sandboxexecution.Manifest
	mustUnmarshalPhase47TemplateLockLegacyJSON(t, "sandbox execution manifest", `{
		"id": "run-template-lock-legacy",
		"purpose": "run",
		"sandboxName": "template-lock-legacy",
		"status": "succeeded",
		"startedAt": "2026-07-03T17:27:14Z"
	}`, &manifest)
	assertPhase47TemplateLockOmitted(t, "legacy sandbox execution manifest", manifest)

	var metadata factory.SandboxMetadata
	mustUnmarshalPhase47TemplateLockLegacyJSON(t, "factory sandbox metadata", `{
		"name": "factory-template-lock-legacy",
		"provider": "fake",
		"status": "running"
	}`, &metadata)
	assertPhase47TemplateLockOmitted(t, "legacy factory sandbox metadata", metadata)

	var runtimeMetadata sandboxruntime.RuntimeMetadata
	mustUnmarshalPhase47TemplateLockLegacyJSON(t, "runtime metadata", `{
		"backend": "rootless_podman",
		"capabilityLabels": ["template"]
	}`, &runtimeMetadata)
	assertPhase47TemplateLockOmitted(t, "legacy runtime metadata", runtimeMetadata)
}

func TestPhase47TemplateLockEmptyMetadataSanitizesToOmittedJSON(t *testing.T) {
	for _, surface := range phase47TemplateLockDurableSurfaces() {
		t.Run(surface.label, func(t *testing.T) {
			requirePhase47TemplateLockSurfaceField(t, surface.typ)
			encoded := phase47RoundTripSurfaceJSON(t, surface.label, surface.typ, surface.payloadWithLock(`{}`))
			if strings.Contains(encoded, `"`+phase47TemplateLockJSONField+`"`) {
				t.Fatalf("%s persisted explicit empty templateLock metadata; want sanitized nil omission: %s", surface.label, encoded)
			}
		})
	}
}

func TestPhase47TemplateLockPersistedJSONShapeAndRedaction(t *testing.T) {
	validLock := phase47TemplateLockValidPayload()
	for _, surface := range phase47TemplateLockDurableSurfaces() {
		t.Run(surface.label, func(t *testing.T) {
			requirePhase47TemplateLockSurfaceField(t, surface.typ)
			encoded := phase47RoundTripSurfaceJSON(t, surface.label, surface.typ, surface.payloadWithLock(validLock))
			assertPhase47TemplateLockPayloadOmitsForbiddenFragments(t, surface.label, encoded)

			lock := phase47TemplateLockObjectFromJSON(t, surface.label, encoded)
			assertPhase47TemplateLockAllowedShape(t, surface.label, lock)
			assertPhase47TemplateLockDigest(t, surface.label, lock, "document", "document_digest", strings.Repeat("a", 64))
			assertPhase47TemplateLockDigest(t, surface.label, lock, "templateReference", "template_reference_digest", strings.Repeat("b", 64))
			assertPhase47TemplateLockDigest(t, surface.label, lock, "runtimeImage", "runtime_image_digest", strings.Repeat("c", 64))
			assertPhase47TemplateLockDigest(t, surface.label, lock, "sourceArtifact", "source_artifact_digest", strings.Repeat("d", 64))
		})
	}
}

func TestPhase47TemplateLockUnresolvedMutableReferenceIsPersistedSafely(t *testing.T) {
	unresolvedLock := phase47TemplateLockUnresolvedPayload()
	for _, surface := range phase47TemplateLockDurableSurfaces() {
		t.Run(surface.label, func(t *testing.T) {
			requirePhase47TemplateLockSurfaceField(t, surface.typ)
			encoded := phase47RoundTripSurfaceJSON(t, surface.label, surface.typ, surface.payloadWithLock(unresolvedLock))
			assertPhase47TemplateLockPayloadOmitsForbiddenFragments(t, surface.label, encoded)

			lock := phase47TemplateLockObjectFromJSON(t, surface.label, encoded)
			assertPhase47TemplateLockAllowedShape(t, surface.label, lock)
			runtimeImage := requirePhase47TemplateLockCategory(t, surface.label, lock, "runtimeImage")
			if got := runtimeImage["status"]; got != "unresolved" {
				t.Fatalf("%s runtimeImage status = %#v, want unresolved", surface.label, got)
			}
			if got := runtimeImage["reasonCode"]; got != "mutable_reference" {
				t.Fatalf("%s runtimeImage reasonCode = %#v, want mutable_reference", surface.label, got)
			}
			if got := runtimeImage["sourceKind"]; got != "runtime_image" {
				t.Fatalf("%s runtimeImage sourceKind = %#v, want runtime_image", surface.label, got)
			}
			if got := runtimeImage["referenceKind"]; got != "oci_image" {
				t.Fatalf("%s runtimeImage referenceKind = %#v, want oci_image", surface.label, got)
			}
			for _, digestKey := range []string{"digestAlgorithm", "digestValue"} {
				if _, ok := runtimeImage[digestKey]; ok {
					t.Fatalf("%s unresolved runtimeImage includes %s: %#v", surface.label, digestKey, runtimeImage)
				}
			}
		})
	}
}

func TestPhase47TemplateLockTypeIsImportNeutralAndRuntimeShapeMatches(t *testing.T) {
	sharedField := requirePhase47TemplateLockSurfaceField(t, reflect.TypeOf(sandbox.SandboxRuntimeState{}))
	sharedType := phase47TemplateLockBaseType(sharedField.Type)
	switch sharedType.PkgPath() {
	case "github.com/jywlabs/hal/internal/sandboxtemplate",
		"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition":
		t.Fatalf("SandboxRuntimeState.TemplateLock type = %s; durable lock metadata must not depend on sandboxtemplate acquisition contracts", sharedField.Type)
	}
	assertPhase47InternalSandboxDoesNotImportTemplatePackages(t)

	for _, surface := range []struct {
		label string
		typ   reflect.Type
	}{
		{label: "sandbox execution manifest", typ: reflect.TypeOf(sandboxexecution.Manifest{})},
		{label: "factory sandbox metadata", typ: reflect.TypeOf(factory.SandboxMetadata{})},
	} {
		field := requirePhase47TemplateLockSurfaceField(t, surface.typ)
		if got := phase47TemplateLockBaseType(field.Type); got != sharedType {
			t.Fatalf("%s TemplateLock type = %s, want shared durable type %s", surface.label, field.Type, sharedType)
		}
	}

	runtimeField := requirePhase47TemplateLockSurfaceField(t, reflect.TypeOf(sandboxruntime.RuntimeMetadata{}))
	runtimeType := phase47TemplateLockBaseType(runtimeField.Type)
	if runtimeType != sharedType {
		sharedShape := phase47TemplateLockJSONShape(sharedType)
		runtimeShape := phase47TemplateLockJSONShape(runtimeType)
		if !reflect.DeepEqual(runtimeShape, sharedShape) {
			t.Fatalf("sandboxruntime.RuntimeMetadata TemplateLock JSON shape = %v, want shared durable shape %v", runtimeShape, sharedShape)
		}
	}
}

type phase47TemplateLockSurface struct {
	label           string
	typ             reflect.Type
	payloadWithLock func(lockJSON string) []byte
}

func phase47TemplateLockDurableSurfaces() []phase47TemplateLockSurface {
	return []phase47TemplateLockSurface{
		{
			label: "sandbox runtime state",
			typ:   reflect.TypeOf(sandbox.SandboxRuntimeState{}),
			payloadWithLock: func(lockJSON string) []byte {
				return []byte(`{
					"driver": "rootless_podman",
					"isolationLevel": "container",
					"runtimeId": "runtime-01",
					"image": "ghcr.io/acme/go-agent:1.2.0",
					"workerId": "worker-01",
					"templateLock": ` + lockJSON + `
				}`)
			},
		},
		{
			label: "sandbox execution manifest",
			typ:   reflect.TypeOf(sandboxexecution.Manifest{}),
			payloadWithLock: func(lockJSON string) []byte {
				return []byte(`{
					"id": "run-template-lock",
					"purpose": "run",
					"sandboxName": "template-lock",
					"status": "running",
					"startedAt": "2026-07-03T17:27:14Z",
					"templateLock": ` + lockJSON + `
				}`)
			},
		},
		{
			label: "factory sandbox metadata",
			typ:   reflect.TypeOf(factory.SandboxMetadata{}),
			payloadWithLock: func(lockJSON string) []byte {
				return []byte(`{
					"name": "factory-template-lock",
					"provider": "fake",
					"status": "running",
					"templateLock": ` + lockJSON + `
				}`)
			},
		},
		{
			label: "runtime metadata",
			typ:   reflect.TypeOf(sandboxruntime.RuntimeMetadata{}),
			payloadWithLock: func(lockJSON string) []byte {
				return []byte(`{
					"backend": "rootless_podman",
					"templateLock": ` + lockJSON + `
				}`)
			},
		},
	}
}

func phase47TemplateLockValidPayload() string {
	return `{
		"document": {
			"sourceKind": "local_file",
			"referenceKind": "local",
			"status": "locked",
			"digestAlgorithm": "sha256",
			"digestValue": "` + strings.Repeat("a", 64) + `",
			"sizeBytes": 4096,
			"lockedAt": "2026-07-03T17:27:14Z",
			"reasonCode": "document_digest",
			"warningCodes": ["document_digest", "ghp_phase47_secret"],
			"localPath": "/Users/v/private-token-template.yaml"
		},
		"templateReference": {
			"sourceKind": "template_reference",
			"referenceKind": "oci_artifact",
			"status": "locked",
			"digestAlgorithm": "sha256",
			"digestValue": "` + strings.Repeat("b", 64) + `",
			"reasonCode": "template_reference_digest",
			"rawRegistryEndpoint": "https://fixture-user:super-secret-password@registry.invalid/acme/template:latest?token=ghp_phase47_secret"
		},
		"runtimeImage": {
			"sourceKind": "runtime_image",
			"referenceKind": "oci_image",
			"status": "locked",
			"digestAlgorithm": "sha256",
			"digestValue": "` + strings.Repeat("c", 64) + `",
			"reasonCode": "runtime_image_digest",
			"username": "fixture-user",
			"password": "super-secret-password"
		},
		"sourceArtifact": {
			"sourceKind": "source_artifact",
			"referenceKind": "oci_artifact",
			"status": "locked",
			"digestAlgorithm": "sha256",
			"digestValue": "` + strings.Repeat("d", 64) + `",
			"reasonCode": "source_artifact_digest",
			"credentialValue": "providerCredential=sk-live-template",
			"secretValue": "secret=sk-live-template"
		},
		"registryEndpoint": "registry.invalid/acme/template:latest?token=ghp_phase47_secret",
		"providerCredentials": "AWS_SECRET_ACCESS_KEY=sk-live-template"
	}`
}

func phase47TemplateLockUnresolvedPayload() string {
	return `{
		"runtimeImage": {
			"sourceKind": "runtime_image",
			"referenceKind": "oci_image",
			"status": "unresolved",
			"reasonCode": "mutable_reference",
			"warningCodes": ["mutable_reference", "sk-live-template"],
			"digestAlgorithm": "sha256",
			"digestValue": "not-a-real-digest-from-https://fixture-user:super-secret-password@registry.invalid/image:latest?token=ghp_phase47_secret"
		}
	}`
}

func requirePhase47TemplateLockSurfaceField(t *testing.T, typ reflect.Type) reflect.StructField {
	t.Helper()
	field, ok := typ.FieldByName("TemplateLock")
	if !ok {
		t.Fatalf("%s missing optional TemplateLock field with json tag templateLock,omitempty", typ.Name())
	}
	if got := strings.Split(field.Tag.Get("json"), ",")[0]; got != phase47TemplateLockJSONField {
		t.Fatalf("%s.TemplateLock json field = %q, want %q", typ.Name(), got, phase47TemplateLockJSONField)
	}
	if !strings.Contains(","+field.Tag.Get("json")+",", ",omitempty,") {
		t.Fatalf("%s.TemplateLock json tag = %q, want omitempty", typ.Name(), field.Tag.Get("json"))
	}
	return field
}

func phase47TemplateLockBaseType(typ reflect.Type) reflect.Type {
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		typ = typ.Elem()
	}
	return typ
}

func assertPhase47TemplateLockOmitted(t *testing.T, label string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%s) error = %v", label, err)
	}
	if strings.Contains(string(encoded), `"`+phase47TemplateLockJSONField+`"`) {
		t.Fatalf("%s unexpectedly includes templateLock without template acquisition: %s", label, encoded)
	}
}

func mustUnmarshalPhase47TemplateLockLegacyJSON(t *testing.T, label string, payload string, out any) {
	t.Helper()
	if err := json.Unmarshal([]byte(payload), out); err != nil {
		t.Fatalf("Unmarshal legacy %s without templateLock error = %v", label, err)
	}
}

func phase47RoundTripSurfaceJSON(t *testing.T, label string, typ reflect.Type, payload []byte) string {
	t.Helper()
	target := reflect.New(typ)
	if err := json.Unmarshal(payload, target.Interface()); err != nil {
		t.Fatalf("Unmarshal(%s) templateLock payload error = %v", label, err)
	}
	encoded, err := json.Marshal(target.Elem().Interface())
	if err != nil {
		t.Fatalf("Marshal(%s) templateLock payload error = %v", label, err)
	}
	return string(encoded)
}

func phase47TemplateLockObjectFromJSON(t *testing.T, label string, encoded string) map[string]any {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal([]byte(encoded), &object); err != nil {
		t.Fatalf("Unmarshal(%s encoded JSON) error = %v", label, err)
	}
	rawLock, ok := object[phase47TemplateLockJSONField]
	if !ok {
		t.Fatalf("%s round-tripped JSON omitted templateLock; durable metadata is missing or not persisted: %s", label, encoded)
	}
	lock, ok := rawLock.(map[string]any)
	if !ok {
		t.Fatalf("%s templateLock JSON = %#v, want object", label, rawLock)
	}
	return lock
}

func assertPhase47TemplateLockAllowedShape(t *testing.T, label string, lock map[string]any) {
	t.Helper()
	for key := range lock {
		if !phase47TemplateLockStructuralKeys[key] {
			t.Fatalf("%s templateLock includes unapproved top-level key %q: %#v", label, key, lock)
		}
	}
	for category, raw := range lock {
		entry, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("%s templateLock.%s = %#v, want object", label, category, raw)
		}
		for key, value := range entry {
			if !phase47TemplateLockLeafKeys[key] {
				t.Fatalf("%s templateLock.%s includes unapproved key %q: %#v", label, category, key, entry)
			}
			assertPhase47TemplateLockBoundedCode(t, label, category, key, value)
		}
	}
}

func assertPhase47TemplateLockBoundedCode(t *testing.T, label string, category string, key string, value any) {
	t.Helper()
	switch key {
	case "reasonCode":
		code, ok := value.(string)
		if !ok || !phase47TemplateLockReasonCodes[code] {
			t.Fatalf("%s templateLock.%s reasonCode = %#v, want bounded reason code", label, category, value)
		}
	case "warningCodes":
		codes, ok := value.([]any)
		if !ok {
			t.Fatalf("%s templateLock.%s warningCodes = %#v, want array", label, category, value)
		}
		for _, rawCode := range codes {
			code, ok := rawCode.(string)
			if !ok || !phase47TemplateLockReasonCodes[code] {
				t.Fatalf("%s templateLock.%s warningCodes contains %#v, want bounded warning code", label, category, rawCode)
			}
		}
	}
}

func assertPhase47TemplateLockDigest(t *testing.T, label string, lock map[string]any, category string, reasonCode string, digestValue string) {
	t.Helper()
	entry := requirePhase47TemplateLockCategory(t, label, lock, category)
	wantFields := map[string]any{
		"status":          "locked",
		"digestAlgorithm": "sha256",
		"digestValue":     digestValue,
		"reasonCode":      reasonCode,
	}
	switch category {
	case "document":
		wantFields["sourceKind"] = "local_file"
		wantFields["referenceKind"] = "local"
	case "templateReference":
		wantFields["sourceKind"] = "template_reference"
		wantFields["referenceKind"] = "oci_artifact"
	case "runtimeImage":
		wantFields["sourceKind"] = "runtime_image"
		wantFields["referenceKind"] = "oci_image"
	case "sourceArtifact":
		wantFields["sourceKind"] = "source_artifact"
		wantFields["referenceKind"] = "oci_artifact"
	}
	for key, want := range wantFields {
		if got := entry[key]; got != want {
			t.Fatalf("%s templateLock.%s.%s = %#v, want %#v; entry=%#v", label, category, key, got, want, entry)
		}
	}
	if category == "document" {
		if got := entry["sizeBytes"]; got != float64(4096) {
			t.Fatalf("%s templateLock.document.sizeBytes = %#v, want 4096", label, got)
		}
		if got := entry["lockedAt"]; got != "2026-07-03T17:27:14Z" {
			t.Fatalf("%s templateLock.document.lockedAt = %#v, want locked timestamp", label, got)
		}
	}
}

func requirePhase47TemplateLockCategory(t *testing.T, label string, lock map[string]any, category string) map[string]any {
	t.Helper()
	raw, ok := lock[category]
	if !ok {
		t.Fatalf("%s templateLock missing %s entry: %#v", label, category, lock)
	}
	entry, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("%s templateLock.%s = %#v, want object", label, category, raw)
	}
	return entry
}

func assertPhase47TemplateLockPayloadOmitsForbiddenFragments(t *testing.T, label string, payload string) {
	t.Helper()
	for _, fragment := range []string{
		"/Users/v/private-token-template.yaml",
		"private-token-template.yaml",
		"registry.invalid/acme/template:latest?token=ghp_phase47_secret",
		"registry.invalid/image:latest?token=ghp_phase47_secret",
		"registry.invalid",
		"?token=",
		"token=",
		"fixture-user",
		"super-secret-password",
		"password",
		"ghp_phase47_secret",
		"sk-live-template",
		"providerCredential",
		"AWS_SECRET_ACCESS_KEY",
		"secret=",
		"secretValue",
	} {
		if fragment == "" {
			continue
		}
		escaped, err := json.Marshal(fragment)
		if err != nil {
			t.Fatalf("Marshal forbidden fragment %q error = %v", fragment, err)
		}
		for _, candidate := range []string{fragment, strings.Trim(string(escaped), `"`)} {
			if candidate != "" && strings.Contains(payload, candidate) {
				t.Fatalf("%s templateLock payload leaked forbidden fragment %q: %s", label, fragment, payload)
			}
		}
	}
}

func assertPhase47InternalSandboxDoesNotImportTemplatePackages(t *testing.T) {
	t.Helper()
	for _, path := range phase47GoFiles(t, filepath.Join("..", "internal", "sandbox")) {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error = %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxtemplate") {
				t.Fatalf("internal/sandbox production file %s imports %s; durable templateLock type must not create a sandbox -> sandboxtemplate dependency", path, importPath)
			}
		}
	}
}

func phase47GoFiles(t *testing.T, root string) []string {
	t.Helper()
	var paths []string
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
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Strings(paths)
	return paths
}

func phase47TemplateLockJSONShape(typ reflect.Type) []string {
	var out []string
	var walk func(prefix string, current reflect.Type)
	walk = func(prefix string, current reflect.Type) {
		current = phase47TemplateLockBaseType(current)
		if current.Kind() != reflect.Struct || current.PkgPath() == "time" && current.Name() == "Time" {
			return
		}
		for i := 0; i < current.NumField(); i++ {
			field := current.Field(i)
			if field.PkgPath != "" {
				continue
			}
			jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
			if jsonName == "" || jsonName == "-" {
				continue
			}
			key := prefix + jsonName
			out = append(out, key)
			walk(key+".", field.Type)
		}
	}
	walk("", typ)
	sort.Strings(out)
	return out
}
