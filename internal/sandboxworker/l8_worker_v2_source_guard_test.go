package sandboxworker

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestL8WorkerV2SourceGuardsKeepV1JobPayloadsCredentialFree(t *testing.T) {
	jobSource := l8ReadWorkerSource(t, "job_types.go")
	for _, marker := range []string{
		"JobContractVersionV2",
		"JobStartRequestV2",
		"JobCredentialIntentV2",
		"productionCredentialsRequested",
		"admissionGrantId",
		"sourceReferenceIds",
	} {
		if strings.Contains(jobSource, marker) {
			t.Fatalf("v1 job_types.go contains v2 marker %q", marker)
		}
	}

	envelopeSource := l8ReadWorkerSource(t, "types.go")
	for _, marker := range []string{
		"productionCredentialsRequested",
		"admissionGrantId",
		"admissionGrantRevision",
		"sourceReferenceIds",
		"authenticatedPrincipal",
	} {
		if strings.Contains(envelopeSource, marker) {
			t.Fatalf("outer envelope source contains inline credential field %q; v2 payloads must remain distinct", marker)
		}
	}
}

func TestL8WorkerV2SourceGuardsRejectSecretAndLiveAuthoritySurfaces(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	allowedV2Files := map[string]bool{
		"client.go":          true,
		"handler.go":         true,
		"job_helpers.go":     true,
		"job_manager_v2.go":  true,
		"job_service_v2.go":  true,
		"job_store_v2.go":    true,
		"job_v2_client.go":   true,
		"job_v2_helpers.go":  true,
		"job_v2_service.go":  true,
		"job_v2_types.go":    true,
		"protocol_decode.go": true,
		"server.go":          true,
		"types.go":           true,
	}
	mixedV1V2Files := map[string]bool{
		"client.go":      true,
		"handler.go":     true,
		"job_helpers.go": true,
		"server.go":      true,
		"types.go":       true,
	}
	v2Markers := []string{
		"JobContractVersionV2",
		"OperationJobStartV2",
		"OperationJobResolveV2",
		"OperationJobStatusV2",
		"OperationJobLogsV2",
		"OperationJobCancelV2",
		"JobStartRequestV2",
		"JobResolveRequestV2",
		"JobStatusRequestV2",
		"JobLogsRequestV2",
		"JobCancelRequestV2",
		"JobCredentialIntentV2",
		"JobCredentialBindingV2",
		"JobLogsResponseV2",
		"JobV2",
		`json:"jobStartV2`,
		`json:"jobResolveV2`,
		`json:"jobStatusV2`,
		`json:"jobLogsV2`,
		`json:"jobCancelV2`,
		`json:"jobV2`,
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		source := l8ReadWorkerSource(t, path)
		containsV2 := false
		for _, marker := range v2Markers {
			if strings.Contains(source, marker) {
				containsV2 = true
				break
			}
		}
		if containsV2 && !allowedV2Files[path] {
			t.Fatalf("production file %s contains worker-v2 declarations/references outside the exact allowlist", path)
		}
		if !containsV2 {
			continue
		}
		scopedSource := source
		if mixedV1V2Files[path] {
			scopedSource = l8WorkerV2ScopedDeclarations(t, path, source)
		}
		for _, forbidden := range []string{
			`json:"value`,
			`json:"secret`,
			`json:"callback`,
			`json:"ticket`,
			`json:"socket`,
			`json:"endpoint`,
			`json:"hostPath`,
			`json:"path`,
			`json:"keySerial`,
			`json:"execBinding`,
			`json:"authenticatedPrincipal`,
			"RawValue",
			"SecretValue",
			"Callback",
			"Ticket",
			"Socket",
			"Endpoint",
			"HostPath",
			"KeySerial",
			"LiveSecretSource",
			"JobCredentialExecBinding",
			"keyctl_read",
			"tls.Conn",
			"net.Listen",
			"os/exec",
		} {
			if strings.Contains(scopedSource, forbidden) {
				t.Fatalf("v2 protocol production file %s contains forbidden live/secret marker %q", path, forbidden)
			}
		}

		parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", path, parseErr)
		}
		if mixedV1V2Files[path] {
			continue
		}
		for _, spec := range parsed.Imports {
			importPath, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil {
				t.Fatalf("unquote import in %s: %v", path, unquoteErr)
			}
			for _, forbidden := range []string{
				"github.com/jywlabs/hal/internal/credentialmemory",
				"github.com/jywlabs/hal/internal/credentialsource",
				"github.com/jywlabs/hal/internal/credentialproxy",
				"github.com/jywlabs/hal/internal/factory",
				"crypto/tls",
				"net",
				"net/http",
				"os/exec",
			} {
				if importPath == forbidden || strings.HasPrefix(importPath, forbidden+"/") {
					t.Fatalf("v2 protocol production file %s imports live/provider dependency %q", path, importPath)
				}
			}
		}
	}
}

func l8WorkerV2ScopedDeclarations(t *testing.T, path, source string) string {
	t.Helper()
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, path, source, 0)
	if err != nil {
		t.Fatalf("parse mixed v1/v2 file %s: %v", path, err)
	}
	var scoped bytes.Buffer
	for _, declaration := range parsed.Decls {
		include := false
		switch typed := declaration.(type) {
		case *ast.FuncDecl:
			include = strings.Contains(typed.Name.Name, "V2")
		case *ast.GenDecl:
			for _, spec := range typed.Specs {
				switch value := spec.(type) {
				case *ast.TypeSpec:
					include = include || strings.Contains(value.Name.Name, "V2")
				case *ast.ValueSpec:
					for _, name := range value.Names {
						include = include || strings.Contains(name.Name, "V2")
					}
				}
			}
		}
		if include {
			if err := format.Node(&scoped, fileSet, declaration); err != nil {
				t.Fatalf("render v2 declaration in %s: %v", path, err)
			}
			scoped.WriteByte('\n')
		}
	}
	return scoped.String()
}

func TestL8WorkerV2SourceGuardsPrincipalCannotBeDecodedFromJSON(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		source := l8ReadWorkerSource(t, path)
		parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", path, parseErr)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			field, ok := node.(*ast.Field)
			if !ok || field.Tag == nil {
				return true
			}
			tag, unquoteErr := strconv.Unquote(field.Tag.Value)
			if unquoteErr != nil {
				t.Fatalf("unquote field tag in %s: %v", path, unquoteErr)
			}
			jsonTag := strings.ToLower(reflectStructTagJSON(tag))
			if strings.Contains(jsonTag, "principal") || strings.Contains(jsonTag, "peeruid") || strings.Contains(jsonTag, "peergid") {
				t.Fatalf("production field in %s exposes server-derived principal through JSON tag %q", path, jsonTag)
			}
			return true
		})
	}
}

func reflectStructTagJSON(tag string) string {
	for _, part := range strings.Fields(tag) {
		if strings.HasPrefix(part, `json:"`) {
			value := strings.TrimPrefix(part, `json:"`)
			return strings.TrimSuffix(value, `"`)
		}
	}
	return ""
}

func l8ReadWorkerSource(t *testing.T, path string) string {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}
