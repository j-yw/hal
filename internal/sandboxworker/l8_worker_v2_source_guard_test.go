package sandboxworker

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestL8WorkerV2PrivateJSONIdentityExceptionsAreExact(t *testing.T) {
	allowed := map[string]string{
		"job_v2_types.go": "package sandboxworker\ntype JobV2 struct { WorkerID string `json:\"workerId\"` }",
	}
	if err := l8AuditWorkerV2PrivateJSONIdentityTags(allowed); err != nil {
		t.Fatalf("exact private identity exceptions were rejected: %v", err)
	}

	for _, tt := range []struct {
		name     string
		path     string
		typeName string
		field    string
		tag      string
		extra    string
	}{
		{name: "principal on job", path: "job_v2_types.go", typeName: "JobV2", field: "PrincipalID", tag: "principalId"},
		{name: "principal on private type", path: "job_v2_types.go", typeName: "privateIdentity", field: "PrincipalID", tag: "principalId"},
		{name: "principal on request", path: "types.go", typeName: "Request", field: "PrincipalID", tag: "principalId"},
		{name: "principal with different field", path: "types.go", typeName: "Request", field: "AuthenticatedPrincipal", tag: "principalId"},
		{name: "principal with different tag", path: "types.go", typeName: "Request", field: "PrincipalID", tag: "principalID"},
		{name: "daemon identity", path: "types.go", typeName: "Request", field: "Generation", tag: "daemonGeneration"},
		{name: "daemon identity with different tag", path: "types.go", typeName: "Request", field: "DaemonGeneration", tag: "daemon_generation"},
		{name: "extra public response surface", path: "types.go", typeName: "Request", field: "WorkerID", tag: "workerId", extra: "\ntype Response struct { PrincipalID string `json:\"principalId\"` }\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source := "package sandboxworker\ntype " + tt.typeName + " struct { " + tt.field + " string `json:\"" + tt.tag + "\"` }\n" + tt.extra
			err := l8AuditWorkerV2PrivateJSONIdentityTags(map[string]string{tt.path: source})
			if err == nil || !strings.Contains(err.Error(), "private server identity") {
				t.Fatalf("identity tag audit error = %v, want private server identity rejection", err)
			}
		})
	}
}

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

func TestL8WorkerV2SourceGuardsPrincipalCannotBeDecodedFromJSON(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sources := make(map[string]string)
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		sources[path] = l8ReadWorkerSource(t, path)
	}
	if err := l8AuditWorkerV2PrivateJSONIdentityTags(sources); err != nil {
		t.Fatal(err)
	}
}

func l8AuditWorkerV2PrivateJSONIdentityTags(sources map[string]string) error {
	paths := make([]string, 0, len(sources))
	for path := range sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		source := sources[path]
		parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if parseErr != nil {
			return fmt.Errorf("parse %s: %w", path, parseErr)
		}
		for _, declaration := range parsed.Decls {
			generated, ok := declaration.(*ast.GenDecl)
			if !ok || generated.Tok != token.TYPE {
				continue
			}
			for _, spec := range generated.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				structType, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, field := range structType.Fields.List {
					if field.Tag == nil {
						continue
					}
					tag, unquoteErr := strconv.Unquote(field.Tag.Value)
					if unquoteErr != nil {
						return fmt.Errorf("unquote field tag in %s: %w", path, unquoteErr)
					}
					jsonTag := reflectStructTagJSON(tag)
					normalizedTag := strings.ToLower(jsonTag)
					if strings.Contains(normalizedTag, "peeruid") || strings.Contains(normalizedTag, "peergid") {
						return fmt.Errorf("production field in %s exposes peer credential through JSON tag %q", path, jsonTag)
					}
					if strings.Contains(normalizedTag, "principal") || strings.Contains(normalizedTag, "daemongeneration") || strings.Contains(normalizedTag, "daemon_generation") {
						return fmt.Errorf("production field in %s exposes private server identity outside exact private identity types through JSON tag %q", path, jsonTag)
					}
				}
			}
		}
	}
	return nil
}

func l8ReadWorkerSource(t *testing.T, path string) string {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
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
