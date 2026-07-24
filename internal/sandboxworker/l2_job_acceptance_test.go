package sandboxworker

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL2JobProtocolOperationsAreDeclared(t *testing.T) {
	t.Parallel()

	declared := l2SandboxworkerDeclaredIdentifiers(t)
	for _, name := range []string{
		"JobContractVersion",
		"OperationJobStart",
		"OperationJobStatus",
		"OperationJobLogs",
		"OperationJobCancel",
		"Job",
		"JobStartRequest",
		"JobStatusRequest",
		"JobLogsRequest",
		"JobCancelRequest",
		"JobLogsResponse",
	} {
		if !declared[name] {
			t.Errorf("sandboxworker production contract does not declare %s", name)
		}
	}
}

func TestL2JobProtocolOperationsAreAcceptedByVersionedEnvelope(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerOptions{
		SocketPath: "worker.sock",
		Handler: RequestHandlerFunc(func(_ context.Context, req Request) Response {
			return protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeInternal, "not reached")
		}),
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	requests := []string{
		`{"protocolVersion":"sandboxworker-v1","requestId":"req-start","operation":"job_start","driverId":"rootless_podman","jobStart":{"contractVersion":"sandboxjob-v1","exec":{"operationId":"op-1","target":{"name":"box","runtime":{"driver":"rootless_podman","runtimeId":"runtime-1"}},"args":["true"],"stdoutLimitBytes":1024,"stderrLimitBytes":1024}}}`,
		`{"protocolVersion":"sandboxworker-v1","requestId":"req-status","operation":"job_status","jobStatus":{"contractVersion":"sandboxjob-v1","jobId":"job-1"}}`,
		`{"protocolVersion":"sandboxworker-v1","requestId":"req-logs","operation":"job_logs","jobLogs":{"contractVersion":"sandboxjob-v1","jobId":"job-1","cursor":0,"limitBytes":32768}}`,
		`{"protocolVersion":"sandboxworker-v1","requestId":"req-cancel","operation":"job_cancel","jobCancel":{"contractVersion":"sandboxjob-v1","jobId":"job-1"}}`,
	}
	for _, raw := range requests {
		raw := raw
		t.Run(l2JobOperationFromJSON(raw), func(t *testing.T) {
			_, errorResp := server.readRequest(strings.NewReader(raw))
			if errorResp != nil {
				t.Fatalf("versioned L2 job request was rejected: %#v", errorResp.Error)
			}
		})
	}
}

func l2SandboxworkerDeclaredIdentifiers(t *testing.T) map[string]bool {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir() error: %v", err)
	}
	fset := token.NewFileSet()
	declared := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", entry.Name()), nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", entry.Name(), err)
		}
		for _, decl := range file.Decls {
			switch typed := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range typed.Specs {
					switch item := spec.(type) {
					case *ast.TypeSpec:
						declared[item.Name.Name] = true
					case *ast.ValueSpec:
						for _, name := range item.Names {
							declared[name.Name] = true
						}
					}
				}
			}
		}
	}
	return declared
}

func l2JobOperationFromJSON(raw string) string {
	for _, operation := range []string{"job_start", "job_status", "job_logs", "job_cancel"} {
		if strings.Contains(raw, `"operation":"`+operation+`"`) {
			return operation
		}
	}
	return "unknown"
}
