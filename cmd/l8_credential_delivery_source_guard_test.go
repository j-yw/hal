package cmd

import (
	"bytes"
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
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read command package: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := entry.Name()
		source := readL8CredentialDeliveryFile(t, path)
		parsed, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse command production file %s: %v", path, err)
		}
		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote command import in %s: %v", path, err)
			}
			for _, forbidden := range []string{
				"github.com/jywlabs/hal/internal/credentialmemory",
				"github.com/jywlabs/hal/internal/credentialsource",
				"github.com/jywlabs/hal/internal/credentialproxy",
				"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol",
				"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server/credentialclient",
			} {
				if importPath == forbidden || strings.HasPrefix(importPath, forbidden+"/") {
					t.Fatalf("command production file %s prematurely imports L8 live package %q", path, importPath)
				}
			}
		}
		for _, marker := range []string{
			"NewLiveSecretSource",
			"NewJobCredentialRuntime",
			"NewCredentialProxy",
			"NewL8Firecracker",
			"guest-agent-v2",
		} {
			if strings.Contains(source, marker) {
				t.Fatalf("command production file %s prematurely contains L8 live constructor marker %q", path, marker)
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
			path: filepath.Join("..", "internal", "sandboxworker", "types.go"),
			schemas: map[string][]string{
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
				},
			},
		},
		{
			path: filepath.Join("..", "internal", "sandboxworker", "exec.go"),
			schemas: map[string][]string{
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

func TestL8CredentialDeliverySourceGuardsLiveMarkerIsolation(t *testing.T) {
	liveTag := "l8_production_" + "credential_" + "delivery_live"
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
			if !strings.Contains(string(source), liveTag) {
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
		"go test -count=1 -timeout=240s",
		"go test -race -count=1 -timeout=360s",
		"go test -count=25 -timeout=420s",
	} {
		if !strings.Contains(focused, required) {
			t.Errorf("L8 focused verifier omits %q", required)
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
