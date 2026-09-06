package sandboxworker

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"
	"testing"
)

func l8WorkerV2AllowedExactMinimalFileSurface(scope l8WorkerV2GuardScope, surface string) bool {
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok || scope.file == nil || filepath.Base(scope.file.path) != "minimal_launch_file_unix.go" || !l8WorkerV2ExactMinimalDeclaration(scope) {
		return false
	}
	if function.Name.Name == "minimalLaunchFileOwned" {
		return surface == "os.Geteuid"
	}
	if function.Name.Name != "openMinimalLaunchNoFollow" && function.Name.Name != "openMinimalLaunchRelative" {
		return false
	}
	return surface == "syscall.O_NOFOLLOW" || surface == "syscall.O_CLOEXEC" || surface == "syscall.O_DIRECTORY" || function.Name.Name == "openMinimalLaunchRelative" && surface == "syscall.O_NONBLOCK"
}

func TestMinimalLaunchSourceGuardLocksReadOnlyNoFollow(t *testing.T) {
	source := l8ReadWorkerSource(t, "minimal_launch_file_unix.go")
	check := func(source, surface string) bool {
		t.Helper()
		fs := token.NewFileSet()
		parsed, err := parser.ParseFile(fs, "minimal_launch_file_unix.go", source, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range parsed.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "openMinimalLaunchNoFollow" {
				return l8WorkerV2AllowedExactMinimalFileSurface(l8WorkerV2GuardScope{file: &l8WorkerV2ParsedFile{path: "minimal_launch_file_unix.go", fileSet: fs, parsed: parsed}, node: function}, surface)
			}
		}
		t.Fatal("missing original nofollow helper")
		return false
	}
	for _, symbol := range []string{"O_NOFOLLOW", "O_CLOEXEC", "O_DIRECTORY"} {
		if !check(source, "syscall."+symbol) {
			t.Fatal("actual read-only opening flags were not recognized")
		}
	}
	for _, surface := range []string{"syscall.Mount", "os.Geteuid", "golang.org/x/sys/unix.O_NOFOLLOW", "syscall.O_NONBLOCK"} {
		if check(source, surface) {
			t.Fatal("read-only helper admitted unrelated kernel surface")
		}
	}
	for _, fixture := range []struct{ name, old, replacement string }{
		{"omitted nofollow", " | syscall.O_NOFOLLOW", ""},
		{"omitted cloexec", " | syscall.O_CLOEXEC", ""},
		{"aliased flags", "syscall.O_NOFOLLOW", "aliasFlag"},
		{"conditional weakening", "flags |= syscall.O_DIRECTORY", "flags = syscall.O_DIRECTORY"},
		{"write", "os.O_RDONLY", "os.O_RDWR"},
		{"create", "os.O_RDONLY", "os.O_RDONLY | os.O_CREATE"},
		{"truncate", "os.O_RDONLY", "os.O_RDONLY | os.O_TRUNC"},
		{"different path", "os.OpenFile(path, flags, 0)", "os.OpenFile(other, flags, 0)"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			if !strings.Contains(source, fixture.old) {
				t.Fatal("nofollow mutation did not match")
			}
			if check(strings.Replace(source, fixture.old, fixture.replacement, 1), "syscall.O_NOFOLLOW") {
				t.Fatal("changed file opening borrowed read-only authority")
			}
		})
	}
}

func l8WorkerV2AllowedExactMinimalDispatchCall(scope l8WorkerV2GuardScope, call *ast.CallExpr, info *types.Info) bool {
	function := l8WorkerV2ScopeFunction(scope)
	if !l8WorkerV2ExactMinimalDispatchDeclaration(scope) {
		return false
	}
	called := l8WorkerV2CalledObject(call.Fun, info)
	if called == nil {
		return false
	}
	if function.Name.Name == "reserveMinimalLaunch" {
		if l8WorkerV2ExactReceiverObject(function, "jobManagerV2", true, info) == nil {
			return false
		}
		if called.Pkg() != nil && called.Pkg().Path() == "context" && called.Name() == "Err" {
			return true
		}
		if called.Pkg() != nil && called.Pkg().Path() == "github.com/jywlabs/hal/internal/sandboxruntime" && (called.Name() == "Reserve" || called.Name() == "ArmDispatch") {
			return true
		}
		_, functionValue := called.Type().(*types.Signature)
		return called.Name() == "poison" && functionValue
	}
	if function.Name.Name == "checkMinimalDispatch" {
		return l8WorkerV2ExactReceiverObject(function, "jobManagerV2", true, info) != nil && called.Pkg() != nil && called.Pkg().Path() == "context" && called.Name() == "Err"
	}
	if function.Name.Name != "handleMinimalLaunch" || l8WorkerV2ExactReceiverObject(function, "L8Service", true, info) == nil {
		return false
	}
	if called.Pkg() != nil {
		if called.Pkg().Path() == "github.com/jywlabs/hal/internal/sandboxruntime" && (called.Name() == "ResolveSelection" || called.Name() == "Current") {
			return true
		}
	}
	named, ok := types.Unalias(called.Type()).(*types.Named)
	return called.Name() == "cancel" && ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "context" && named.Obj().Name() == "CancelFunc"
}

func l8WorkerV2ExactMinimalDispatchDeclaration(scope l8WorkerV2GuardScope) bool {
	_, ok := scope.node.(*ast.FuncDecl)
	if !ok || scope.file == nil || filepath.Base(scope.file.path) != "minimal_launch_dispatch.go" {
		return false
	}
	return l8WorkerV2ExactMinimalDeclaration(scope)
}

func TestMinimalLaunchSourceGuardLocksActualDispatchComposition(t *testing.T) {
	source := l8ReadWorkerSource(t, "minimal_launch_dispatch.go")
	check := func(source, name string) bool {
		t.Helper()
		fs := token.NewFileSet()
		parsed, err := parser.ParseFile(fs, "minimal_launch_dispatch.go", source, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range parsed.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == name {
				return l8WorkerV2ExactMinimalDispatchDeclaration(l8WorkerV2GuardScope{file: &l8WorkerV2ParsedFile{path: "minimal_launch_dispatch.go", fileSet: fs, parsed: parsed}, node: function})
			}
		}
		t.Fatal("missing expected declaration")
		return false
	}
	if !check(source, "handleMinimalLaunch") {
		t.Fatal("actual audited handler composition changed")
	}
	if !check(source, "reserveMinimalLaunch") {
		t.Fatal("actual audited manager reservation composition changed")
	}
	for _, fixture := range []struct{ name, old, replacement string }{
		{"detached context", "beginMinimalPreparation(ctx, deadline)", "beginMinimalPreparation(context.Background(), deadline)"},
		{"rebased deadline", "beginMinimalPreparation(ctx, deadline)", "beginMinimalPreparation(ctx, time.Now().Add(service.minimalLaunch.PreparationTimeout))"},
		{"reassigned context", "start := cloneJobStartRequestV2", "ctx = context.Background(); start := cloneJobStartRequestV2"},
		{"reassigned principal", "start := cloneJobStartRequestV2", "principal = nil; start := cloneJobStartRequestV2"},
		{"foreign authorizer", "service.minimalLaunch.Authorizer.ResolveSelection", "foreign.Authorizer.ResolveSelection"},
		{"foreign provider", "service.minimalLaunch.Provider.Start", "foreign.Provider.Start"},
		{"foreign selection", "Provider.Start(entry.reservation, entry.selection,", "Provider.Start(entry.reservation, selection,"},
		{"foreign barrier owner", "service.jobs.checkMinimalDispatch(entry)", "foreign.jobs.checkMinimalDispatch(entry)"},
		{"foreign barrier entry", "service.jobs.checkMinimalDispatch(entry)", "service.jobs.checkMinimalDispatch(foreignEntry)"},
		{"bypass final barrier", "return service.jobs.checkMinimalDispatch(entry)", "return nil"},
		{"bypass reserve", "service.jobs.reserveMinimalLaunch", "foreign.reserveMinimalLaunch"},
		{"early provider", "entry, job, retained, err :=", "_, _ = service.minimalLaunch.Provider.Start(nil, selection); entry, job, retained, err :="},
		{"injected call", "defer service.jobs.endMinimalPreparation(preparation)", "defer service.jobs.endMinimalPreparation(preparation); arbitrary()"},
		{"skip currentness", "selection.Current(preparation.ctx) != nil", "false"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			if !strings.Contains(source, fixture.old) {
				t.Fatal("dispatch mutation did not match")
			}
			if check(strings.Replace(source, fixture.old, fixture.replacement, 1), "handleMinimalLaunch") {
				t.Fatal("altered composition borrowed selected call authority")
			}
		})
	}
	for _, fixture := range []struct{ name, old, replacement string }{
		{"skip reserved save", "if manager.store.save(state) != nil {", "if false {"},
		{"skip dispatch save", "manager.store.save(state) != nil || reservation.ArmDispatch", "false || reservation.ArmDispatch"},
		{"arm before dispatch save", "manager.store.save(state) != nil || reservation.ArmDispatch(reservation.Context(), identity) != nil", "reservation.ArmDispatch(reservation.Context(), identity) != nil || manager.store.save(state) != nil"},
		{"skip arm", "reservation.ArmDispatch(reservation.Context(), identity) != nil", "false"},
		{"reserve detached", "selection.Reserve(ctx, manager.minimalContext, jobID", "selection.Reserve(context.Background(), manager.minimalContext, jobID"},
		{"client owns accepted job", "if reservation.Context().Err() != nil", "if ctx.Err() != nil"},
		{"early manager return", "if manager.store.save(state) != nil {", "return entry, job, true, nil; if manager.store.save(state) != nil {"},
		{"foreign save", "manager.store.save(state)", "foreignStore.save(state)"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			if !strings.Contains(source, fixture.old) {
				t.Fatal("manager mutation did not match")
			}
			if check(strings.Replace(source, fixture.old, fixture.replacement, 1), "reserveMinimalLaunch") {
				t.Fatal("altered manager borrowed selected call authority")
			}
		})
	}
}

// Enrollment adds audited roots, not exemptions. These fixtures deliberately
// have no v2 names: every declaration in each selected file must be inspected.
func TestMinimalLaunchSourceGuardEnrollsAuditedRoots(t *testing.T) {
	policy := l8WorkerV2ProductionGuardPolicy()
	for _, path := range []string{"minimal_launch_dispatch.go", "minimal_launch_file_other.go", "minimal_launch_file_unix.go", "minimal_launch_store.go", "minimal_launch_store_ops.go"} {
		t.Run(path, func(t *testing.T) {
			if !policy.dedicated[path] || policy.mixed[path] {
				t.Fatal("selected file is not a dedicated audited root")
			}
			l8AssertWorkerV2GuardAllows(t, map[string]string{path: "package sandboxworker\nfunc selectedHelper() {}"}, policy)
			for _, fixture := range []struct{ name, source, reason string }{
				{"process", "package sandboxworker\nimport \"os\"\nfunc selectedHelper() { os.Exit(1) }", "os.Exit"},
				{"unbounded reader", "package sandboxworker\nimport \"io\"\nfunc selectedHelper(reader io.Reader) { _, _ = io.ReadAll(reader) }", "implicit interface callback"},
				{"callback", "package sandboxworker\ntype selectedDispatcher interface { Run() }\nfunc selectedHelper(value selectedDispatcher) { value.Run() }", "interface dispatch"},
				{"schema", "package sandboxworker\ntype selectedRecord struct { Value string `json:\"secretValue\"` }", `json:\"secret`},
			} {
				t.Run(fixture.name, func(t *testing.T) {
					l8AssertWorkerV2GuardRejects(t, map[string]string{path: fixture.source}, policy, fixture.reason)
				})
			}
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				path:             "package sandboxworker\nfunc selectedHelper() { indirectHelper() }",
				"job_helpers.go": "package sandboxworker\nimport \"os\"\nfunc indirectHelper() { os.Exit(1) }",
			}, policy, "os.Exit")
		})
	}
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"minimal_launch_unlisted.go": "package sandboxworker\nfunc hiddenJobStartV2() {}",
	}, policy, "outside the exact allowlist")
}

// This is the exact optional private extension of the existing stored record;
// it does not admit another encoder or relax the recursive callback audit.
func l8WorkerV2IsExactMinimalLaunchSchema(typ types.Type) bool {
	pointer, ok := types.Unalias(typ).(*types.Pointer)
	if !ok {
		return false
	}
	structure, ok := l8WorkerV2ExactNamedStructUnderlying(pointer.Elem(), "storedMinimalLaunchV1")
	fields := []struct{ name, kind, tag string }{
		{"ContractVersion", "string", "contractVersion"}, {"Revision", "uint64", "revision"}, {"Phase", "string", "phase"},
		{"JobGeneration", "string", "jobGeneration"}, {"SandboxID", "string", "sandboxId"}, {"ExecutionID", "string", "executionId"},
		{"SubmissionID", "string", "submissionId"}, {"RuntimeGeneration", "string", "runtimeGeneration"},
		{"LaunchGrantID", "string", "launchGrantId"}, {"LaunchPolicyID", "string", "launchPolicyId"}, {"LaunchPolicyRevision", "uint64", "launchPolicyRevision"},
		{"NetworkPolicyID", "string", "networkPolicyId"}, {"PreparationStartedAt", "time.Time", "preparationStartedAt"}, {"PreparationDeadline", "time.Time", "preparationDeadline"},
	}
	if !ok || structure.NumFields() != len(fields) {
		return false
	}
	for index, expected := range fields {
		field := structure.Field(index)
		if field.Name() != expected.name || field.Embedded() || structure.Tag(index) != `json:"`+expected.tag+`"` {
			return false
		}
		if expected.kind == "time.Time" {
			named, ok := types.Unalias(field.Type()).(*types.Named)
			if !ok || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "time" || named.Obj().Name() != "Time" || named.TypeArgs().Len() != 0 {
				return false
			}
		} else if !types.Identical(field.Type(), types.Universe.Lookup(expected.kind).Type()) {
			return false
		}
	}
	return true
}

func TestMinimalLaunchSourceGuardLocksPrivateSchema(t *testing.T) {
	policy := l8WorkerV2ProductionGuardPolicy()
	minimal := "package sandboxworker\nimport \"time\"\n" + `type storedMinimalLaunchV1 struct {
ContractVersion string ` + "`json:\"contractVersion\"`" + `
Revision uint64 ` + "`json:\"revision\"`" + `
Phase string ` + "`json:\"phase\"`" + `
JobGeneration string ` + "`json:\"jobGeneration\"`" + `
SandboxID string ` + "`json:\"sandboxId\"`" + `
ExecutionID string ` + "`json:\"executionId\"`" + `
SubmissionID string ` + "`json:\"submissionId\"`" + `
RuntimeGeneration string ` + "`json:\"runtimeGeneration\"`" + `
LaunchGrantID string ` + "`json:\"launchGrantId\"`" + `
LaunchPolicyID string ` + "`json:\"launchPolicyId\"`" + `
LaunchPolicyRevision uint64 ` + "`json:\"launchPolicyRevision\"`" + `
NetworkPolicyID string ` + "`json:\"networkPolicyId\"`" + `
PreparationStartedAt time.Time ` + "`json:\"preparationStartedAt\"`" + `
PreparationDeadline time.Time ` + "`json:\"preparationDeadline\"`" + `
}`
	store := "package sandboxworker\nimport \"encoding/json\"\n" + `
type JobV2 struct { ID string }
type storedJobCredentialStateV2 struct { ContractVersion string }
type storedJobCredentialRuntimeRecoveryReceiptV1 struct { ContractVersion string }
type storedJobStateV2 struct {
JobV2 JobV2
RequestKey string ` + "`json:\"requestKey\"`" + `
PrincipalID string ` + "`json:\"principalId\"`" + `
DaemonGeneration string ` + "`json:\"daemonGeneration\"`" + `
CredentialState *storedJobCredentialStateV2 ` + "`json:\"credentialState,omitempty\"`" + `
CredentialRecoveryReceipt *storedJobCredentialRuntimeRecoveryReceiptV1 ` + "`json:\"credentialRecoveryReceipt,omitempty\"`" + `
MinimalLaunch *storedMinimalLaunchV1 ` + "`json:\"minimalLaunch,omitempty\"`" + `
}
func encodeStoredJobStateV2(state storedJobStateV2) ([]byte, error) { return json.Marshal(state) }`
	sources := map[string]string{"job_store_v2.go": store, "minimal_launch_store.go": minimal}
	l8AssertWorkerV2GuardAllows(t, sources, policy)
	for _, fixture := range []struct{ name, path, old, replacement string }{
		{"omit option", "job_store_v2.go", "minimalLaunch,omitempty", "minimalLaunch"},
		{"alias tag", "minimal_launch_store.go", "jobGeneration\"", "job_generation\""},
		{"wrong type", "minimal_launch_store.go", "Revision uint64", "Revision string"},
		{"extra field", "minimal_launch_store.go", "type storedMinimalLaunchV1 struct {", "type storedMinimalLaunchV1 struct { Extra string;"},
		{"secret field", "minimal_launch_store.go", "type storedMinimalLaunchV1 struct {", "type storedMinimalLaunchV1 struct { Value string `json:\"secretValue\"`;"},
		{"transitive renderer", "minimal_launch_store.go", "Phase string", "Phase minimalRenderer"},
		{"whole value renderer", "minimal_launch_store.go", "type storedMinimalLaunchV1 struct {", "func (*storedMinimalLaunchV1) MarshalJSON() ([]byte, error) { return nil, nil }; type storedMinimalLaunchV1 struct {"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			mutated := l8CloneWorkerV2GuardSources(sources)
			if !strings.Contains(mutated[fixture.path], fixture.old) {
				t.Fatal("schema mutation did not match")
			}
			mutated[fixture.path] = strings.Replace(mutated[fixture.path], fixture.old, fixture.replacement, 1)
			if fixture.name == "transitive renderer" {
				mutated["minimal_launch_store.go"] += "\ntype minimalRenderer string\nfunc (minimalRenderer) MarshalJSON() ([]byte, error) { return nil, nil }"
			}
			if err := l8AuditWorkerV2Sources(mutated, policy); err == nil {
				t.Fatal("guard accepted changed private schema/callback")
			}
		})
	}
}
