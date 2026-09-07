package sandboxworker

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestMinimalLaunchSourceGuardLocksRetainedStoreAndLifetime(t *testing.T) {
	for _, fixture := range []struct{ name, file, function, old, replacement string }{
		{"wrong retained root", "minimal_launch_store_ops.go", "newMinimalLaunchStoreOps", "root: root", "root: foreign"},
		{"foreign rename", "minimal_launch_store_ops.go", "newMinimalLaunchStoreOps", "rename: root.Rename", "rename: os.Rename"},
		{"foreign sync", "minimal_launch_store_ops.go", "newMinimalLaunchStoreOps", "sync: directory.Sync", "sync: foreign.Sync"},
		{"missing exact lock", "minimal_launch_store_ops.go", "checkMinimalAuthority", "store.minimalOps.lock != lock", "false"},
		{"missing original root", "minimal_launch_store_ops.go", "checkMinimalAuthority", "!os.SameFile(info, root)", "false"},
		{"missing public root", "minimal_launch_store_ops.go", "checkMinimalAuthority", "!os.SameFile(info, current)", "false"},
		{"missing held lock", "minimal_launch_store_ops.go", "checkMinimalAuthority", "!os.SameFile(heldLock, currentLock)", "false"},
		{"wrong lock name", "minimal_launch_store_ops.go", "checkMinimalAuthority", "root.Lstat(jobStateLockFileName)", "root.Lstat(otherName)"},
		{"missing temp identity", "minimal_launch_store_ops.go", "removeMinimalTemporary", "!os.SameFile(held, current)", "false"},
		{"wrong temp destination", "minimal_launch_store_ops.go", "removeMinimalTemporary", "root.Remove(name)", "root.Remove(otherName)"},
		{"omitted root close", "minimal_launch_store_ops.go", "closeMinimalStore", "_ = ops.root.Close()", ""},
		{"legacy write bypass", "minimal_launch_store.go", "saveMinimalLaunch", "openMinimalLaunchRelative(store.minimalOps.root, name, true)", "os.CreateTemp(store.root, name)"},
		{"omitted file sync", "minimal_launch_store.go", "saveMinimalLaunch", "file.Sync() != nil", "false"},
		{"omitted directory sync", "minimal_launch_store.go", "saveMinimalLaunch", "store.minimalOps.sync() != nil", "false"},
		{"omitted byte readback", "minimal_launch_store.go", "saveMinimalLaunch", "!bytes.Equal(readback, payload)", "false"},
		{"cleanup consumed name", "minimal_launch_store.go", "saveMinimalLaunch", "defer file.Close()", "defer file.Close(); defer store.minimalOps.root.Remove(name)"},
		{"unbounded decoder", "minimal_launch_store.go", "readMinimalLaunchFile", "maxStoredJobStateV2Bytes, &state", "1<<30, &state"},
		{"legacy stored ID validation", "minimal_launch_store.go", "readMinimalLaunchFile", "sandboxruntime.ValidMinimalLaunchID(strings.TrimSuffix(path, \".json\"))", "validWorkerV2SafeID(strings.TrimSuffix(path, \".json\"))"},
		{"foreign decode input", "minimal_launch_store.go", "readMinimalLaunchFile", "bytes.NewReader(payload)", "foreignReader"},
		{"foreign output", "minimal_launch_store.go", "readMinimalLaunchFile", "maxStoredJobStateV2Bytes, &state", "maxStoredJobStateV2Bytes, &foreign"},
		{"unconditional retained close", "minimal_launch_store.go", "requireMinimalLaunchEmpty", "if !retained {", "if true {"},
		{"closed currentness bypass", "minimal_launch_store.go", "requireMinimalLaunchEmpty", "store.checkMinimalAuthority(lock) != nil", "false"},
		{"wrong final entry", "minimal_launch_dispatch.go", "checkMinimalDispatch", "manager.minimalLive[identity.WorkerJobID] != entry", "false"},
		{"omit final readback", "minimal_launch_dispatch.go", "checkMinimalDispatch", "!bytes.Equal(want, got)", "false"},
		{"omit cancellation", "minimal_launch_dispatch.go", "finishMinimalClose", "manager.minimalCancel()", ""},
		{"omit join", "minimal_launch_dispatch.go", "finishMinimalClose", "manager.minimalActive.Wait()", ""},
		{"release lock before join", "minimal_launch_dispatch.go", "finishMinimalClose", "manager.minimalActive.Wait()", "closeJobManagerV2StateLock(manager.stateLock); manager.minimalActive.Wait()"},
		{"client owns accepted context", "minimal_launch_dispatch.go", "beginMinimalPreparation", "context.AfterFunc(manager.minimalContext, preparation.cancel)", "context.AfterFunc(ctx, preparation.cancel)"},
		{"relative nofollow absent", "minimal_launch_file_unix.go", "openMinimalLaunchRelative", "|syscall.O_NOFOLLOW", ""},
		{"relative cloexec absent", "minimal_launch_file_unix.go", "openMinimalLaunchRelative", "|syscall.O_CLOEXEC", ""},
		{"relative nonblock absent", "minimal_launch_file_unix.go", "openMinimalLaunchRelative", "|syscall.O_NONBLOCK", ""},
		{"relative aliased nonblock", "minimal_launch_file_unix.go", "openMinimalLaunchRelative", "syscall.O_NONBLOCK", "aliasFlag"},
		{"relative weakened read", "minimal_launch_file_unix.go", "openMinimalLaunchRelative", "return root.OpenFile(name, flags, mode)", "if !create { flags = os.O_RDONLY }; return root.OpenFile(name, flags, mode)"},
		{"relative exclusive absent", "minimal_launch_file_unix.go", "openMinimalLaunchRelative", "|os.O_EXCL", ""},
		{"relative truncate", "minimal_launch_file_unix.go", "openMinimalLaunchRelative", "os.O_WRONLY", "os.O_WRONLY|os.O_TRUNC"},
		{"relative wrong mode", "minimal_launch_file_unix.go", "openMinimalLaunchRelative", "0o600", "0o666"},
		{"relative foreign root", "minimal_launch_file_unix.go", "openMinimalLaunchRelative", "root.OpenFile(name, flags, mode)", "foreign.OpenFile(name, flags, mode)"},
		{"relative foreign name", "minimal_launch_file_unix.go", "openMinimalLaunchRelative", "root.OpenFile(name, flags, mode)", "root.OpenFile(other, flags, mode)"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			source := l8ReadWorkerSource(t, fixture.file)
			if !strings.Contains(source, fixture.old) {
				t.Fatal("adversarial mutation did not match")
			}
			source = strings.Replace(source, fixture.old, fixture.replacement, 1)
			fs := token.NewFileSet()
			parsed, err := parser.ParseFile(fs, fixture.file, source, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, declaration := range parsed.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Name.Name != fixture.function {
					continue
				}
				scope := l8WorkerV2GuardScope{file: &l8WorkerV2ParsedFile{path: fixture.file, fileSet: fs, parsed: parsed}, node: function}
				// Exercise the actual audit entry. Changed closed-scope bodies
				// must reject before any per-call exception or type traversal.
				if err := l8InspectWorkerV2Scope(scope, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "changed exact minimal") {
					t.Fatalf("changed ownership composition accepted: %v", err)
				}
				return
			}
			t.Fatal("missing audited function")
		})
	}
}

func TestMinimalLaunchSourceGuardPinsOpaqueIDEntropy(t *testing.T) {
	source := l8ReadWorkerSource(t, "job_helpers.go")
	start, end := strings.Index(source, "func newOpaqueJobID("), strings.Index(source, "func cloneJob(")
	if start < 0 || end <= start {
		t.Fatal("missing existing entropy function")
	}
	helper := "package sandboxworker\nimport (\"crypto/rand\";\"encoding/hex\";\"io\")\n" + source[start:end]
	sources := map[string]string{
		"minimal_launch_store.go": "package sandboxworker\nfunc selectedHelper() { _, _ = newOpaqueJobID() }",
		"job_helpers.go":          helper,
	}
	policy := l8WorkerV2ProductionGuardPolicy()
	l8AssertWorkerV2GuardAllows(t, sources, policy)
	for _, fixture := range []struct{ name, old, replacement string }{
		{"foreign reader", "rand.Reader", "foreignReader"},
		{"short entropy", "[16]byte", "[1]byte"},
		{"unbounded extent", "value[:])", "arbitraryBuffer)"},
		{"additional reader", "var value [16]byte", "_, _ = io.ReadFull(foreignReader, arbitraryBuffer); var value [16]byte"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			if !strings.Contains(helper, fixture.old) {
				t.Fatal("entropy mutation did not match")
			}
			mutated := l8CloneWorkerV2GuardSources(sources)
			mutated["job_helpers.go"] = strings.Replace(helper, fixture.old, fixture.replacement, 1) + "\nvar foreignReader io.Reader = rand.Reader\nvar arbitraryBuffer []byte"
			l8AssertWorkerV2GuardRejects(t, mutated, policy, "changed exact minimal")
		})
	}
}
