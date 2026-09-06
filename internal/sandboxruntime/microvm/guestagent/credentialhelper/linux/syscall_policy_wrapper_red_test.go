//go:build linux && amd64 && l8_d4_full_syscall_adapter

package linux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
)

// l8D4FullWrapperSourceSHA256 is a checked-in review tripwire, not runtime
// authority. A coordinated wrapper-and-lock update requires code review and
// protected-branch enforcement.
const (
	l8D4FullWrapperSourcePath    = "syscall_policy_wrapper_linux.go"
	l8D4FullWrapperSourceMaximum = int64(64 << 10)
	l8D4FullWrapperSourceSHA256  = "f202fcca96b376a2efa46d7d317dd04dba214a6c0040da5337495d3a5a0c6aa7"
)

var errL8D4FullWrapperSourceLock = errors.New("L8 D4 full-wrapper source lock mismatch")

func TestL8D4FullSyscallWrapperSourceContract(t *testing.T) {
	payload, err := readL8D4FullWrapperLockedSource(l8D4FullWrapperSourcePath, l8D4FullWrapperSourceSHA256, nil)
	if err != nil {
		t.Fatalf("read sole live wrapper: %v", err)
	}
	if err := validateL8D4FullSyscallWrapperSource(string(payload)); err != nil {
		t.Fatal(err)
	}
}

func TestL8D4FullSyscallWrapperSourceGuardRejectsMutations(t *testing.T) {
	payload, err := readL8D4FullWrapperLockedSource(l8D4FullWrapperSourcePath, l8D4FullWrapperSourceSHA256, nil)
	if err != nil {
		t.Fatalf("read sole live wrapper: %v", err)
	}
	source := string(payload)
	mutations := []struct {
		name        string
		old         string
		replacement string
		suffix      string
	}{
		{name: "drops amd64 gate", old: "//go:build linux && amd64 && l8_d4_full_syscall_adapter", replacement: "//go:build linux && l8_d4_full_syscall_adapter"},
		{name: "drops binding claim", old: "bindings, err := policy.NewAdapterBindings(ticket, wrapper)", replacement: "var bindings syscallpolicy.AdapterBindings\n\tvar err error"},
		{name: "duplicates binding claim", old: "bindings, err := policy.NewAdapterBindings(ticket, wrapper)", replacement: "_, _ = policy.NewAdapterBindings(ticket, wrapper)\n\tbindings, err := policy.NewAdapterBindings(ticket, wrapper)"},
		{name: "substitutes binding source", old: "policy.NewAdapterBindings(ticket, wrapper)", replacement: "policy.NewAdapterBindings(ticket, observations)"},
		{name: "duplicates pre authorization", old: "permit, pre, err := policy.AuthorizePre(ticket, wrapper.bindings, wrapper)", replacement: "_, _, _ = policy.AuthorizePre(ticket, wrapper.bindings, wrapper)\n\tpermit, pre, err := policy.AuthorizePre(ticket, wrapper.bindings, wrapper)"},
		{name: "substitutes pre bindings", old: "policy.AuthorizePre(ticket, wrapper.bindings, wrapper)", replacement: "policy.AuthorizePre(ticket, syscallpolicy.AdapterBindings{}, wrapper)"},
		{name: "substitutes pre source", old: "policy.AuthorizePre(ticket, wrapper.bindings, wrapper)", replacement: "policy.AuthorizePre(ticket, wrapper.bindings, observations)"},
		{name: "duplicates executor call", old: "execution, err = executor.execute(ctx)", replacement: "_, _ = executor.execute(ctx)\n\texecution, err = executor.execute(ctx)"},
		{name: "substitutes executor context", old: "executor.execute(ctx)", replacement: "executor.execute(context.Background())"},
		{name: "duplicates abort terminal", old: "decision, err := terminal.policy.AbortPermit(permit.value, phase)", replacement: "_, _ = terminal.policy.AbortPermit(permit.value, phase)\n\tdecision, err := terminal.policy.AbortPermit(permit.value, phase)"},
		{name: "substitutes abort permit", old: "terminal.policy.AbortPermit(permit.value, phase)", replacement: "terminal.policy.AbortPermit(syscallpolicy.AdapterPermit{}, phase)"},
		{name: "duplicates post terminal", old: "decision, err := terminal.policy.AuthorizePost(permit.value, source)", replacement: "_, _ = terminal.policy.AuthorizePost(permit.value, source)\n\tdecision, err := terminal.policy.AuthorizePost(permit.value, source)"},
		{name: "substitutes post permit", old: "terminal.policy.AuthorizePost(permit.value, source)", replacement: "terminal.policy.AuthorizePost(syscallpolicy.AdapterPermit{}, source)"},
		{name: "duplicates commit terminal", old: "decision, err := terminal.policy.CommitNoObject(permit.value)", replacement: "_, _ = terminal.policy.CommitNoObject(permit.value)\n\tdecision, err := terminal.policy.CommitNoObject(permit.value)"},
		{name: "substitutes commit permit", old: "terminal.policy.CommitNoObject(permit.value)", replacement: "terminal.policy.CommitNoObject(syscallpolicy.AdapterPermit{})"},
		{name: "finalizes before object cleanup", old: "cleanupErr := closeReturnedObjectSafely(object)\n\twrapper.mu.Lock()\n\twrapper.finishLocked()", replacement: "wrapper.mu.Lock()\n\twrapper.finishLocked()\n\twrapper.mu.Unlock()\n\tcleanupErr := closeReturnedObjectSafely(object)\n\twrapper.mu.Lock()"},
		{name: "connects default constructor", old: "type syscallExecutor interface {", replacement: "var _ = NewSyscallPolicyCoreKernel\n\ntype syscallExecutor interface {"},
		{name: "exports wrapper constructor", old: "func newSyscallPolicyWrapper(", replacement: "func NewSyscallPolicyWrapper("},
		{name: "exports executor authority", old: "type syscallExecutor interface {", replacement: "type SyscallExecutor interface {"},
		{name: "adds raw syscall", old: "execution, err = executor.execute(ctx)", replacement: "_, _, _ = syscall.Syscall(0, 0, 0, 0)\n\texecution, err = executor.execute(ctx)"},
		{name: "stores binding method alias", old: "bindings, err := policy.NewAdapterBindings(ticket, wrapper)", replacement: "bindingMethod := policy.NewAdapterBindings\n\t_ = bindingMethod\n\tbindings, err := policy.NewAdapterBindings(ticket, wrapper)"},
		{name: "invokes binding claim through closure", old: "bindings, err := policy.NewAdapterBindings(ticket, wrapper)", replacement: "claimBindings := func() (syscallpolicy.AdapterBindings, error) { return policy.NewAdapterBindings(ticket, wrapper) }\n\tbindings, err := claimBindings()"},
		{name: "references pre method value", old: "permit, pre, err := policy.AuthorizePre(ticket, wrapper.bindings, wrapper)", replacement: "_ = policy.AuthorizePre\n\tpermit, pre, err := policy.AuthorizePre(ticket, wrapper.bindings, wrapper)"},
		{name: "invokes pre authorization through closure", old: "permit, pre, err := policy.AuthorizePre(ticket, wrapper.bindings, wrapper)", replacement: "authorizePre := func() (syscallpolicy.AdapterPermit, syscallpolicy.AdapterDecision, error) { return policy.AuthorizePre(ticket, wrapper.bindings, wrapper) }\n\tpermit, pre, err := authorizePre()"},
		{name: "captures executor method in closure", old: "execution, err = executor.execute(ctx)", replacement: "_ = func() any { return executor.execute }\n\texecution, err = executor.execute(ctx)"},
		{name: "invokes executor through closure", old: "execution, err = executor.execute(ctx)", replacement: "executeLater := func() (syscallExecution, error) { return executor.execute(ctx) }\n\texecution, err = executeLater()"},
		{
			name: "repeats executor through backward goto",
			old:  "execution, err = executor.execute(ctx)\n\treturn execution, err",
			replacement: "reviewerRepeatExecutor:\n" +
				"\treviewerRepeatExecutorCall = reviewerRepeatExecutorCall\n" +
				"\texecution, err = executor.execute(ctx)\n" +
				"\tif reviewerRepeatExecutorCall {\n" +
				"\t\treviewerRepeatExecutorCall = false\n" +
				"\t\tgoto reviewerRepeatExecutor\n" +
				"\t}\n" +
				"\treturn execution, err",
			suffix: "\nvar reviewerRepeatExecutorCall = true\n",
		},
		{
			name:        "retains policy authority container",
			old:         "bindings, err := policy.NewAdapterBindings(ticket, wrapper)",
			replacement: "reviewerRetainedPolicies = append(reviewerRetainedPolicies, policy)\n\tbindings, err := policy.NewAdapterBindings(ticket, wrapper)",
			suffix:      "\nvar reviewerRetainedPolicies []*syscallpolicy.Policy\n",
		},
		{name: "references abort method value", old: "decision, err := terminal.policy.AbortPermit(permit.value, phase)", replacement: "_ = terminal.policy.AbortPermit\n\tdecision, err := terminal.policy.AbortPermit(permit.value, phase)"},
		{name: "invokes concrete abort through closure", old: "decision, err := terminal.policy.AbortPermit(permit.value, phase)", replacement: "abort := func() (syscallpolicy.AdapterDecision, error) { return terminal.policy.AbortPermit(permit.value, phase) }\n\tdecision, err := abort()"},
		{name: "stores post method value", old: "decision, err := terminal.policy.AuthorizePost(permit.value, source)", replacement: "_ = []any{terminal.policy.AuthorizePost}\n\tdecision, err := terminal.policy.AuthorizePost(permit.value, source)"},
		{name: "invokes concrete post through closure", old: "decision, err := terminal.policy.AuthorizePost(permit.value, source)", replacement: "authorizePost := func() (syscallpolicy.AdapterDecision, error) { return terminal.policy.AuthorizePost(permit.value, source) }\n\tdecision, err := authorizePost()"},
		{name: "passes commit method as callback", old: "decision, err := terminal.policy.CommitNoObject(permit.value)", replacement: "func(callback any) {}(terminal.policy.CommitNoObject)\n\tdecision, err := terminal.policy.CommitNoObject(permit.value)"},
		{name: "invokes concrete commit through closure", old: "decision, err := terminal.policy.CommitNoObject(permit.value)", replacement: "commit := func() (syscallpolicy.AdapterDecision, error) { return terminal.policy.CommitNoObject(permit.value) }\n\tdecision, err := commit()"},
		{name: "references pre-abort terminal method", old: "return terminal.abortPermit(permit, syscallpolicy.AdapterPhasePre)", replacement: "_ = terminal.abortPermit\n\t\t\treturn terminal.abortPermit(permit, syscallpolicy.AdapterPhasePre)"},
		{name: "invokes pre-abort terminal through closure", old: "return terminal.abortPermit(permit, syscallpolicy.AdapterPhasePre)", replacement: "abort := func() syscallTerminalResult { return terminal.abortPermit(permit, syscallpolicy.AdapterPhasePre) }\n\t\t\treturn abort()"},
		{name: "references post terminal method", old: "return terminal.authorizePost(permit, postSource)", replacement: "_ = terminal.authorizePost\n\t\t\t\treturn terminal.authorizePost(permit, postSource)"},
		{name: "invokes post terminal through closure", old: "return terminal.authorizePost(permit, postSource)", replacement: "authorizePost := func() syscallTerminalResult { return terminal.authorizePost(permit, postSource) }\n\t\t\t\treturn authorizePost()"},
		{name: "references commit terminal method", old: "return terminal.commitNoObject(permit)", replacement: "_ = terminal.commitNoObject\n\t\t\treturn terminal.commitNoObject(permit)"},
		{name: "invokes commit terminal through closure", old: "return terminal.commitNoObject(permit)", replacement: "commit := func() syscallTerminalResult { return terminal.commitNoObject(permit) }\n\t\t\treturn commit()"},
		{
			name:        "retains post-abort closure after finalization",
			old:         "return terminal.abortPermit(permit, syscallpolicy.AdapterPhasePost)",
			replacement: "reviewerRetainedTerminal = func() syscallTerminalResult { return terminal.abortPermit(permit, syscallpolicy.AdapterPhasePost) }\n\t\t\treturn reviewerRetainedTerminal()",
			suffix:      "\nvar reviewerRetainedTerminal func() syscallTerminalResult\n",
		},
		{
			name:        "retains approved terminal callback after finalization",
			old:         "return call()\n}",
			replacement: "reviewerRetainedTerminalCallback = call\n\treturn call()\n}",
			suffix:      "\nvar reviewerRetainedTerminalCallback func() syscallTerminalResult\n",
		},
		{
			name: "retains pre-abort assignment behind dummy convergence",
			old:  "terminalResult := callTerminalSafely(func() syscallTerminalResult {\n\t\t\treturn terminal.abortPermit(permit, syscallpolicy.AdapterPhasePre)\n\t\t})",
			replacement: "terminalResult := callTerminalSafely(func() syscallTerminalResult {\n" +
				"\t\t\treviewerRetainedOuterTerminal = func() syscallTerminalResult {\n" +
				"\t\t\t\tterminalResult := callTerminalSafely(func() syscallTerminalResult {\n" +
				"\t\t\t\t\treturn terminal.abortPermit(permit, syscallpolicy.AdapterPhasePre)\n" +
				"\t\t\t\t})\n" +
				"\t\t\t\treturn terminalResult\n" +
				"\t\t\t}\n" +
				"\t\t\t_ = reviewerRetainedOuterTerminal()\n" +
				"\t\t\treturn syscallTerminalResult{valid: true}\n" +
				"\t\t})",
			suffix: "\nvar reviewerRetainedOuterTerminal func() syscallTerminalResult\n",
		},
		{
			name: "retains post-abort assignment behind dummy convergence",
			old:  "terminalResult = callTerminalSafely(func() syscallTerminalResult {\n\t\t\treturn terminal.abortPermit(permit, syscallpolicy.AdapterPhasePost)\n\t\t})",
			replacement: "reviewerRetainedOuterTerminal = func() syscallTerminalResult {\n" +
				"\t\t\tterminalResult = callTerminalSafely(func() syscallTerminalResult {\n" +
				"\t\t\t\treturn terminal.abortPermit(permit, syscallpolicy.AdapterPhasePost)\n" +
				"\t\t\t})\n" +
				"\t\t\treturn terminalResult\n" +
				"\t\t}\n" +
				"\t\t_ = reviewerRetainedOuterTerminal()\n" +
				"\t\tterminalResult = callTerminalSafely(func() syscallTerminalResult {\n" +
				"\t\t\treturn syscallTerminalResult{valid: true}\n" +
				"\t\t})",
			suffix: "\nvar reviewerRetainedOuterTerminal func() syscallTerminalResult\n",
		},
		{
			name: "retains private post assignment behind dummy convergence",
			old:  "terminalResult = callTerminalSafely(func() syscallTerminalResult {\n\t\t\t\treturn terminal.authorizePost(permit, postSource)\n\t\t\t})",
			replacement: "reviewerRetainedOuterTerminal = func() syscallTerminalResult {\n" +
				"\t\t\t\tterminalResult = callTerminalSafely(func() syscallTerminalResult {\n" +
				"\t\t\t\t\treturn terminal.authorizePost(permit, postSource)\n" +
				"\t\t\t\t})\n" +
				"\t\t\t\treturn terminalResult\n" +
				"\t\t\t}\n" +
				"\t\t\t_ = reviewerRetainedOuterTerminal()\n" +
				"\t\t\tterminalResult = callTerminalSafely(func() syscallTerminalResult {\n" +
				"\t\t\t\treturn syscallTerminalResult{valid: true}\n" +
				"\t\t\t})",
			suffix: "\nvar reviewerRetainedOuterTerminal func() syscallTerminalResult\n",
		},
		{
			name: "retains private commit assignment behind dummy convergence",
			old:  "terminalResult = callTerminalSafely(func() syscallTerminalResult {\n\t\t\treturn terminal.commitNoObject(permit)\n\t\t})",
			replacement: "reviewerRetainedOuterTerminal = func() syscallTerminalResult {\n" +
				"\t\t\tterminalResult = callTerminalSafely(func() syscallTerminalResult {\n" +
				"\t\t\t\treturn terminal.commitNoObject(permit)\n" +
				"\t\t\t})\n" +
				"\t\t\treturn terminalResult\n" +
				"\t\t}\n" +
				"\t\t_ = reviewerRetainedOuterTerminal()\n" +
				"\t\tterminalResult = callTerminalSafely(func() syscallTerminalResult {\n" +
				"\t\t\treturn syscallTerminalResult{valid: true}\n" +
				"\t\t})",
			suffix: "\nvar reviewerRetainedOuterTerminal func() syscallTerminalResult\n",
		},
		{
			name:        "stores abort method in generic box",
			old:         "decision, err := terminal.policy.AbortPermit(permit.value, phase)",
			replacement: "_ = reviewerMethodBox[func(syscallpolicy.AdapterPermit, syscallpolicy.AdapterPhase) (syscallpolicy.AdapterDecision, error)]{value: terminal.policy.AbortPermit}\n\tdecision, err := terminal.policy.AbortPermit(permit.value, phase)",
			suffix:      "\ntype reviewerMethodBox[T any] struct { value T }\n",
		},
		{name: "finalizes early before cleanup", old: "decision, terminalErr := checkedTerminalResult(terminalResult)", replacement: "wrapper.mu.Lock()\n\twrapper.finishLocked()\n\twrapper.mu.Unlock()\n\tdecision, terminalErr := checkedTerminalResult(terminalResult)"},
		{name: "invokes aliased finalizer before cleanup", old: "decision, terminalErr := checkedTerminalResult(terminalResult)", replacement: "finalizeEarly := wrapper.finishLocked\n\tfinalizeEarly()\n\tdecision, terminalErr := checkedTerminalResult(terminalResult)"},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := strings.Replace(source, mutation.old, mutation.replacement, 1) + mutation.suffix
			if mutated == source {
				t.Fatal("mutation did not change source")
			}
			if err := validateL8D4FullSyscallWrapperSource(mutated); err == nil {
				t.Fatal("source guard accepted mutation")
			} else if !errors.Is(err, errL8D4FullWrapperSourceLock) {
				t.Fatalf("source mutation reached semantic validation before the lock: %v", err)
			}
		})
	}
}

func TestL8D4FullSyscallWrapperSemanticAnchors(t *testing.T) {
	payload, err := readL8D4FullWrapperLockedSource(l8D4FullWrapperSourcePath, l8D4FullWrapperSourceSHA256, nil)
	if err != nil {
		t.Fatalf("read sole live wrapper: %v", err)
	}
	source := string(payload)
	parse := func(t *testing.T, candidate string) *ast.File {
		t.Helper()
		parsed, err := parser.ParseFile(token.NewFileSet(), l8D4FullWrapperSourcePath, candidate, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse semantic-anchor fixture: %v", err)
		}
		return parsed
	}
	if err := validateL8D4FullWrapperSemanticAnchors(parse(t, source)); err != nil {
		t.Fatalf("canonical semantic anchors: %v", err)
	}
	for _, mutation := range []struct {
		name        string
		old         string
		replacement string
	}{
		{name: "exported seam", old: "type syscallExecutor interface", replacement: "type SyscallExecutor interface"},
		{name: "executor signature", old: "execute(context.Context) (syscallExecution, error)", replacement: "execute(context.Context, context.Context) (syscallExecution, error)"},
		{name: "binding source", old: "policy.NewAdapterBindings(ticket, wrapper)", replacement: "policy.NewAdapterBindings(ticket, observations)"},
		{name: "raw syscall", old: "execution, err = executor.execute(ctx)", replacement: "_, _, _ = syscall.RawSyscall(0, 0, 0, 0)\n\texecution, err = executor.execute(ctx)"},
		{name: "default callsite", old: "type syscallExecutor interface", replacement: "var _ = NewSyscallPolicyCoreKernel\n\ntype syscallExecutor interface"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := strings.Replace(source, mutation.old, mutation.replacement, 1)
			if mutated == source {
				t.Fatal("semantic-anchor mutation did not change source")
			}
			if err := validateL8D4FullWrapperSemanticAnchors(parse(t, mutated)); err == nil {
				t.Fatal("semantic anchors accepted mutation")
			}
		})
	}
}

func TestL8D4FullSyscallWrapperClosedSourceRead(t *testing.T) {
	canonical, err := readL8D4FullWrapperLockedSource(l8D4FullWrapperSourcePath, l8D4FullWrapperSourceSHA256, nil)
	if err != nil {
		t.Fatalf("read canonical wrapper: %v", err)
	}
	writeRegular := func(t *testing.T, path string, payload []byte) {
		t.Helper()
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			t.Fatalf("write locked fixture: %v", err)
		}
	}

	t.Run("stale lock", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wrapper.go")
		writeRegular(t, path, canonical)
		if _, err := readL8D4FullWrapperLockedSource(path, strings.Repeat("0", sha256.Size*2), nil); !errors.Is(err, errL8D4FullWrapperSourceLock) {
			t.Fatalf("stale source lock error = %v", err)
		}
	})

	t.Run("wrong source", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wrapper.go")
		writeRegular(t, path, []byte("wrong source bytes"))
		if _, err := readL8D4FullWrapperLockedSource(path, l8D4FullWrapperSourceSHA256, nil); !errors.Is(err, errL8D4FullWrapperSourceLock) {
			t.Fatalf("wrong source error = %v", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target.go")
		link := filepath.Join(directory, "wrapper.go")
		writeRegular(t, target, canonical)
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("create source symlink: %v", err)
		}
		if _, err := readL8D4FullWrapperLockedSource(link, l8D4FullWrapperSourceSHA256, nil); err == nil {
			t.Fatal("closed source read accepted a symlink")
		}
	})

	t.Run("nonregular", func(t *testing.T) {
		if _, err := readL8D4FullWrapperLockedSource(t.TempDir(), l8D4FullWrapperSourceSHA256, nil); err == nil {
			t.Fatal("closed source read accepted a directory")
		}
	})

	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wrapper.go")
		writeRegular(t, path, []byte(strings.Repeat("x", int(l8D4FullWrapperSourceMaximum)+1)))
		if _, err := readL8D4FullWrapperLockedSource(path, l8D4FullWrapperSourceSHA256, nil); err == nil {
			t.Fatal("closed source read exceeded its bound")
		}
	})

	t.Run("identity change", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "wrapper.go")
		replacement := filepath.Join(directory, "replacement.go")
		writeRegular(t, path, canonical)
		writeRegular(t, replacement, canonical)
		_, err := readL8D4FullWrapperLockedSource(path, l8D4FullWrapperSourceSHA256, func() error {
			return os.Rename(replacement, path)
		})
		if err == nil {
			t.Fatal("closed source read accepted a pathname identity change")
		}
	})
}

func TestL8D4FullSyscallWrapperConstructorFailsBeforeAuthority(t *testing.T) {
	observations := &wrapperObservationFake{}
	executor := &wrapperExecutorFake{}
	wrapper, decision, err := newSyscallPolicyWrapper(nil, syscallpolicy.AdapterTicket{}, observations, executor)
	var policyErr *syscallpolicy.ContractError
	if wrapper != nil || decision.Final() || !errors.As(err, &policyErr) || policyErr.Code() != syscallpolicy.ErrorCodeOwnership {
		t.Fatalf("new wrapper with absent policy = (%#v, %#v, %v)", wrapper, decision, err)
	}
	if executor.calls.Load() != 0 {
		t.Fatalf("executor calls = %d before claim", executor.calls.Load())
	}

	var typedNilObservations *wrapperObservationFake
	if wrapper, _, err := newSyscallPolicyWrapper(nil, syscallpolicy.AdapterTicket{}, typedNilObservations, executor); wrapper != nil || !errors.Is(err, credentialhelper.ErrContractTypedNil) {
		t.Fatalf("new wrapper with typed-nil observations = (%#v, %v)", wrapper, err)
	}
	var typedNilExecutor *wrapperExecutorFake
	if wrapper, _, err := newSyscallPolicyWrapper(nil, syscallpolicy.AdapterTicket{}, observations, typedNilExecutor); wrapper != nil || !errors.Is(err, credentialhelper.ErrContractTypedNil) {
		t.Fatalf("new wrapper with typed-nil executor = (%#v, %v)", wrapper, err)
	}
}

func TestL8D4FullSyscallWrapperSuccessUsesOneTerminalAndCleansObject(t *testing.T) {
	t.Run("returned object", func(t *testing.T) {
		object := &wrapperReturnedObjectFake{number: 41}
		executor := &wrapperExecutorFake{result: syscallExecution{returnedObject: object}}
		terminal := newWrapperTerminalFake()
		wrapper, permit := newClaimedWrapperForTest(true, executor, terminal)

		if _, err := wrapper.execute(context.Background()); err != nil {
			t.Fatalf("execute() error = %v", err)
		}
		assertWrapperFinalizedAndEmpty(t, wrapper)
		terminal.assertOneCall(t, wrapperTerminalPost, syscallpolicy.AdapterPhasePost, permit)
		if executor.calls.Load() != 1 || object.numberCalls.Load() != 1 || object.closes.Load() != 1 {
			t.Fatalf("executor calls = %d, object number reads = %d, object closes = %d", executor.calls.Load(), object.numberCalls.Load(), object.closes.Load())
		}
	})

	t.Run("no object", func(t *testing.T) {
		executor := &wrapperExecutorFake{}
		terminal := newWrapperTerminalFake()
		wrapper, permit := newClaimedWrapperForTest(false, executor, terminal)

		if _, err := wrapper.execute(context.Background()); err != nil {
			t.Fatalf("execute() error = %v", err)
		}
		assertWrapperFinalizedAndEmpty(t, wrapper)
		terminal.assertOneCall(t, wrapperTerminalCommit, syscallpolicy.AdapterPhasePost, permit)
		if executor.calls.Load() != 1 {
			t.Fatalf("executor calls = %d, want 1", executor.calls.Load())
		}
	})
}

func TestL8D4FullSyscallWrapperCancellationUsesExactAbortPhase(t *testing.T) {
	t.Run("nil context", func(t *testing.T) {
		executor := &wrapperExecutorFake{}
		terminal := newWrapperTerminalFake()
		wrapper, permit := newClaimedWrapperForTest(false, executor, terminal)

		if _, err := wrapper.execute(nil); !errors.Is(err, credentialhelper.ErrContractTypedNil) {
			t.Fatalf("execute() error = %v, want typed-nil context", err)
		}
		assertWrapperFinalizedAndEmpty(t, wrapper)
		terminal.assertOneCall(t, wrapperTerminalAbort, syscallpolicy.AdapterPhasePre, permit)
		if executor.calls.Load() != 0 {
			t.Fatalf("executor calls = %d, want 0", executor.calls.Load())
		}
	})

	t.Run("pre call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		executor := &wrapperExecutorFake{}
		terminal := newWrapperTerminalFake()
		wrapper, permit := newClaimedWrapperForTest(false, executor, terminal)

		if _, err := wrapper.execute(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("execute() error = %v, want context cancellation", err)
		}
		assertWrapperFinalizedAndEmpty(t, wrapper)
		terminal.assertOneCall(t, wrapperTerminalAbort, syscallpolicy.AdapterPhasePre, permit)
		if executor.calls.Load() != 0 {
			t.Fatalf("executor calls = %d, want 0", executor.calls.Load())
		}
	})

	t.Run("post call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		object := &wrapperReturnedObjectFake{number: 42}
		executor := &wrapperExecutorFake{run: func(context.Context) (syscallExecution, error) {
			cancel()
			return syscallExecution{returnedObject: object}, nil
		}}
		terminal := newWrapperTerminalFake()
		wrapper, permit := newClaimedWrapperForTest(true, executor, terminal)

		if _, err := wrapper.execute(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("execute() error = %v, want context cancellation", err)
		}
		assertWrapperFinalizedAndEmpty(t, wrapper)
		terminal.assertOneCall(t, wrapperTerminalAbort, syscallpolicy.AdapterPhasePost, permit)
		if executor.calls.Load() != 1 || object.closes.Load() != 1 {
			t.Fatalf("executor calls = %d, object closes = %d", executor.calls.Load(), object.closes.Load())
		}
	})
}

func TestL8D4FullSyscallWrapperContainsTypedNilPanicAndError(t *testing.T) {
	var typedNil *wrapperExecutorFake
	if err := syscallExecutorDependencyError(typedNil); !errors.Is(err, credentialhelper.ErrContractTypedNil) {
		t.Fatalf("typed-nil executor error = %v", err)
	}
	if err := syscallExecutorDependencyError(nil); !errors.Is(err, credentialhelper.ErrContractDependency) {
		t.Fatalf("nil executor error = %v", err)
	}

	for _, test := range []struct {
		name string
		run  func(context.Context) (syscallExecution, error)
	}{
		{name: "error", run: func(context.Context) (syscallExecution, error) {
			return syscallExecution{}, errors.New("secret executor detail")
		}},
		{name: "panic", run: func(context.Context) (syscallExecution, error) {
			panic("secret executor panic")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor := &wrapperExecutorFake{run: test.run}
			terminal := newWrapperTerminalFake()
			wrapper, permit := newClaimedWrapperForTest(false, executor, terminal)
			_, err := wrapper.execute(context.Background())
			if !errors.Is(err, credentialhelper.ErrContractDependency) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("execute() error = %v", err)
			}
			assertWrapperFinalizedAndEmpty(t, wrapper)
			terminal.assertOneCall(t, wrapperTerminalAbort, syscallpolicy.AdapterPhasePost, permit)
			if executor.calls.Load() != 1 {
				t.Fatalf("executor calls = %d, want 1", executor.calls.Load())
			}
		})
	}

	var typedNilObject *wrapperReturnedObjectFake
	executor := &wrapperExecutorFake{result: syscallExecution{returnedObject: typedNilObject}}
	terminal := newWrapperTerminalFake()
	wrapper, permit := newClaimedWrapperForTest(true, executor, terminal)
	if _, err := wrapper.execute(context.Background()); !errors.Is(err, credentialhelper.ErrContractTypedNil) {
		t.Fatalf("typed-nil object error = %v", err)
	}
	assertWrapperFinalizedAndEmpty(t, wrapper)
	terminal.assertOneCall(t, wrapperTerminalAbort, syscallpolicy.AdapterPhasePost, permit)
}

func TestL8D4FullSyscallWrapperRejectsReturnedObjectMatrixMismatch(t *testing.T) {
	for _, test := range []struct {
		name         string
		requiresPost bool
		object       *wrapperReturnedObjectFake
		wantErr      error
	}{
		{name: "missing required object", requiresPost: true, wantErr: credentialhelper.ErrContractResultMatrix},
		{name: "unexpected object", object: &wrapperReturnedObjectFake{number: 44}, wantErr: credentialhelper.ErrContractResultMatrix},
		{name: "invalid object number", requiresPost: true, object: &wrapperReturnedObjectFake{number: -1}, wantErr: credentialhelper.ErrContractInvalidArgument},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor := &wrapperExecutorFake{}
			if test.object != nil {
				executor.result.returnedObject = test.object
			}
			terminal := newWrapperTerminalFake()
			wrapper, permit := newClaimedWrapperForTest(test.requiresPost, executor, terminal)
			if _, err := wrapper.execute(context.Background()); !errors.Is(err, test.wantErr) {
				t.Fatalf("execute() error = %v, want %v", err, test.wantErr)
			}
			assertWrapperFinalizedAndEmpty(t, wrapper)
			terminal.assertOneCall(t, wrapperTerminalAbort, syscallpolicy.AdapterPhasePost, permit)
			if test.object != nil && test.object.closes.Load() != 1 {
				t.Fatalf("object closes = %d, want 1", test.object.closes.Load())
			}
		})
	}
}

func TestL8D4FullSyscallWrapperCleansReturnedObjectOnEveryConvergence(t *testing.T) {
	for _, test := range []struct {
		name          string
		executorErr   error
		terminalPanic bool
		closeErr      error
		closePanic    bool
		terminalKind  wrapperTerminalKind
	}{
		{name: "executor error with object", executorErr: errors.New("secret executor detail"), terminalKind: wrapperTerminalAbort},
		{name: "terminal error", terminalKind: wrapperTerminalPost},
		{name: "terminal panic", terminalPanic: true, terminalKind: wrapperTerminalPost},
		{name: "cleanup error", closeErr: errors.New("secret cleanup detail"), terminalKind: wrapperTerminalPost},
		{name: "cleanup panic", closePanic: true, terminalKind: wrapperTerminalPost},
	} {
		t.Run(test.name, func(t *testing.T) {
			object := &wrapperReturnedObjectFake{number: 43, closeErr: test.closeErr, closePanic: test.closePanic}
			executor := &wrapperExecutorFake{result: syscallExecution{returnedObject: object}, err: test.executorErr}
			terminal := newWrapperTerminalFake()
			terminal.panicCall = test.terminalPanic
			if test.name == "terminal error" {
				terminal.result.err = errors.New("sanitized terminal failure")
			}
			wrapper, permit := newClaimedWrapperForTest(true, executor, terminal)
			_, err := wrapper.execute(context.Background())
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("execute() error = %v", err)
			}
			assertWrapperFinalizedAndEmpty(t, wrapper)
			terminal.assertOneCall(t, test.terminalKind, syscallpolicy.AdapterPhasePost, permit)
			if object.closes.Load() != 1 {
				t.Fatalf("object closes = %d, want 1", object.closes.Load())
			}
		})
	}
}

func TestL8D4FullSyscallWrapperRejectsConcurrentReentrantAndReuse(t *testing.T) {
	t.Run("concurrent", func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		executor := &wrapperExecutorFake{run: func(context.Context) (syscallExecution, error) {
			close(started)
			<-release
			return syscallExecution{}, nil
		}}
		terminal := newWrapperTerminalFake()
		wrapper, permit := newClaimedWrapperForTest(false, executor, terminal)
		first := make(chan error, 1)
		go func() {
			_, err := wrapper.execute(context.Background())
			first <- err
		}()
		<-started

		const racers = 32
		errorsSeen := make(chan error, racers)
		var wait sync.WaitGroup
		for index := 0; index < racers; index++ {
			wait.Add(1)
			go func() {
				defer wait.Done()
				_, err := wrapper.execute(context.Background())
				errorsSeen <- err
			}()
		}
		wait.Wait()
		close(errorsSeen)
		for err := range errorsSeen {
			if !errors.Is(err, credentialhelper.ErrContractOwnership) {
				t.Errorf("concurrent execute error = %v", err)
			}
		}
		close(release)
		if err := <-first; err != nil {
			t.Fatalf("first execute error = %v", err)
		}
		assertWrapperFinalizedAndEmpty(t, wrapper)
		terminal.assertOneCall(t, wrapperTerminalCommit, syscallpolicy.AdapterPhasePost, permit)
		if executor.calls.Load() != 1 {
			t.Fatalf("executor calls = %d, want 1", executor.calls.Load())
		}
	})

	t.Run("reentrant and reuse", func(t *testing.T) {
		terminal := newWrapperTerminalFake()
		inner := make(chan error, 1)
		var wrapper *syscallPolicyWrapper
		executor := &wrapperExecutorFake{run: func(context.Context) (syscallExecution, error) {
			_, err := wrapper.execute(context.Background())
			inner <- err
			return syscallExecution{}, nil
		}}
		var permit syscallPermit
		wrapper, permit = newClaimedWrapperForTest(false, executor, terminal)
		if _, err := wrapper.execute(context.Background()); err != nil {
			t.Fatalf("outer execute error = %v", err)
		}
		if err := <-inner; !errors.Is(err, credentialhelper.ErrContractOwnership) {
			t.Fatalf("reentrant execute error = %v", err)
		}
		if _, err := wrapper.execute(context.Background()); !errors.Is(err, credentialhelper.ErrContractOwnership) {
			t.Fatalf("reuse error = %v", err)
		}
		assertWrapperFinalizedAndEmpty(t, wrapper)
		terminal.assertOneCall(t, wrapperTerminalCommit, syscallpolicy.AdapterPhasePost, permit)
		if executor.calls.Load() != 1 {
			t.Fatalf("executor calls = %d, want 1", executor.calls.Load())
		}
	})
}

func TestL8D4FullSyscallWrapperHasNoRawBypass(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		payload, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		wrapperReferences := strings.Count(string(payload), "newSyscallPolicyWrapper")
		if name == "syscall_policy_wrapper_linux.go" {
			if wrapperReferences != 1 {
				t.Errorf("%s wrapper constructor spellings = %d, want sole declaration", name, wrapperReferences)
			}
		} else if wrapperReferences != 0 {
			t.Errorf("%s connects the default-off wrapper", name)
		}
		for _, rawMarker := range []string{"syscall.", "unix.", "RawSyscall", "//go:linkname"} {
			if strings.Contains(string(payload), rawMarker) {
				t.Errorf("%s contains raw syscall authority marker %q", name, rawMarker)
			}
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, payload, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if ok && (identifier.Name == "syscall" || identifier.Name == "unix") && strings.HasPrefix(selector.Sel.Name, "Syscall") {
				t.Errorf("%s contains raw syscall bypass %s.%s", name, identifier.Name, selector.Sel.Name)
			}
			return true
		})
	}
}

func readL8D4FullWrapperLockedSource(path, expectedSHA256 string, afterOpen func() error) (payload []byte, err error) {
	if len(expectedSHA256) != sha256.Size*2 || strings.ToLower(expectedSHA256) != expectedSHA256 {
		return nil, fmt.Errorf("%w: malformed digest", errL8D4FullWrapperSourceLock)
	}
	if _, decodeErr := hex.DecodeString(expectedSHA256); decodeErr != nil {
		return nil, fmt.Errorf("%w: malformed digest", errL8D4FullWrapperSourceLock)
	}
	initial, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat locked wrapper: %w", err)
	}
	if initial.Mode()&os.ModeSymlink != 0 || !initial.Mode().IsRegular() ||
		initial.Size() <= 0 || initial.Size() > l8D4FullWrapperSourceMaximum {
		return nil, errors.New("locked wrapper is not one bounded regular file")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open locked wrapper without following links: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open locked wrapper returned no file")
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			payload = nil
			err = fmt.Errorf("close locked wrapper: %w", closeErr)
		}
	}()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened wrapper: %w", err)
	}
	if !opened.Mode().IsRegular() || opened.Size() <= 0 ||
		opened.Size() > l8D4FullWrapperSourceMaximum || !os.SameFile(initial, opened) {
		return nil, errors.New("locked wrapper changed identity or bounds before read")
	}
	if afterOpen != nil {
		if err := afterOpen(); err != nil {
			return nil, fmt.Errorf("locked wrapper identity hook: %w", err)
		}
	}
	payload, err = io.ReadAll(io.LimitReader(file, l8D4FullWrapperSourceMaximum+1))
	if err != nil {
		return nil, fmt.Errorf("read locked wrapper: %w", err)
	}
	if int64(len(payload)) != opened.Size() || int64(len(payload)) > l8D4FullWrapperSourceMaximum {
		return nil, errors.New("locked wrapper changed size while being read")
	}
	afterRead, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("reinspect opened wrapper: %w", err)
	}
	if !afterRead.Mode().IsRegular() || afterRead.Size() != opened.Size() || !os.SameFile(opened, afterRead) {
		return nil, errors.New("locked wrapper descriptor identity changed while being read")
	}
	current, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("reinspect locked wrapper path: %w", err)
	}
	if current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) {
		return nil, errors.New("locked wrapper pathname identity changed while being read")
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != expectedSHA256 {
		return nil, fmt.Errorf("%w: wrapper bytes changed", errL8D4FullWrapperSourceLock)
	}
	return payload, nil
}

// validateL8D4FullSyscallWrapperSource rejects unlocked bytes before checking
// the compact semantic anchors.
func validateL8D4FullSyscallWrapperSource(source string) error {
	digest := sha256.Sum256([]byte(source))
	if hex.EncodeToString(digest[:]) != l8D4FullWrapperSourceSHA256 {
		return errL8D4FullWrapperSourceLock
	}
	if !strings.HasPrefix(source, "//go:build linux && amd64 && l8_d4_full_syscall_adapter\n") {
		return errors.New("locked wrapper build constraint changed")
	}
	if strings.Contains(source, "//go:linkname") {
		return errors.New("locked wrapper reached linkname authority")
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), l8D4FullWrapperSourcePath, source, parser.ParseComments)
	if err != nil {
		return err
	}
	return validateL8D4FullWrapperSemanticAnchors(parsed)
}

func validateL8D4FullWrapperSemanticAnchors(parsed *ast.File) error {
	if parsed == nil || parsed.Name == nil || parsed.Name.Name != "linux" {
		return errors.New("locked wrapper left its package")
	}
	var forbiddenAuthority error
	ast.Inspect(parsed, func(node ast.Node) bool {
		if forbiddenAuthority != nil {
			return false
		}
		if identifier, ok := node.(*ast.Ident); ok && identifier.Name == "NewSyscallPolicyCoreKernel" {
			forbiddenAuthority = errors.New("locked wrapper connected the unavailable default constructor")
			return false
		}
		if selector, ok := node.(*ast.SelectorExpr); ok {
			switch selector.Sel.Name {
			case "Syscall", "Syscall6", "RawSyscall", "RawSyscall6":
				forbiddenAuthority = errors.New("locked wrapper reached raw syscall authority")
				return false
			}
		}
		if call, ok := node.(*ast.CallExpr); ok {
			if identifier, ok := call.Fun.(*ast.Ident); ok && identifier.Name == "newSyscallPolicyWrapper" {
				forbiddenAuthority = errors.New("locked wrapper connected a default callsite")
				return false
			}
		}
		return true
	})
	if forbiddenAuthority != nil {
		return forbiddenAuthority
	}
	for _, imported := range parsed.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return errors.New("locked wrapper has a malformed import")
		}
		switch path {
		case "syscall", "unsafe", "golang.org/x/sys/unix":
			return errors.New("locked wrapper imported raw syscall authority")
		}
	}
	expectedFunctions := map[string]string{
		"newSyscallPolicyWrapper":                       "(*syscallpolicy.Policy,syscallpolicy.AdapterTicket,syscallPolicyObservations,syscallExecutor)->(*syscallPolicyWrapper,syscallpolicy.AdapterDecision,error)",
		"*syscallPolicyWrapper.execute":                 "(context.Context)->(syscallpolicy.AdapterDecision,error)",
		"*d2SyscallPolicyTerminal.abortPermit":          "(syscallPermit,syscallpolicy.AdapterPhase)->(syscallTerminalResult)",
		"*d2SyscallPolicyTerminal.authorizePost":        "(syscallPermit,syscallpolicy.PostObservationSource)->(syscallTerminalResult)",
		"*d2SyscallPolicyTerminal.commitNoObject":       "(syscallPermit)->(syscallTerminalResult)",
		"executeSyscallSafely":                          "(context.Context,syscallExecutor)->(syscallExecution,error)",
		"callTerminalSafely":                            "(func()->(syscallTerminalResult))->(syscallTerminalResult)",
		"*syscallPolicyWrapper.ObserveBinding":          "(syscallpolicy.BindingQuery)->(syscallpolicy.BindingObservation,error)",
		"*syscallPolicyWrapper.ObserveState":            "(syscallpolicy.StateQuery)->(syscallpolicy.StateObservation,error)",
		"*syscallPolicyWrapper.ObserveFD":               "(syscallpolicy.FDQuery)->(syscallpolicy.FDObservation,error)",
		"*syscallPolicyWrapper.ObservePointer":          "(syscallpolicy.PointerQuery)->(syscallpolicy.PointerObservation,error)",
		"*syscallPolicyWrapper.ObserveObject":           "(syscallpolicy.ObjectQuery)->(syscallpolicy.ObjectObservation,error)",
		"*syscallPostObservationSource.ReinspectObject": "(syscallpolicy.ObjectQuery)->(syscallpolicy.ObjectObservation,error)",
	}
	allowedExportedMethods := map[string]bool{
		"*syscallPolicyWrapper.ObserveBinding":          true,
		"*syscallPolicyWrapper.ObserveState":            true,
		"*syscallPolicyWrapper.ObserveFD":               true,
		"*syscallPolicyWrapper.ObservePointer":          true,
		"*syscallPolicyWrapper.ObserveObject":           true,
		"*syscallPostObservationSource.ReinspectObject": true,
	}
	expectedCalls := map[string]int{
		"newSyscallPolicyWrapper|policy.NewAdapterBindings(ticket,wrapper)":                         1,
		"newSyscallPolicyWrapper|policy.AuthorizePre(ticket,wrapper.bindings,wrapper)":              1,
		"*d2SyscallPolicyTerminal.abortPermit|terminal.policy.AbortPermit(permit.value,phase)":      1,
		"*d2SyscallPolicyTerminal.authorizePost|terminal.policy.AuthorizePost(permit.value,source)": 1,
		"*d2SyscallPolicyTerminal.commitNoObject|terminal.policy.CommitNoObject(permit.value)":      1,
		"executeSyscallSafely|executor.execute(ctx)":                                                1,
		"*syscallPolicyWrapper.execute|terminal.abortPermit(permit,syscallpolicy.AdapterPhasePre)":  1,
		"*syscallPolicyWrapper.execute|terminal.abortPermit(permit,syscallpolicy.AdapterPhasePost)": 6,
		"*syscallPolicyWrapper.execute|terminal.authorizePost(permit,postSource)":                   1,
		"*syscallPolicyWrapper.execute|terminal.commitNoObject(permit)":                             1,
	}
	guardedSelectors := map[string]bool{
		"NewAdapterBindings": true,
		"AuthorizePre":       true,
		"AbortPermit":        true,
		"AuthorizePost":      true,
		"CommitNoObject":     true,
		"execute":            true,
		"abortPermit":        true,
		"authorizePost":      true,
		"commitNoObject":     true,
	}
	functionCounts := make(map[string]int)
	callCounts := make(map[string]int)
	executorInterfaces := 0
	for _, declaration := range parsed.Decls {
		switch declaration := declaration.(type) {
		case *ast.FuncDecl:
			owner := l8D4FullWrapperAnchorFunctionKey(declaration)
			if declaration.Name.IsExported() && !allowedExportedMethods[owner] {
				return errors.New("locked wrapper exported new authority")
			}
			if expected, ok := expectedFunctions[owner]; ok {
				if l8D4FullWrapperAnchorFunctionSignature(declaration.Type) != expected {
					return fmt.Errorf("locked wrapper changed signature for %s", owner)
				}
				functionCounts[owner]++
			}
			if err := l8D4FullWrapperCollectAnchorCalls(declaration, owner, guardedSelectors, expectedCalls, callCounts); err != nil {
				return err
			}
		case *ast.GenDecl:
			for _, specification := range declaration.Specs {
				switch specification := specification.(type) {
				case *ast.TypeSpec:
					if specification.Name.IsExported() {
						return errors.New("locked wrapper exported a type")
					}
					if specification.Name.Name == "syscallExecutor" {
						executorInterfaces++
						if !l8D4FullWrapperExactExecutorInterface(specification.Type) {
							return errors.New("locked wrapper changed its executor seam")
						}
					}
				case *ast.ValueSpec:
					for _, name := range specification.Names {
						if name.IsExported() {
							return errors.New("locked wrapper exported a value")
						}
					}
				}
			}
		}
	}
	if executorInterfaces != 1 {
		return errors.New("locked wrapper must have one private executor seam")
	}
	for owner := range expectedFunctions {
		if functionCounts[owner] != 1 {
			return fmt.Errorf("locked wrapper lost exact owner %s", owner)
		}
	}
	for call, expected := range expectedCalls {
		if callCounts[call] != expected {
			return fmt.Errorf("locked wrapper changed direct lifecycle call %s", call)
		}
	}
	return nil
}

func l8D4FullWrapperCollectAnchorCalls(function *ast.FuncDecl, owner string, guardedSelectors map[string]bool, expectedCalls map[string]int, callCounts map[string]int) error {
	if function == nil || function.Body == nil {
		return nil
	}
	var anchorErr error
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if anchorErr != nil {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !guardedSelectors[selector.Sel.Name] {
			return true
		}
		key := owner + "|" + l8D4FullWrapperAnchorCallShape(call)
		if _, approved := expectedCalls[key]; !approved {
			anchorErr = errors.New("locked wrapper changed a direct lifecycle call")
			return false
		}
		callCounts[key]++
		return true
	})
	return anchorErr
}

func l8D4FullWrapperExactExecutorInterface(expression ast.Expr) bool {
	executor, ok := expression.(*ast.InterfaceType)
	if !ok || executor.Methods == nil || len(executor.Methods.List) != 1 {
		return false
	}
	method := executor.Methods.List[0]
	function, ok := method.Type.(*ast.FuncType)
	return ok && len(method.Names) == 1 && method.Names[0].Name == "execute" &&
		l8D4FullWrapperAnchorFunctionSignature(function) == "(context.Context)->(syscallExecution,error)"
}

func l8D4FullWrapperAnchorFunctionKey(function *ast.FuncDecl) string {
	if function == nil {
		return ""
	}
	if function.Recv == nil || len(function.Recv.List) != 1 {
		return function.Name.Name
	}
	return l8D4FullWrapperAnchorTypeShape(function.Recv.List[0].Type) + "." + function.Name.Name
}

func l8D4FullWrapperAnchorFunctionSignature(function *ast.FuncType) string {
	if function == nil {
		return ""
	}
	return "(" + l8D4FullWrapperAnchorFieldShapes(function.Params) + ")->(" + l8D4FullWrapperAnchorFieldShapes(function.Results) + ")"
}

func l8D4FullWrapperAnchorFieldShapes(fields *ast.FieldList) string {
	if fields == nil {
		return ""
	}
	var shapes []string
	for _, field := range fields.List {
		count := len(field.Names)
		if count == 0 {
			count = 1
		}
		for index := 0; index < count; index++ {
			shapes = append(shapes, l8D4FullWrapperAnchorTypeShape(field.Type))
		}
	}
	return strings.Join(shapes, ",")
}

func l8D4FullWrapperAnchorCallShape(call *ast.CallExpr) string {
	if call == nil {
		return ""
	}
	arguments := make([]string, 0, len(call.Args))
	for _, argument := range call.Args {
		arguments = append(arguments, l8D4FullWrapperAnchorTypeShape(argument))
	}
	return l8D4FullWrapperAnchorTypeShape(call.Fun) + "(" + strings.Join(arguments, ",") + ")"
}

func l8D4FullWrapperAnchorTypeShape(expression ast.Expr) string {
	switch expression := expression.(type) {
	case *ast.Ident:
		return expression.Name
	case *ast.SelectorExpr:
		return l8D4FullWrapperAnchorTypeShape(expression.X) + "." + expression.Sel.Name
	case *ast.StarExpr:
		return "*" + l8D4FullWrapperAnchorTypeShape(expression.X)
	case *ast.FuncType:
		return "func" + l8D4FullWrapperAnchorFunctionSignature(expression)
	}
	return ""
}

type wrapperExecutorFake struct {
	calls  atomic.Int32
	result syscallExecution
	err    error
	run    func(context.Context) (syscallExecution, error)
}

type wrapperObservationFake struct{}

func (*wrapperObservationFake) ObserveBinding(syscallpolicy.BindingQuery) (syscallpolicy.BindingObservation, error) {
	return syscallpolicy.BindingObservation{}, nil
}

func (*wrapperObservationFake) ObserveState(syscallpolicy.StateQuery) (syscallpolicy.StateObservation, error) {
	return syscallpolicy.StateObservation{}, nil
}

func (*wrapperObservationFake) ObserveFD(syscallpolicy.FDQuery) (syscallpolicy.FDObservation, error) {
	return syscallpolicy.FDObservation{}, nil
}

func (*wrapperObservationFake) ObservePointer(syscallpolicy.PointerQuery) (syscallpolicy.PointerObservation, error) {
	return syscallpolicy.PointerObservation{}, nil
}

func (*wrapperObservationFake) ObserveObject(syscallpolicy.ObjectQuery) (syscallpolicy.ObjectObservation, error) {
	return syscallpolicy.ObjectObservation{}, nil
}

func (executor *wrapperExecutorFake) execute(ctx context.Context) (syscallExecution, error) {
	executor.calls.Add(1)
	if executor.run != nil {
		return executor.run(ctx)
	}
	return executor.result, executor.err
}

type wrapperReturnedObjectFake struct {
	number      int32
	numberCalls atomic.Int32
	closes      atomic.Int32
	closeErr    error
	closePanic  bool
}

func (object *wrapperReturnedObjectFake) numberValue() int32 {
	object.numberCalls.Add(1)
	return object.number
}

func (object *wrapperReturnedObjectFake) inspectObject(syscallpolicy.ObjectQuery) (syscallObjectInspection, error) {
	return syscallObjectInspection{}, nil
}

func (object *wrapperReturnedObjectFake) closeObject() error {
	object.closes.Add(1)
	if object.closePanic {
		panic("secret cleanup panic")
	}
	return object.closeErr
}

type wrapperTerminalKind uint8

const (
	wrapperTerminalAbort wrapperTerminalKind = 1 + iota
	wrapperTerminalPost
	wrapperTerminalCommit
)

type wrapperTerminalCall struct {
	kind   wrapperTerminalKind
	phase  syscallpolicy.AdapterPhase
	permit syscallPermit
}

type wrapperTerminalFake struct {
	mu        sync.Mutex
	calls     []wrapperTerminalCall
	result    syscallTerminalResult
	panicCall bool
}

func newWrapperTerminalFake() *wrapperTerminalFake {
	return &wrapperTerminalFake{result: syscallTerminalResult{valid: true}}
}

func (terminal *wrapperTerminalFake) abortPermit(permit syscallPermit, phase syscallpolicy.AdapterPhase) syscallTerminalResult {
	return terminal.record(wrapperTerminalCall{kind: wrapperTerminalAbort, phase: phase, permit: permit})
}

func (terminal *wrapperTerminalFake) authorizePost(permit syscallPermit, source syscallpolicy.PostObservationSource) syscallTerminalResult {
	if source == nil {
		return syscallTerminalResult{err: credentialhelper.ErrContractTypedNil, valid: true}
	}
	return terminal.record(wrapperTerminalCall{kind: wrapperTerminalPost, phase: syscallpolicy.AdapterPhasePost, permit: permit})
}

func (terminal *wrapperTerminalFake) commitNoObject(permit syscallPermit) syscallTerminalResult {
	return terminal.record(wrapperTerminalCall{kind: wrapperTerminalCommit, phase: syscallpolicy.AdapterPhasePost, permit: permit})
}

func (terminal *wrapperTerminalFake) record(call wrapperTerminalCall) syscallTerminalResult {
	terminal.mu.Lock()
	terminal.calls = append(terminal.calls, call)
	result, panicCall := terminal.result, terminal.panicCall
	terminal.mu.Unlock()
	if panicCall {
		panic("secret terminal panic")
	}
	return result
}

func (terminal *wrapperTerminalFake) assertOneCall(t *testing.T, kind wrapperTerminalKind, phase syscallpolicy.AdapterPhase, permit syscallPermit) {
	t.Helper()
	terminal.mu.Lock()
	defer terminal.mu.Unlock()
	if len(terminal.calls) != 1 {
		t.Fatalf("terminal calls = %#v, want exactly one", terminal.calls)
	}
	call := terminal.calls[0]
	if call.kind != kind || call.phase != phase || call.permit.identity != permit.identity || call.permit.requiresPost != permit.requiresPost {
		t.Fatalf("terminal call = %#v, want kind=%v phase=%v same permit", call, kind, phase)
	}
}

func newClaimedWrapperForTest(requiresPost bool, executor syscallExecutor, terminal syscallPolicyTerminal) (*syscallPolicyWrapper, syscallPermit) {
	permit := syscallPermit{identity: &syscallPermitIdentity{}, requiresPost: requiresPost}
	return &syscallPolicyWrapper{
		state:    wrapperStateClaimed,
		permit:   permit,
		executor: executor,
		terminal: terminal,
	}, permit
}

func assertWrapperFinalizedAndEmpty(t *testing.T, wrapper *syscallPolicyWrapper) {
	t.Helper()
	wrapper.mu.Lock()
	defer wrapper.mu.Unlock()
	if wrapper.state != wrapperStateFinalized {
		t.Fatalf("wrapper state = %v, want finalized", wrapper.state)
	}
	if wrapper.observations != nil || wrapper.bindings.SHA256() != ([32]byte{}) || wrapper.permit.identity != nil || wrapper.permit.value.SHA256() != ([32]byte{}) || wrapper.executor != nil || wrapper.terminal != nil {
		t.Fatalf("finalized wrapper retained authority or object dependency")
	}
}
