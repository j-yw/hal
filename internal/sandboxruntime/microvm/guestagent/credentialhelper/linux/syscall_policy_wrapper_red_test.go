//go:build linux && amd64 && l8_d4_full_syscall_adapter

package linux

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
)

func TestL8D4FullSyscallWrapperSourceContract(t *testing.T) {
	payload, err := os.ReadFile("syscall_policy_wrapper_linux.go")
	if err != nil {
		t.Fatalf("read sole live wrapper: %v", err)
	}
	text := string(payload)
	for _, marker := range []string{
		"//go:build linux && amd64 && l8_d4_full_syscall_adapter",
		"type syscallExecutor interface",
		"execute(context.Context) (syscallExecution, error)",
		"type wrapperState uint8",
		"wrapperStateUnstarted wrapperState = 1",
		"wrapperStateClaimed   wrapperState = 2",
		"wrapperStateExecuted  wrapperState = 3",
		"wrapperStateFinalized wrapperState = 4",
		"NewAdapterBindings",
		"AuthorizePre",
		"AuthorizePost",
		"CommitNoObject",
		"AbortPermit",
		"newPostObservationSource",
	} {
		if !strings.Contains(text, marker) {
			t.Errorf("sole live wrapper lacks %q", marker)
		}
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), "syscall_policy_wrapper_linux.go", payload, 0)
	if err != nil {
		t.Fatalf("parse sole live wrapper: %v", err)
	}
	allowedInterfaceMethods := map[string]bool{
		"ObserveBinding":  true,
		"ObserveState":    true,
		"ObserveFD":       true,
		"ObservePointer":  true,
		"ObserveObject":   true,
		"ReinspectObject": true,
	}
	for _, declaration := range parsed.Decls {
		switch declaration := declaration.(type) {
		case *ast.FuncDecl:
			if declaration.Name.IsExported() && (declaration.Recv == nil || !allowedInterfaceMethods[declaration.Name.Name]) {
				t.Errorf("live wrapper exports function or method %s", declaration.Name.Name)
			}
		case *ast.GenDecl:
			for _, specification := range declaration.Specs {
				typeSpec, ok := specification.(*ast.TypeSpec)
				if ok && typeSpec.Name.IsExported() {
					t.Errorf("live wrapper exports type %s", typeSpec.Name.Name)
				}
			}
		}
	}
	if err := validateL8D4FullSyscallWrapperSource(string(payload)); err != nil {
		t.Fatal(err)
	}
}

func TestL8D4FullSyscallWrapperSourceGuardRejectsMutations(t *testing.T) {
	payload, err := os.ReadFile("syscall_policy_wrapper_linux.go")
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
			}
		})
	}
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

func validateL8D4FullSyscallWrapperSource(source string) error {
	if !strings.HasPrefix(source, "//go:build linux && amd64 && l8_d4_full_syscall_adapter\n") {
		return errors.New("live wrapper must remain Linux/amd64/tag gated")
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), "syscall_policy_wrapper_linux.go", source, 0)
	if err != nil {
		return err
	}
	identifierRefs := make(map[string]int)
	callShapes := make(map[string]int)
	exportedTypes := 0
	exportedFunctions := 0
	var executorInterfaces []*ast.InterfaceType
	var executeMethods []*ast.FuncDecl
	var callTerminalSafelyFunctions []*ast.FuncDecl
	for _, declaration := range parsed.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok {
			if function.Name.IsExported() && function.Recv == nil {
				exportedFunctions++
			}
			if function.Name.Name == "execute" && l8D4FullWrapperReceiverShape(function) == "*syscallPolicyWrapper" {
				executeMethods = append(executeMethods, function)
			}
			if function.Name.Name == "callTerminalSafely" && function.Recv == nil {
				callTerminalSafelyFunctions = append(callTerminalSafelyFunctions, function)
			}
		}
		generation, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, specification := range generation.Specs {
			typeSpec, ok := specification.(*ast.TypeSpec)
			if !ok {
				continue
			}
			if typeSpec.Name.IsExported() {
				exportedTypes++
			}
			if typeSpec.Name.Name == "syscallExecutor" {
				if executorInterface, ok := typeSpec.Type.(*ast.InterfaceType); ok {
					executorInterfaces = append(executorInterfaces, executorInterface)
				}
			}
		}
	}
	expectedGuardedCalls := map[string]int{
		"policy.NewAdapterBindings(ticket,wrapper)":                   1,
		"policy.AuthorizePre(ticket,wrapper.bindings,wrapper)":        1,
		"terminal.policy.AbortPermit(permit.value,phase)":             1,
		"terminal.policy.AuthorizePost(permit.value,source)":          1,
		"terminal.policy.CommitNoObject(permit.value)":                1,
		"executor.execute(ctx)":                                       1,
		"terminal.abortPermit(permit,syscallpolicy.AdapterPhasePre)":  1,
		"terminal.abortPermit(permit,syscallpolicy.AdapterPhasePost)": 6,
		"terminal.authorizePost(permit,postSource)":                   1,
		"terminal.commitNoObject(permit)":                             1,
		"wrapper.finishLocked()":                                      2,
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
		"finishLocked":       true,
	}
	parents := l8D4FullWrapperParentMap(parsed)
	approvedSelectorReferences := make(map[*ast.SelectorExpr]bool)
	selectorReferences := make(map[string]int)
	ast.Inspect(parsed, func(node ast.Node) bool {
		if identifier, ok := node.(*ast.Ident); ok {
			identifierRefs[identifier.Name]++
		}
		if selector, ok := node.(*ast.SelectorExpr); ok {
			selectorReferences[selector.Sel.Name]++
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		shape := l8D4FullWrapperCallShape(call)
		callShapes[shape]++
		if selector, direct := call.Fun.(*ast.SelectorExpr); direct && expectedGuardedCalls[shape] != 0 && l8D4FullWrapperGuardedCallContext(call, parents) {
			approvedSelectorReferences[selector] = true
		}
		return true
	})
	if len(executorInterfaces) != 1 || !l8D4ExactSyscallExecutorInterface(executorInterfaces[0]) {
		return errors.New("live wrapper must contain one exact private one-method executor")
	}
	if len(callTerminalSafelyFunctions) != 1 || !l8D4ExactCallTerminalSafely(callTerminalSafelyFunctions[0]) {
		return errors.New("live wrapper terminal callback may escape its immediate invocation")
	}
	for callShape, want := range expectedGuardedCalls {
		if callShapes[callShape] != want {
			return errors.New("live wrapper changed an exact D2 or executor call")
		}
	}
	var unapprovedSelector bool
	ast.Inspect(parsed, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if ok && guardedSelectors[selector.Sel.Name] && !approvedSelectorReferences[selector] {
			unapprovedSelector = true
		}
		return true
	})
	if unapprovedSelector {
		return errors.New("live wrapper stores or aliases guarded D2 or executor authority")
	}
	for _, forbidden := range []string{"Syscall", "Syscall6", "RawSyscall", "RawSyscall6", "EmbeddedVerifiedPolicyArtifact", "EmbeddedExpectedPinnedCallsiteEvidence"} {
		if selectorReferences[forbidden] != 0 {
			return errors.New("live wrapper reached forbidden raw or issuer authority")
		}
	}
	if identifierRefs["NewSyscallPolicyCoreKernel"] != 0 || exportedTypes != 0 || exportedFunctions != 0 {
		return errors.New("live wrapper escaped or connected default-off authority")
	}
	if len(executeMethods) != 1 || validateL8D4FullWrapperConvergence(executeMethods[0]) != nil {
		return errors.New("live wrapper changed its mutually exclusive finalization paths")
	}
	return nil
}

func l8D4FullWrapperGuardedCallContext(call *ast.CallExpr, parents map[ast.Node]ast.Node) bool {
	shape := l8D4FullWrapperCallShape(call)
	owner, insideLiteral := l8D4FullWrapperCallOwner(call, parents)
	ownerShape := l8D4FullWrapperFunctionShape(owner)
	switch shape {
	case "policy.NewAdapterBindings(ticket,wrapper)":
		return !insideLiteral && ownerShape == "newSyscallPolicyWrapper" && l8D4FullWrapperDirectAssignment(call, parents, owner, "bindings,err", token.DEFINE)
	case "policy.AuthorizePre(ticket,wrapper.bindings,wrapper)":
		return !insideLiteral && ownerShape == "newSyscallPolicyWrapper" && l8D4FullWrapperDirectAssignment(call, parents, owner, "permit,pre,err", token.DEFINE)
	case "terminal.policy.AbortPermit(permit.value,phase)":
		return !insideLiteral && ownerShape == "*d2SyscallPolicyTerminal.abortPermit" && l8D4FullWrapperDirectAssignment(call, parents, owner, "decision,err", token.DEFINE)
	case "terminal.policy.AuthorizePost(permit.value,source)":
		return !insideLiteral && ownerShape == "*d2SyscallPolicyTerminal.authorizePost" && l8D4FullWrapperDirectAssignment(call, parents, owner, "decision,err", token.DEFINE)
	case "terminal.policy.CommitNoObject(permit.value)":
		return !insideLiteral && ownerShape == "*d2SyscallPolicyTerminal.commitNoObject" && l8D4FullWrapperDirectAssignment(call, parents, owner, "decision,err", token.DEFINE)
	case "executor.execute(ctx)":
		return !insideLiteral && ownerShape == "executeSyscallSafely" && l8D4FullWrapperDirectAssignment(call, parents, owner, "execution,err", token.ASSIGN)
	case "terminal.abortPermit(permit,syscallpolicy.AdapterPhasePre)":
		return insideLiteral && ownerShape == "*syscallPolicyWrapper.execute" && l8D4FullWrapperImmediateTerminalCallback(call, parents, token.DEFINE)
	case "terminal.abortPermit(permit,syscallpolicy.AdapterPhasePost)",
		"terminal.authorizePost(permit,postSource)",
		"terminal.commitNoObject(permit)":
		return insideLiteral && ownerShape == "*syscallPolicyWrapper.execute" && l8D4FullWrapperImmediateTerminalCallback(call, parents, token.ASSIGN)
	case "wrapper.finishLocked()":
		_, directStatement := parents[call].(*ast.ExprStmt)
		return !insideLiteral && ownerShape == "*syscallPolicyWrapper.execute" && directStatement
	default:
		return false
	}
}

func l8D4FullWrapperParentMap(root ast.Node) map[ast.Node]ast.Node {
	parents := make(map[ast.Node]ast.Node)
	var stack []ast.Node
	ast.Inspect(root, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) != 0 {
			parents[node] = stack[len(stack)-1]
		}
		stack = append(stack, node)
		return true
	})
	return parents
}

func l8D4FullWrapperCallOwner(call *ast.CallExpr, parents map[ast.Node]ast.Node) (*ast.FuncDecl, bool) {
	insideLiteral := false
	for node := parents[call]; node != nil; node = parents[node] {
		switch node := node.(type) {
		case *ast.FuncLit:
			insideLiteral = true
		case *ast.FuncDecl:
			return node, insideLiteral
		}
	}
	return nil, insideLiteral
}

func l8D4FullWrapperFunctionShape(function *ast.FuncDecl) string {
	if function == nil {
		return ""
	}
	receiver := l8D4FullWrapperReceiverShape(function)
	if receiver == "" {
		return function.Name.Name
	}
	return receiver + "." + function.Name.Name
}

func l8D4FullWrapperDirectAssignment(call *ast.CallExpr, parents map[ast.Node]ast.Node, owner *ast.FuncDecl, left string, operator token.Token) bool {
	assignment, ok := parents[call].(*ast.AssignStmt)
	if !ok || assignment.Tok != operator || len(assignment.Rhs) != 1 || assignment.Rhs[0] != call || l8D4FullWrapperExpressionListShape(assignment.Lhs) != left {
		return false
	}
	block, ok := parents[assignment].(*ast.BlockStmt)
	return ok && owner != nil && block == owner.Body
}

func l8D4FullWrapperImmediateTerminalCallback(call *ast.CallExpr, parents map[ast.Node]ast.Node, operator token.Token) bool {
	result, ok := parents[call].(*ast.ReturnStmt)
	if !ok || len(result.Results) != 1 || result.Results[0] != call {
		return false
	}
	body, ok := parents[result].(*ast.BlockStmt)
	if !ok || len(body.List) != 1 || body.List[0] != result {
		return false
	}
	literal, ok := parents[body].(*ast.FuncLit)
	if !ok || literal.Body != body || l8D4FullWrapperFieldShapes(literal.Type.Params) != "" || l8D4FullWrapperFieldShapes(literal.Type.Results) != "syscallTerminalResult" {
		return false
	}
	protectedCall, ok := parents[literal].(*ast.CallExpr)
	if !ok || l8D4FullWrapperExpressionShape(protectedCall.Fun) != "callTerminalSafely" || len(protectedCall.Args) != 1 || protectedCall.Args[0] != literal {
		return false
	}
	assignment, ok := parents[protectedCall].(*ast.AssignStmt)
	return ok && assignment.Tok == operator && len(assignment.Lhs) == 1 && l8D4FullWrapperExpressionShape(assignment.Lhs[0]) == "terminalResult" && len(assignment.Rhs) == 1 && assignment.Rhs[0] == protectedCall
}

func l8D4ExactCallTerminalSafely(function *ast.FuncDecl) bool {
	if function == nil || function.Type == nil || function.Body == nil ||
		l8D4FullWrapperFieldNameShapes(function.Type.Params) != "call:func" ||
		!l8D4ExactTerminalCallbackParameter(function.Type.Params) ||
		l8D4FullWrapperFieldNameShapes(function.Type.Results) != "result:syscallTerminalResult" ||
		len(function.Body.List) != 2 {
		return false
	}
	deferred, ok := function.Body.List[0].(*ast.DeferStmt)
	if !ok || deferred.Call == nil || len(deferred.Call.Args) != 0 {
		return false
	}
	if _, ok := deferred.Call.Fun.(*ast.FuncLit); !ok {
		return false
	}
	result, ok := function.Body.List[1].(*ast.ReturnStmt)
	if !ok || len(result.Results) != 1 {
		return false
	}
	call, ok := result.Results[0].(*ast.CallExpr)
	if !ok || l8D4FullWrapperCallShape(call) != "call()" {
		return false
	}
	callReferences := 0
	ast.Inspect(function.Body, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if ok && identifier.Name == "call" {
			callReferences++
		}
		return true
	})
	return callReferences == 1
}

func l8D4ExactTerminalCallbackParameter(fields *ast.FieldList) bool {
	if fields == nil || len(fields.List) != 1 || len(fields.List[0].Names) != 1 || fields.List[0].Names[0].Name != "call" {
		return false
	}
	function, ok := fields.List[0].Type.(*ast.FuncType)
	return ok && l8D4FullWrapperFieldShapes(function.Params) == "" && l8D4FullWrapperFieldShapes(function.Results) == "syscallTerminalResult"
}

func l8D4FullWrapperFieldNameShapes(fields *ast.FieldList) string {
	if fields == nil {
		return ""
	}
	var shapes []string
	for _, field := range fields.List {
		if len(field.Names) == 0 {
			shapes = append(shapes, ":"+l8D4FullWrapperExpressionShape(field.Type))
			continue
		}
		for _, name := range field.Names {
			shapes = append(shapes, name.Name+":"+l8D4FullWrapperExpressionShape(field.Type))
		}
	}
	return strings.Join(shapes, ",")
}

func l8D4FullWrapperExpressionListShape(expressions []ast.Expr) string {
	shapes := make([]string, 0, len(expressions))
	for _, expression := range expressions {
		shapes = append(shapes, l8D4FullWrapperExpressionShape(expression))
	}
	return strings.Join(shapes, ",")
}

func validateL8D4FullWrapperConvergence(execute *ast.FuncDecl) error {
	if execute == nil || execute.Body == nil || len(execute.Body.List) < 7 {
		return errors.New("live wrapper execute body is unavailable")
	}
	statements := execute.Body.List
	terminalSwitch, ok := statements[len(statements)-7].(*ast.SwitchStmt)
	if !ok || !l8D4FullWrapperTerminalSwitchAssignsEveryPath(terminalSwitch) {
		return errors.New("live wrapper terminal selection must precede convergence")
	}
	if l8D4FullWrapperAssignedCallShape(statements[len(statements)-6]) != "checkedTerminalResult(terminalResult)" ||
		l8D4FullWrapperAssignedCallShape(statements[len(statements)-5]) != "closeReturnedObjectSafely(object)" ||
		l8D4FullWrapperStatementCallShape(statements[len(statements)-4]) != "wrapper.mu.Lock()" ||
		l8D4FullWrapperStatementCallShape(statements[len(statements)-3]) != "wrapper.finishLocked()" ||
		l8D4FullWrapperStatementCallShape(statements[len(statements)-2]) != "wrapper.mu.Unlock()" ||
		l8D4FullWrapperReturnShape(statements[len(statements)-1]) != "decision,joinWrapperErrors(primaryErr,terminalErr,cleanupErr)" {
		return errors.New("live wrapper must terminalize, clean, and then finalize")
	}

	var finishCalls, preAbortCalls, postAbortCalls, postCalls, commitCalls []*ast.CallExpr
	ast.Inspect(execute.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch l8D4FullWrapperCallShape(call) {
		case "wrapper.finishLocked()":
			finishCalls = append(finishCalls, call)
		case "terminal.abortPermit(permit,syscallpolicy.AdapterPhasePre)":
			preAbortCalls = append(preAbortCalls, call)
		case "terminal.abortPermit(permit,syscallpolicy.AdapterPhasePost)":
			postAbortCalls = append(postAbortCalls, call)
		case "terminal.authorizePost(permit,postSource)":
			postCalls = append(postCalls, call)
		case "terminal.commitNoObject(permit)":
			commitCalls = append(commitCalls, call)
		}
		return true
	})
	if len(finishCalls) != 2 || len(preAbortCalls) != 1 || len(postAbortCalls) != 6 || len(postCalls) != 1 || len(commitCalls) != 1 {
		return errors.New("live wrapper finalization or terminal call count changed")
	}
	postFinish := l8D4FullWrapperStatementCall(statements[len(statements)-3])
	if postFinish == nil || finishCalls[1] != postFinish || !l8D4FullWrapperCallsWithin(terminalSwitch, postAbortCalls, postCalls, commitCalls) {
		return errors.New("live wrapper post-execution convergence escaped its terminal switch")
	}

	var preAbortBranch *ast.IfStmt
	for _, statement := range statements[:len(statements)-7] {
		branch, ok := statement.(*ast.IfStmt)
		if ok && l8D4FullWrapperNodesWithin(branch, preAbortCalls[0], finishCalls[0]) {
			if preAbortBranch != nil {
				return errors.New("live wrapper has multiple pre-abort finalization branches")
			}
			preAbortBranch = branch
		}
	}
	if preAbortBranch == nil || preAbortBranch.Else != nil || l8D4FullWrapperConditionShape(preAbortBranch.Cond) != "ctxErr!=nil" || len(preAbortBranch.Body.List) != 5 {
		return errors.New("live wrapper pre-abort finalization branch is unavailable")
	}
	if !l8D4FullWrapperTerminalResultAssignment(preAbortBranch.Body.List[0]) ||
		l8D4FullWrapperAssignedCallShape(preAbortBranch.Body.List[1]) != "checkedTerminalResult(terminalResult)" ||
		l8D4FullWrapperStatementCallShape(preAbortBranch.Body.List[2]) != "wrapper.finishLocked()" ||
		l8D4FullWrapperStatementCallShape(preAbortBranch.Body.List[3]) != "wrapper.mu.Unlock()" ||
		l8D4FullWrapperReturnShape(preAbortBranch.Body.List[4]) != "decision,joinWrapperErrors(ctxErr,terminalErr)" ||
		preAbortBranch.End() >= terminalSwitch.Pos() {
		return errors.New("live wrapper pre-abort path must return before post-execution terminalization")
	}
	return nil
}

func l8D4FullWrapperTerminalSwitchAssignsEveryPath(terminalSwitch *ast.SwitchStmt) bool {
	if terminalSwitch == nil || terminalSwitch.Init != nil || terminalSwitch.Tag != nil || terminalSwitch.Body == nil || len(terminalSwitch.Body.List) != 7 {
		return false
	}
	simpleCases, splitCases := 0, 0
	for _, statement := range terminalSwitch.Body.List {
		clause, ok := statement.(*ast.CaseClause)
		if !ok || len(clause.Body) == 0 {
			return false
		}
		last := clause.Body[len(clause.Body)-1]
		if l8D4FullWrapperTerminalResultAssignment(last) {
			simpleCases++
			continue
		}
		branch, ok := last.(*ast.IfStmt)
		elseBlock, elseOK := branchElseBlock(branch)
		if !ok || !elseOK || branch.Body == nil || len(branch.Body.List) == 0 || len(elseBlock.List) == 0 ||
			!l8D4FullWrapperTerminalResultAssignment(branch.Body.List[len(branch.Body.List)-1]) ||
			!l8D4FullWrapperTerminalResultAssignment(elseBlock.List[len(elseBlock.List)-1]) {
			return false
		}
		splitCases++
	}
	return simpleCases == 6 && splitCases == 1
}

func branchElseBlock(branch *ast.IfStmt) (*ast.BlockStmt, bool) {
	if branch == nil {
		return nil, false
	}
	block, ok := branch.Else.(*ast.BlockStmt)
	return block, ok
}

func l8D4FullWrapperTerminalResultAssignment(statement ast.Stmt) bool {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 || l8D4FullWrapperExpressionShape(assignment.Lhs[0]) != "terminalResult" {
		return false
	}
	call, ok := assignment.Rhs[0].(*ast.CallExpr)
	return ok && l8D4FullWrapperExpressionShape(call.Fun) == "callTerminalSafely" && len(call.Args) == 1
}

func l8D4FullWrapperConditionShape(expression ast.Expr) string {
	binary, ok := expression.(*ast.BinaryExpr)
	if !ok {
		return l8D4FullWrapperExpressionShape(expression)
	}
	return l8D4FullWrapperExpressionShape(binary.X) + binary.Op.String() + l8D4FullWrapperExpressionShape(binary.Y)
}

func l8D4FullWrapperReceiverShape(function *ast.FuncDecl) string {
	if function == nil || function.Recv == nil || len(function.Recv.List) != 1 {
		return ""
	}
	return l8D4FullWrapperExpressionShape(function.Recv.List[0].Type)
}

func l8D4FullWrapperAssignedCallShape(statement ast.Stmt) string {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok || len(assignment.Rhs) != 1 {
		return ""
	}
	call, _ := assignment.Rhs[0].(*ast.CallExpr)
	return l8D4FullWrapperCallShape(call)
}

func l8D4FullWrapperStatementCall(statement ast.Stmt) *ast.CallExpr {
	expression, ok := statement.(*ast.ExprStmt)
	if !ok {
		return nil
	}
	call, _ := expression.X.(*ast.CallExpr)
	return call
}

func l8D4FullWrapperStatementCallShape(statement ast.Stmt) string {
	return l8D4FullWrapperCallShape(l8D4FullWrapperStatementCall(statement))
}

func l8D4FullWrapperReturnShape(statement ast.Stmt) string {
	result, ok := statement.(*ast.ReturnStmt)
	if !ok {
		return ""
	}
	shapes := make([]string, 0, len(result.Results))
	for _, expression := range result.Results {
		if call, ok := expression.(*ast.CallExpr); ok {
			shapes = append(shapes, l8D4FullWrapperCallShape(call))
		} else {
			shapes = append(shapes, l8D4FullWrapperExpressionShape(expression))
		}
	}
	return strings.Join(shapes, ",")
}

func l8D4FullWrapperNodesWithin(parent ast.Node, children ...ast.Node) bool {
	if parent == nil {
		return false
	}
	for _, child := range children {
		if child == nil || child.Pos() < parent.Pos() || child.End() > parent.End() {
			return false
		}
	}
	return true
}

func l8D4FullWrapperCallsWithin(parent ast.Node, groups ...[]*ast.CallExpr) bool {
	for _, group := range groups {
		for _, call := range group {
			if !l8D4FullWrapperNodesWithin(parent, call) {
				return false
			}
		}
	}
	return true
}

func l8D4ExactSyscallExecutorInterface(executor *ast.InterfaceType) bool {
	if executor == nil || executor.Methods == nil || len(executor.Methods.List) != 1 {
		return false
	}
	method := executor.Methods.List[0]
	function, ok := method.Type.(*ast.FuncType)
	return ok && len(method.Names) == 1 && method.Names[0].Name == "execute" &&
		l8D4FullWrapperFieldShapes(function.Params) == "context.Context" &&
		l8D4FullWrapperFieldShapes(function.Results) == "syscallExecution,error"
}

func l8D4FullWrapperFieldShapes(fields *ast.FieldList) string {
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
			shapes = append(shapes, l8D4FullWrapperExpressionShape(field.Type))
		}
	}
	return strings.Join(shapes, ",")
}

func l8D4FullWrapperCallShape(call *ast.CallExpr) string {
	if call == nil {
		return ""
	}
	arguments := make([]string, 0, len(call.Args))
	for _, argument := range call.Args {
		arguments = append(arguments, l8D4FullWrapperExpressionShape(argument))
	}
	return l8D4FullWrapperExpressionShape(call.Fun) + "(" + strings.Join(arguments, ",") + ")"
}

func l8D4FullWrapperExpressionShape(expression ast.Expr) string {
	switch expression := expression.(type) {
	case *ast.Ident:
		return expression.Name
	case *ast.SelectorExpr:
		return l8D4FullWrapperExpressionShape(expression.X) + "." + expression.Sel.Name
	case *ast.StarExpr:
		return "*" + l8D4FullWrapperExpressionShape(expression.X)
	case *ast.FuncType:
		return "func"
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
