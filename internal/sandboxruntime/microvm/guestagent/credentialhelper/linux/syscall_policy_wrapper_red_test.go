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
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := strings.Replace(source, mutation.old, mutation.replacement, 1)
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
	selectorCalls := make(map[string]int)
	identifierCalls := make(map[string]int)
	identifierRefs := make(map[string]int)
	callShapes := make(map[string]int)
	exportedTypes := 0
	exportedFunctions := 0
	var executorInterfaces []*ast.InterfaceType
	for _, declaration := range parsed.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.IsExported() && function.Recv == nil {
			exportedFunctions++
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
	ast.Inspect(parsed, func(node ast.Node) bool {
		if identifier, ok := node.(*ast.Ident); ok {
			identifierRefs[identifier.Name]++
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch function := call.Fun.(type) {
		case *ast.SelectorExpr:
			selectorCalls[function.Sel.Name]++
		case *ast.Ident:
			identifierCalls[function.Name]++
		}
		callShapes[l8D4FullWrapperCallShape(call)]++
		return true
	})
	if len(executorInterfaces) != 1 || !l8D4ExactSyscallExecutorInterface(executorInterfaces[0]) {
		return errors.New("live wrapper must contain one exact private one-method executor")
	}
	for name, want := range map[string]int{
		"NewAdapterBindings": 1,
		"AuthorizePre":       1,
		"AbortPermit":        1,
		"AuthorizePost":      1,
		"CommitNoObject":     1,
		"execute":            1,
	} {
		if selectorCalls[name] != want {
			return errors.New("live wrapper must contain each concrete D2/executor call exactly once")
		}
	}
	for _, callShape := range []string{
		"policy.NewAdapterBindings(ticket,wrapper)",
		"policy.AuthorizePre(ticket,wrapper.bindings,wrapper)",
		"terminal.policy.AbortPermit(permit.value,phase)",
		"terminal.policy.AuthorizePost(permit.value,source)",
		"terminal.policy.CommitNoObject(permit.value)",
		"executor.execute(ctx)",
	} {
		if callShapes[callShape] != 1 {
			return errors.New("live wrapper changed an exact D2 or executor call")
		}
	}
	for _, forbidden := range []string{"Syscall", "Syscall6", "RawSyscall", "RawSyscall6", "EmbeddedVerifiedPolicyArtifact", "EmbeddedExpectedPinnedCallsiteEvidence"} {
		if selectorCalls[forbidden] != 0 {
			return errors.New("live wrapper reached forbidden raw or issuer authority")
		}
	}
	if identifierCalls["NewSyscallPolicyCoreKernel"] != 0 || identifierRefs["NewSyscallPolicyCoreKernel"] != 0 || exportedTypes != 0 || exportedFunctions != 0 {
		return errors.New("live wrapper escaped or connected default-off authority")
	}
	cleanupIndex := strings.LastIndex(source, "cleanupErr := closeReturnedObjectSafely(object)")
	finalizeIndex := strings.LastIndex(source, "wrapper.finishLocked()")
	if cleanupIndex < 0 || finalizeIndex < cleanupIndex {
		return errors.New("live wrapper must clean returned objects before convergence")
	}
	return nil
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
