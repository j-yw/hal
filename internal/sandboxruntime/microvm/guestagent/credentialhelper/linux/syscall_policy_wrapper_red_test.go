//go:build linux && l8_d4_full_syscall_adapter

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
		"//go:build linux && l8_d4_full_syscall_adapter",
		"type syscallExecutor interface",
		"execute(context.Context) (syscallExecution, error)",
		"type wrapperState uint8",
		"wrapperStateUnstarted wrapperState = 1",
		"wrapperStateClaimed wrapperState = 2",
		"wrapperStateExecuted wrapperState = 3",
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
	for _, declaration := range parsed.Decls {
		switch declaration := declaration.(type) {
		case *ast.FuncDecl:
			if declaration.Name.IsExported() {
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
		if executor.calls.Load() != 1 || object.closes.Load() != 1 {
			t.Fatalf("executor calls = %d, object closes = %d", executor.calls.Load(), object.closes.Load())
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

func TestL8D4FullSyscallWrapperCleansReturnedObjectOnEveryConvergence(t *testing.T) {
	for _, test := range []struct {
		name          string
		terminalPanic bool
		closeErr      error
		closePanic    bool
	}{
		{name: "terminal error"},
		{name: "terminal panic", terminalPanic: true},
		{name: "cleanup error", closeErr: errors.New("secret cleanup detail")},
		{name: "cleanup panic", closePanic: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			object := &wrapperReturnedObjectFake{number: 43, closeErr: test.closeErr, closePanic: test.closePanic}
			executor := &wrapperExecutorFake{result: syscallExecution{returnedObject: object}}
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
			terminal.assertOneCall(t, wrapperTerminalPost, syscallpolicy.AdapterPhasePost, permit)
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
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
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

type wrapperExecutorFake struct {
	calls  atomic.Int32
	result syscallExecution
	err    error
	run    func(context.Context) (syscallExecution, error)
}

func (executor *wrapperExecutorFake) execute(ctx context.Context) (syscallExecution, error) {
	executor.calls.Add(1)
	if executor.run != nil {
		return executor.run(ctx)
	}
	return executor.result, executor.err
}

type wrapperReturnedObjectFake struct {
	number     int32
	closes     atomic.Int32
	closeErr   error
	closePanic bool
}

func (object *wrapperReturnedObjectFake) numberValue() int32 { return object.number }

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
	if wrapper.permit.identity != nil || wrapper.permit.value.SHA256() != ([32]byte{}) || wrapper.executor != nil || wrapper.terminal != nil {
		t.Fatalf("finalized wrapper retained authority or object dependency")
	}
}
