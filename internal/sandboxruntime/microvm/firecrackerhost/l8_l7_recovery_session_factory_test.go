package firecrackerhost

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
)

func TestProductionL7RecoverySessionFactoryRejectsMissingDependencies(t *testing.T) {
	valid := productionL7RecoverySessionFactoryOptionsForTest(t)
	if factory, err := NewProductionL7RecoverySessionFactory(valid); factory == nil || err != nil {
		t.Fatalf("complete factory = %#v, %v", factory, err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*ProductionL7RecoverySessionFactoryOptions)
	}{
		{name: "missing recovery", mutate: func(o *ProductionL7RecoverySessionFactoryOptions) { o.Recovery = nil }},
		{name: "typed-nil recovery", mutate: func(o *ProductionL7RecoverySessionFactoryOptions) {
			var recovery *l7RecoverySessionFactoryTopology
			o.Recovery = recovery
		}},
		{name: "missing TAP", mutate: func(o *ProductionL7RecoverySessionFactoryOptions) { o.TAP = nil }},
		{name: "typed-nil TAP", mutate: func(o *ProductionL7RecoverySessionFactoryOptions) {
			var tap *l7network.LinuxTAP
			o.TAP = tap
		}},
		{name: "missing rules", mutate: func(o *ProductionL7RecoverySessionFactoryOptions) { o.Rules = nil }},
		{name: "typed-nil rules", mutate: func(o *ProductionL7RecoverySessionFactoryOptions) {
			var rules *l7RecoverySessionFactoryRules
			o.Rules = rules
		}},
		{name: "missing journal and state dir", mutate: func(o *ProductionL7RecoverySessionFactoryOptions) {
			o.Journal = nil
			o.StateDir = ""
		}},
		{name: "relative state dir", mutate: func(o *ProductionL7RecoverySessionFactoryOptions) {
			o.Journal = nil
			o.StateDir = "relative-journal"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := productionL7RecoverySessionFactoryOptionsForTest(t)
			test.mutate(&options)
			factory, err := NewProductionL7RecoverySessionFactory(options)
			if factory != nil || !errors.Is(err, l7network.ErrInvalidConfiguration) {
				t.Fatalf("NewProductionL7RecoverySessionFactory() = %#v, %v, want ErrInvalidConfiguration", factory, err)
			}
		})
	}

	if options, err := (*ProductionL7RecoverySessionFactory)(nil).ReconcilerOptions(); options != (l7network.ReconcilerOptions{}) || !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("nil factory options = %#v, %v", options, err)
	}
}

func TestProductionL7RecoverySessionFactoryBuildsCompleteReconcilerOptions(t *testing.T) {
	factory, err := NewProductionL7RecoverySessionFactory(productionL7RecoverySessionFactoryOptionsForTest(t))
	if err != nil {
		t.Fatalf("NewProductionL7RecoverySessionFactory: %v", err)
	}
	options, err := factory.ReconcilerOptions()
	if err != nil {
		t.Fatalf("ReconcilerOptions: %v", err)
	}
	if interfaceValueIsNil(options.Recovery) || interfaceValueIsNil(options.TAP) || interfaceValueIsNil(options.Rules) ||
		interfaceValueIsNil(options.VMTermination) || (interfaceValueIsNil(options.Journal) && options.StateDir == "") {
		t.Fatalf("incomplete recovered options = %#v", options)
	}
	if reflect.TypeOf(options.VMTermination) != reflect.TypeOf(l7network.NewRecoveredVMTerminationVerifier()) {
		t.Fatalf("VMTermination type = %T, want recovered verifier", options.VMTermination)
	}
	reconciler, err := l7network.NewReconciler(options)
	if err != nil || reconciler == nil {
		t.Fatalf("NewReconciler(factory options) = %#v, %v", reconciler, err)
	}
}

func TestL8RuntimeOwnerRecoveryBindingFinalizeUsesProductionL7SessionFactory(t *testing.T) {
	if !l8RuntimeOwnerPlatformSupported() {
		t.Skip("Linux-only recovery binding")
	}
	seed := l8RuntimeOwnerTestSeed()
	now := seed.IssuedAt.Add(time.Minute)
	record := l8RuntimeOwnerTestRecord(t, seed, "01234567-89ab-cdef-0123-456789abcdef")
	record.State, record.ControllerState = "absent", "controlled"
	binding, store := l8RuntimeOwnerTestRecoveryBinding(t, record, nil)
	binding.now = func() time.Time { return now }
	options := productionL7RecoverySessionFactoryOptionsForTest(t)
	stateDir := options.StateDir
	factory, err := NewProductionL7RecoverySessionFactory(options)
	if err != nil {
		t.Fatal(err)
	}
	binding.l7SessionFactory = factory
	proof, err := sandboxruntime.NewJobCredentialRuntimeAbsenceProof(sandboxruntime.JobCredentialRuntimeAbsenceProofInput{
		Seed: seed, AbsenceInspectedAt: seed.IssuedAt.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := binding.FinalizeJobCredentialRuntimeRecovery(context.Background(), proof)
	if receipt != (sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt{}) || !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("factory finalize without durable L7 journal = %#v, %v", receipt, err)
	}
	if store.record.State != "finalizing" {
		t.Fatalf("factory finalize state = %#v", store.record)
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	foundSandboxJournal := false
	for _, entry := range entries {
		if entry.Name() == seed.SandboxID {
			foundSandboxJournal = true
			break
		}
	}
	if !foundSandboxJournal {
		t.Fatalf("complete factory options did not reach L7 Recover journal acquire in %s: %#v", stateDir, namesOf(entries))
	}

	incomplete := &l8RuntimeOwnerRecoveryBinding{
		seed: seed, commitKey: bytes32("0123456789abcdef0123456789abcdef"),
		store: store, now: func() time.Time { return now },
		currentBootID:    func() (string, error) { return record.HostBootID, nil },
		l7SessionFactory: &ProductionL7RecoverySessionFactory{},
	}
	store.transitions = nil
	if _, err := incomplete.FinalizeJobCredentialRuntimeRecovery(context.Background(), proof); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("incomplete factory finalize = %v", err)
	}
}

func TestProductionL7RecoverySessionFactoryRemainsDefaultOff(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", "..", ".."))
	set := token.NewFileSet()
	callers := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.HasSuffix(filepath.ToSlash(path), "microvm/firecrackerhost/l8_l7_recovery_session_factory.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(set, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch function := call.Fun.(type) {
			case *ast.Ident:
				name = function.Name
			case *ast.SelectorExpr:
				name = function.Sel.Name
			}
			if name == "NewProductionL7RecoverySessionFactory" {
				callers++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if callers != 0 {
		t.Fatalf("production NewProductionL7RecoverySessionFactory callers = %d, want zero", callers)
	}

	for _, name := range []string{"adapter.go", "live_driver.go", "l7_live_composition.go", "l8_job_credential_runtime.go"} {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(source), "NewProductionL7RecoverySessionFactory") {
			t.Fatalf("%s wires production L7 recovery session factory", name)
		}
	}
	runtimeSource, err := os.ReadFile("l8_job_credential_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(runtimeSource), "l7network.NewReconciler") {
		t.Fatal("NewProductionL8JobCredentialRuntime production file calls l7network.NewReconciler")
	}
}

func productionL7RecoverySessionFactoryOptionsForTest(t *testing.T) ProductionL7RecoverySessionFactoryOptions {
	t.Helper()
	tap, err := l7network.NewLinuxTAP(l7network.TAPOptions{
		IPPath: "/usr/sbin/ip", SysctlPath: "/usr/sbin/sysctl", NsenterPath: "/usr/bin/nsenter",
		Command: l7RecoverySessionFactoryCommand{},
	})
	if err != nil {
		t.Fatalf("NewLinuxTAP: %v", err)
	}
	return ProductionL7RecoverySessionFactoryOptions{
		Recovery: &l7RecoverySessionFactoryTopology{},
		TAP:      tap,
		Rules:    &l7RecoverySessionFactoryRules{},
		StateDir: t.TempDir(),
	}
}

func namesOf(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

type l7RecoverySessionFactoryCommand struct{}

func (l7RecoverySessionFactoryCommand) Run(context.Context, l7network.NamespaceLease, l7network.NamespaceCommandRequest, int64) ([]byte, error) {
	return nil, errors.New("fake TAP command unused")
}

type l7RecoverySessionFactoryTopology struct{}

func (*l7RecoverySessionFactoryTopology) Recover(context.Context, l7network.Identity) (l7network.TopologyLifecycle, l7network.TopologySession, error) {
	return nil, nil, l7network.ErrStaleTopologyUnverified
}

type l7RecoverySessionFactoryRules struct{}

func (*l7RecoverySessionFactoryRules) ApplyAndInspect(context.Context, linuxrules.ExpectedRuleSet) (networkenforcement.RuleLifecycleMetadata, error) {
	return networkenforcement.RuleLifecycleMetadata{}, nil
}

func (*l7RecoverySessionFactoryRules) Inspect(context.Context, linuxrules.ExpectedRuleSet) (networkenforcement.RuleLifecycleMetadata, error) {
	return networkenforcement.RuleLifecycleMetadata{}, nil
}

func (*l7RecoverySessionFactoryRules) Quarantine(context.Context, linuxrules.ExpectedRuleSet) error {
	return nil
}

func (*l7RecoverySessionFactoryRules) Cleanup(context.Context, linuxrules.ExpectedRuleSet) error {
	return nil
}
