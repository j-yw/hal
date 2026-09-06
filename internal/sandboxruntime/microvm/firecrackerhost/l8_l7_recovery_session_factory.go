package firecrackerhost

import (
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
)

// ProductionL7RecoverySessionFactoryOptions is explicit constructor input for
// the default-off Finalize L7 recovery session factory. Callers inject journal,
// TAP, rules, and recovery topology. The factory always attaches the recovered
// VM-termination verifier and never invents missing adapters.
type ProductionL7RecoverySessionFactoryOptions struct {
	Recovery l7network.RecoveryTopology
	TAP      l7network.TAPLifecycle
	Rules    l7network.RuleAdapter
	Journal  l7network.JournalStore
	StateDir string
}

// ProductionL7RecoverySessionFactory builds complete l7network.ReconcilerOptions
// for same-boot Finalize cleanup. It is never invoked by sandboxd, hal run,
// hal auto, factory, worker Service, or NewProductionL8JobCredentialRuntime
// unless a caller injects it into a recovery binding.
type ProductionL7RecoverySessionFactory struct {
	options l7network.ReconcilerOptions
}

// NewProductionL7RecoverySessionFactory constructs complete recovered
// ReconcilerOptions. Missing or typed-nil dependencies fail closed.
func NewProductionL7RecoverySessionFactory(input ProductionL7RecoverySessionFactoryOptions) (*ProductionL7RecoverySessionFactory, error) {
	options := l7network.ReconcilerOptions{
		Recovery:      input.Recovery,
		TAP:           input.TAP,
		Rules:         input.Rules,
		Journal:       input.Journal,
		StateDir:      input.StateDir,
		VMTermination: l7network.NewRecoveredVMTerminationVerifier(),
	}
	if _, err := l7network.NewReconciler(options); err != nil {
		return nil, err
	}
	return &ProductionL7RecoverySessionFactory{options: options}, nil
}

// ReconcilerOptions returns a copy of the complete recovered options for
// Finalize. A nil factory fails closed without constructing a reconciler.
func (factory *ProductionL7RecoverySessionFactory) ReconcilerOptions() (l7network.ReconcilerOptions, error) {
	if factory == nil || interfaceValueIsNil(factory.options.Recovery) || interfaceValueIsNil(factory.options.TAP) ||
		interfaceValueIsNil(factory.options.Rules) || interfaceValueIsNil(factory.options.VMTermination) {
		return l7network.ReconcilerOptions{}, errL8RuntimeOwnerInvalid
	}
	if interfaceValueIsNil(factory.options.Journal) && factory.options.StateDir == "" {
		return l7network.ReconcilerOptions{}, l7network.ErrInvalidConfiguration
	}
	options := factory.options
	options.VMTermination = l7network.NewRecoveredVMTerminationVerifier()
	return options, nil
}
