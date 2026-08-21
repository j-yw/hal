//go:build linux && amd64 && l8_d4_full_syscall_adapter

package linux

import (
	"context"
	"errors"
	"reflect"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
)

type syscallExecutor interface {
	execute(context.Context) (syscallExecution, error)
}

type syscallExecution struct {
	returnedObject syscallReturnedObject
}

type syscallReturnedObject interface {
	numberValue() int32
	inspectObject(syscallpolicy.ObjectQuery) (syscallObjectInspection, error)
	closeObject() error
}

type syscallObjectInspection struct {
	kind             syscallpolicy.DescriptorKind
	access           syscallpolicy.DescriptorAccess
	generationSHA256 [32]byte
	checks           syscallpolicy.CheckSet
	fixed            bool
}

type syscallPolicyObservations interface {
	syscallpolicy.BindingSource
	syscallpolicy.PreObservationSource
}

type wrapperState uint8

const (
	wrapperStateUnstarted wrapperState = 1
	wrapperStateClaimed   wrapperState = 2
	wrapperStateExecuted  wrapperState = 3
	wrapperStateFinalized wrapperState = 4
)

type syscallPermitIdentity struct{ marker byte }

type syscallPermit struct {
	value        syscallpolicy.AdapterPermit
	identity     *syscallPermitIdentity
	requiresPost bool
}

type syscallTerminalResult struct {
	decision syscallpolicy.AdapterDecision
	err      error
	valid    bool
}

type syscallPolicyTerminal interface {
	abortPermit(syscallPermit, syscallpolicy.AdapterPhase) syscallTerminalResult
	authorizePost(syscallPermit, syscallpolicy.PostObservationSource) syscallTerminalResult
	commitNoObject(syscallPermit) syscallTerminalResult
}

type d2SyscallPolicyTerminal struct {
	policy *syscallpolicy.Policy
}

func (terminal *d2SyscallPolicyTerminal) abortPermit(permit syscallPermit, phase syscallpolicy.AdapterPhase) syscallTerminalResult {
	if !validSyscallPermit(permit) {
		return syscallTerminalResult{err: credentialhelper.ErrContractOwnership, valid: true}
	}
	decision, err := terminal.policy.AbortPermit(permit.value, phase)
	return syscallTerminalResult{decision: decision, err: err, valid: err != nil || decision.Final()}
}

func (terminal *d2SyscallPolicyTerminal) authorizePost(permit syscallPermit, source syscallpolicy.PostObservationSource) syscallTerminalResult {
	if !validSyscallPermit(permit) || !permit.requiresPost {
		return syscallTerminalResult{err: credentialhelper.ErrContractOwnership, valid: true}
	}
	decision, err := terminal.policy.AuthorizePost(permit.value, source)
	return syscallTerminalResult{decision: decision, err: err, valid: err != nil || decision.Final()}
}

func (terminal *d2SyscallPolicyTerminal) commitNoObject(permit syscallPermit) syscallTerminalResult {
	if !validSyscallPermit(permit) || permit.requiresPost {
		return syscallTerminalResult{err: credentialhelper.ErrContractOwnership, valid: true}
	}
	decision, err := terminal.policy.CommitNoObject(permit.value)
	return syscallTerminalResult{decision: decision, err: err, valid: err != nil || decision.Final()}
}

type syscallPolicyWrapper struct {
	mu           sync.Mutex
	state        wrapperState
	observations syscallPolicyObservations
	bindings     syscallpolicy.AdapterBindings
	permit       syscallPermit
	executor     syscallExecutor
	terminal     syscallPolicyTerminal
}

func newSyscallPolicyWrapper(
	policy *syscallpolicy.Policy,
	ticket syscallpolicy.AdapterTicket,
	observations syscallPolicyObservations,
	executor syscallExecutor,
) (*syscallPolicyWrapper, syscallpolicy.AdapterDecision, error) {
	if err := syscallExecutorDependencyError(executor); err != nil {
		return nil, syscallpolicy.AdapterDecision{}, err
	}
	if err := syscallObservationDependencyError(observations); err != nil {
		return nil, syscallpolicy.AdapterDecision{}, err
	}

	wrapper := &syscallPolicyWrapper{
		state:        wrapperStateUnstarted,
		observations: observations,
	}
	bindings, err := policy.NewAdapterBindings(ticket, wrapper)
	if err != nil {
		wrapper.destroyUnstarted()
		return nil, syscallpolicy.AdapterDecision{}, err
	}
	if bindings.SHA256() == ([32]byte{}) {
		wrapper.destroyUnstarted()
		return nil, syscallpolicy.AdapterDecision{}, credentialhelper.ErrContractOwnership
	}
	wrapper.bindings = bindings

	permit, pre, err := policy.AuthorizePre(ticket, wrapper.bindings, wrapper)
	if err != nil {
		wrapper.destroyUnstarted()
		return nil, pre, err
	}
	if !pre.Ready() {
		wrapper.destroyUnstarted()
		if !pre.Final() {
			return nil, syscallpolicy.AdapterDecision{}, credentialhelper.ErrContractResultMatrix
		}
		return nil, pre, nil
	}
	if permit.SHA256() == ([32]byte{}) || permit.PermitCorrelationSHA256() == ([32]byte{}) {
		wrapper.destroyUnstarted()
		return nil, syscallpolicy.AdapterDecision{}, credentialhelper.ErrContractOwnership
	}

	wrapper.observations = nil
	wrapper.permit = syscallPermit{
		value:        permit,
		identity:     &syscallPermitIdentity{},
		requiresPost: permit.RequiresPost(),
	}
	wrapper.executor = executor
	wrapper.terminal = &d2SyscallPolicyTerminal{policy: policy}
	wrapper.state = wrapperStateClaimed
	return wrapper, pre, nil
}

func (wrapper *syscallPolicyWrapper) execute(ctx context.Context) (syscallpolicy.AdapterDecision, error) {
	if wrapper == nil {
		return syscallpolicy.AdapterDecision{}, credentialhelper.ErrContractOwnership
	}
	ctxErr := syscallContextError(ctx)

	wrapper.mu.Lock()
	if wrapper.state != wrapperStateClaimed || wrapper.permit.identity == nil || wrapper.executor == nil || wrapper.terminal == nil {
		wrapper.mu.Unlock()
		return syscallpolicy.AdapterDecision{}, credentialhelper.ErrContractOwnership
	}
	permit, terminal := wrapper.permit, wrapper.terminal
	if ctxErr != nil {
		terminalResult := callTerminalSafely(func() syscallTerminalResult {
			return terminal.abortPermit(permit, syscallpolicy.AdapterPhasePre)
		})
		decision, terminalErr := checkedTerminalResult(terminalResult)
		wrapper.finishLocked()
		wrapper.mu.Unlock()
		return decision, joinWrapperErrors(ctxErr, terminalErr)
	}
	wrapper.state = wrapperStateExecuted
	executor := wrapper.executor
	wrapper.mu.Unlock()

	execution, executionErr := executeSyscallSafely(ctx, executor)
	object, returnedObjectNumber, objectErr := checkedReturnedObject(execution.returnedObject)
	if executionErr == nil && objectErr == nil {
		ctxErr = syscallContextError(ctx)
	}

	var terminalResult syscallTerminalResult
	var primaryErr error
	switch {
	case executionErr != nil:
		primaryErr = credentialhelper.ErrContractDependency
		terminalResult = callTerminalSafely(func() syscallTerminalResult {
			return terminal.abortPermit(permit, syscallpolicy.AdapterPhasePost)
		})
	case objectErr != nil:
		primaryErr = objectErr
		terminalResult = callTerminalSafely(func() syscallTerminalResult {
			return terminal.abortPermit(permit, syscallpolicy.AdapterPhasePost)
		})
	case ctxErr != nil:
		primaryErr = ctxErr
		terminalResult = callTerminalSafely(func() syscallTerminalResult {
			return terminal.abortPermit(permit, syscallpolicy.AdapterPhasePost)
		})
	case permit.requiresPost && object == nil:
		primaryErr = credentialhelper.ErrContractResultMatrix
		terminalResult = callTerminalSafely(func() syscallTerminalResult {
			return terminal.abortPermit(permit, syscallpolicy.AdapterPhasePost)
		})
	case !permit.requiresPost && object != nil:
		primaryErr = credentialhelper.ErrContractResultMatrix
		terminalResult = callTerminalSafely(func() syscallTerminalResult {
			return terminal.abortPermit(permit, syscallpolicy.AdapterPhasePost)
		})
	case permit.requiresPost:
		postSource, err := newPostObservationSource(permit, object, returnedObjectNumber)
		if err != nil {
			primaryErr = err
			terminalResult = callTerminalSafely(func() syscallTerminalResult {
				return terminal.abortPermit(permit, syscallpolicy.AdapterPhasePost)
			})
		} else {
			terminalResult = callTerminalSafely(func() syscallTerminalResult {
				return terminal.authorizePost(permit, postSource)
			})
		}
	default:
		terminalResult = callTerminalSafely(func() syscallTerminalResult {
			return terminal.commitNoObject(permit)
		})
	}

	decision, terminalErr := checkedTerminalResult(terminalResult)
	cleanupErr := closeReturnedObjectSafely(object)
	wrapper.mu.Lock()
	wrapper.finishLocked()
	wrapper.mu.Unlock()
	return decision, joinWrapperErrors(primaryErr, terminalErr, cleanupErr)
}

func (wrapper *syscallPolicyWrapper) ObserveBinding(query syscallpolicy.BindingQuery) (syscallpolicy.BindingObservation, error) {
	observations := wrapper.constructionObservations()
	if observations == nil {
		return syscallpolicy.BindingObservation{}, credentialhelper.ErrContractOwnership
	}
	return observations.ObserveBinding(query)
}

func (wrapper *syscallPolicyWrapper) ObserveState(query syscallpolicy.StateQuery) (syscallpolicy.StateObservation, error) {
	observations := wrapper.constructionObservations()
	if observations == nil {
		return syscallpolicy.StateObservation{}, credentialhelper.ErrContractOwnership
	}
	return observations.ObserveState(query)
}

func (wrapper *syscallPolicyWrapper) ObserveFD(query syscallpolicy.FDQuery) (syscallpolicy.FDObservation, error) {
	observations := wrapper.constructionObservations()
	if observations == nil {
		return syscallpolicy.FDObservation{}, credentialhelper.ErrContractOwnership
	}
	return observations.ObserveFD(query)
}

func (wrapper *syscallPolicyWrapper) ObservePointer(query syscallpolicy.PointerQuery) (syscallpolicy.PointerObservation, error) {
	observations := wrapper.constructionObservations()
	if observations == nil {
		return syscallpolicy.PointerObservation{}, credentialhelper.ErrContractOwnership
	}
	return observations.ObservePointer(query)
}

func (wrapper *syscallPolicyWrapper) ObserveObject(query syscallpolicy.ObjectQuery) (syscallpolicy.ObjectObservation, error) {
	observations := wrapper.constructionObservations()
	if observations == nil {
		return syscallpolicy.ObjectObservation{}, credentialhelper.ErrContractOwnership
	}
	return observations.ObserveObject(query)
}

func (wrapper *syscallPolicyWrapper) constructionObservations() syscallPolicyObservations {
	if wrapper == nil {
		return nil
	}
	wrapper.mu.Lock()
	defer wrapper.mu.Unlock()
	if wrapper.state != wrapperStateUnstarted {
		return nil
	}
	return wrapper.observations
}

func (wrapper *syscallPolicyWrapper) destroyUnstarted() {
	wrapper.observations = nil
	wrapper.bindings = syscallpolicy.AdapterBindings{}
	wrapper.permit = syscallPermit{}
	wrapper.executor = nil
	wrapper.terminal = nil
}

func (wrapper *syscallPolicyWrapper) finishLocked() {
	wrapper.state = wrapperStateFinalized
	wrapper.observations = nil
	wrapper.bindings = syscallpolicy.AdapterBindings{}
	wrapper.permit = syscallPermit{}
	wrapper.executor = nil
	wrapper.terminal = nil
}

type syscallPostObservationSource struct {
	permitCorrelationSHA256 [32]byte
	returnedObjectNumber    int32
	object                  syscallReturnedObject
	nextOrdinal             uint16
}

func newPostObservationSource(permit syscallPermit, object syscallReturnedObject, number int32) (*syscallPostObservationSource, error) {
	if permit.identity == nil || !permit.requiresPost || nilInterface(object) {
		return nil, credentialhelper.ErrContractOwnership
	}
	if number < 0 {
		return nil, credentialhelper.ErrContractInvalidArgument
	}
	return &syscallPostObservationSource{
		permitCorrelationSHA256: permit.value.PermitCorrelationSHA256(),
		returnedObjectNumber:    number,
		object:                  object,
	}, nil
}

func (source *syscallPostObservationSource) ReinspectObject(query syscallpolicy.ObjectQuery) (syscallpolicy.ObjectObservation, error) {
	if source == nil || source.object == nil || query.Source() != syscallpolicy.ObjectSourceReturn || query.Phase() != syscallpolicy.AdapterPhasePost || query.PermitCorrelationSHA256() != source.permitCorrelationSHA256 || query.Ordinal() != source.nextOrdinal {
		return syscallpolicy.ObjectObservation{}, credentialhelper.ErrContractOwnership
	}
	inspection, err := source.object.inspectObject(query)
	if err != nil {
		return syscallpolicy.ObjectObservation{}, credentialhelper.ErrContractDependency
	}
	observation, err := syscallpolicy.NewObjectObservation(
		query,
		source.returnedObjectNumber,
		inspection.kind,
		inspection.access,
		inspection.generationSHA256,
		inspection.checks,
		inspection.fixed,
	)
	if err == nil {
		source.nextOrdinal++
	}
	return observation, err
}

func validSyscallPermit(permit syscallPermit) bool {
	return permit.identity != nil && permit.value.SHA256() != ([32]byte{}) && permit.value.RequiresPost() == permit.requiresPost
}

func syscallExecutorDependencyError(executor syscallExecutor) error {
	if executor == nil {
		return credentialhelper.ErrContractDependency
	}
	if nilInterface(executor) {
		return credentialhelper.ErrContractTypedNil
	}
	return nil
}

func syscallObservationDependencyError(observations syscallPolicyObservations) error {
	if observations == nil {
		return credentialhelper.ErrContractDependency
	}
	if nilInterface(observations) {
		return credentialhelper.ErrContractTypedNil
	}
	return nil
}

func syscallContextError(ctx context.Context) (err error) {
	if ctx == nil || nilInterface(ctx) {
		return credentialhelper.ErrContractTypedNil
	}
	defer func() {
		if recover() != nil {
			err = credentialhelper.ErrContractDependency
		}
	}()
	return ctx.Err()
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func executeSyscallSafely(ctx context.Context, executor syscallExecutor) (execution syscallExecution, err error) {
	defer func() {
		if recover() != nil {
			execution = syscallExecution{}
			err = credentialhelper.ErrContractDependency
		}
	}()
	execution, err = executor.execute(ctx)
	return execution, err
}

func checkedReturnedObject(object syscallReturnedObject) (syscallReturnedObject, int32, error) {
	if object == nil {
		return nil, -1, nil
	}
	if nilInterface(object) {
		return nil, -1, credentialhelper.ErrContractTypedNil
	}
	number, err := returnedObjectNumberSafely(object)
	if err != nil {
		return object, -1, err
	}
	if number < 0 {
		return object, number, credentialhelper.ErrContractInvalidArgument
	}
	return object, number, nil
}

func returnedObjectNumberSafely(object syscallReturnedObject) (number int32, err error) {
	defer func() {
		if recover() != nil {
			number = -1
			err = credentialhelper.ErrContractDependency
		}
	}()
	return object.numberValue(), nil
}

func closeReturnedObjectSafely(object syscallReturnedObject) (err error) {
	if object == nil || nilInterface(object) {
		return nil
	}
	defer func() {
		if recover() != nil {
			err = credentialhelper.ErrContractDependency
		}
	}()
	if object.closeObject() != nil {
		return credentialhelper.ErrContractDependency
	}
	return nil
}

func callTerminalSafely(call func() syscallTerminalResult) (result syscallTerminalResult) {
	defer func() {
		if recover() != nil {
			result = syscallTerminalResult{err: credentialhelper.ErrContractDependency, valid: true}
		}
	}()
	return call()
}

func checkedTerminalResult(result syscallTerminalResult) (syscallpolicy.AdapterDecision, error) {
	if !result.valid {
		return syscallpolicy.AdapterDecision{}, credentialhelper.ErrContractResultMatrix
	}
	return result.decision, result.err
}

func joinWrapperErrors(failures ...error) error {
	nonNil := failures[:0]
	for _, failure := range failures {
		if failure != nil {
			nonNil = append(nonNil, failure)
		}
	}
	return errors.Join(nonNil...)
}
