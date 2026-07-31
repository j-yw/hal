package linuxrules

import (
	"context"
	"errors"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

type NFTExecutor interface {
	ApplyBatch(context.Context, NamespaceHandle, []byte) error
	ListTableJSON(context.Context, NamespaceHandle, TableQuery, int64) ([]byte, error)
}

type AdapterOptions struct {
	MaxBatchBytes      int
	MaxInspectionBytes int64
}

type Adapter struct {
	executor           NFTExecutor
	maxBatchBytes      int
	maxInspectionBytes int64
	mu                 sync.Mutex
}

func NewAdapter(executor NFTExecutor, options AdapterOptions) *Adapter {
	maxBatchBytes := options.MaxBatchBytes
	if maxBatchBytes <= 0 {
		maxBatchBytes = defaultMaxBatchBytes
	}
	maxInspectionBytes := options.MaxInspectionBytes
	if maxInspectionBytes <= 0 {
		maxInspectionBytes = defaultMaxInspectionBytes
	}
	return &Adapter{
		executor: executor, maxBatchBytes: maxBatchBytes,
		maxInspectionBytes: maxInspectionBytes,
	}
}

func (a *Adapter) ApplyAndInspect(ctx context.Context, expected ExpectedRuleSet) (networkenforcement.RuleLifecycleMetadata, error) {
	if a == nil {
		return failedMetadata(expected, networkenforcement.LifecycleReasonCapabilityMissing), operationError{err: ErrInvalidConfiguration}
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.executor == nil || !expected.valid() {
		return failedMetadata(expected, networkenforcement.LifecycleReasonCapabilityMissing), operationError{err: ErrInvalidConfiguration}
	}
	present, owned, err := a.ownership(ctx, expected)
	if err != nil {
		return failedMetadata(expected, networkenforcement.LifecycleReasonRuleInspectionFailed), safeError(err)
	}
	if present && !owned {
		return failedMetadata(expected, networkenforcement.LifecycleReasonProofMismatch), operationError{err: ErrStaleGeneration}
	}

	batch := expected.fullBatch(present)
	if len(batch) > a.maxBatchBytes {
		return failedMetadata(expected, networkenforcement.LifecycleReasonCapabilityMissing), operationError{err: ErrBatchTooLarge}
	}
	if err := a.executor.ApplyBatch(ctx, expected.namespace, batch); err != nil {
		if quarantineErr := a.quarantineIfOwned(ctx, expected); quarantineErr != nil {
			return failedMetadata(expected, networkenforcement.LifecycleReasonQuarantineFailed), quarantineErr
		}
		return failedMetadata(expected, networkenforcement.LifecycleReasonAdapterFailed), operationError{err: ErrApplyFailed}
	}

	payload, err := a.executor.ListTableJSON(ctx, expected.namespace, expected.query(), a.maxInspectionBytes)
	if err != nil {
		if quarantineErr := a.quarantineIfOwned(ctx, expected); quarantineErr != nil {
			return failedMetadata(expected, networkenforcement.LifecycleReasonQuarantineFailed), safeError(errors.Join(err, quarantineErr))
		}
		return failedMetadata(expected, networkenforcement.LifecycleReasonRuleInspectionFailed), safeError(err)
	}
	if err := inspectExpected(payload, expected, a.maxInspectionBytes); err != nil {
		if quarantineErr := a.quarantineIfOwned(ctx, expected); quarantineErr != nil {
			return failedMetadata(expected, networkenforcement.LifecycleReasonQuarantineFailed), safeError(errors.Join(err, quarantineErr))
		}
		return failedMetadata(expected, networkenforcement.LifecycleReasonRuleInspectionFailed), safeError(err)
	}
	return activeMetadata(expected), nil
}

func (a *Adapter) Cleanup(ctx context.Context, expected ExpectedRuleSet) error {
	if a == nil {
		return operationError{err: ErrInvalidConfiguration}
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.executor == nil || !expected.valid() {
		return operationError{err: ErrInvalidConfiguration}
	}
	present, owned, err := a.ownership(ctx, expected)
	if err != nil {
		return safeError(err)
	}
	if !present {
		return nil
	}
	if !owned {
		return operationError{err: ErrStaleGeneration}
	}
	if err := a.applyBounded(ctx, expected, expected.quarantineBatch(), ErrQuarantineFailed); err != nil {
		return err
	}
	if err := a.inspectQuarantine(ctx, expected); err != nil {
		return err
	}
	if err := a.applyBounded(ctx, expected, expected.deleteBatch(), ErrCleanupFailed); err != nil {
		return err
	}
	_, err = a.executor.ListTableJSON(ctx, expected.namespace, expected.query(), a.maxInspectionBytes)
	if errors.Is(err, ErrTableNotFound) {
		return nil
	}
	return operationError{err: ErrCleanupFailed}
}

func (a *Adapter) ownership(ctx context.Context, expected ExpectedRuleSet) (present, owned bool, err error) {
	payload, err := a.executor.ListTableJSON(ctx, expected.namespace, expected.query(), a.maxInspectionBytes)
	if errors.Is(err, ErrTableNotFound) {
		return false, false, nil
	}
	if err != nil {
		return false, false, safeError(err)
	}
	owned, err = inspectOwnership(payload, expected, a.maxInspectionBytes)
	return true, owned, err
}

func (a *Adapter) quarantineIfOwned(ctx context.Context, expected ExpectedRuleSet) error {
	present, owned, err := a.ownership(ctx, expected)
	if err != nil {
		return operationError{err: ErrQuarantineFailed}
	}
	if !present || !owned {
		return nil
	}
	if err := a.applyBounded(ctx, expected, expected.quarantineBatch(), ErrQuarantineFailed); err != nil {
		return err
	}
	return a.inspectQuarantine(ctx, expected)
}

func (a *Adapter) inspectQuarantine(ctx context.Context, expected ExpectedRuleSet) error {
	payload, err := a.executor.ListTableJSON(ctx, expected.namespace, expected.query(), a.maxInspectionBytes)
	if err != nil {
		return operationError{err: ErrQuarantineFailed}
	}
	if err := inspectQuarantine(payload, expected, a.maxInspectionBytes); err != nil {
		return operationError{err: ErrQuarantineFailed}
	}
	return nil
}

func (a *Adapter) applyBounded(ctx context.Context, expected ExpectedRuleSet, batch []byte, failure error) error {
	if len(batch) > a.maxBatchBytes {
		return operationError{err: ErrBatchTooLarge}
	}
	if err := a.executor.ApplyBatch(ctx, expected.namespace, batch); err != nil {
		return operationError{err: failure}
	}
	return nil
}

func activeMetadata(expected ExpectedRuleSet) networkenforcement.RuleLifecycleMetadata {
	correlation := expected.correlation
	labels := []string{
		"default_deny", "private_range_rules",
		"metadata_endpoint", "loopback_rules", "link_local_rules", "raw_protocols",
	}
	proof := networkenforcement.InspectedRuleProof{
		ID:               "proof-" + expected.ownerToken,
		RuleDigest:       expected.ruleDigest,
		Status:           networkenforcement.RuleInspectionStatusInspected,
		Correlation:      &correlation,
		Mechanisms:       []networkenforcement.EnforcementMechanism{networkenforcement.EnforcementMechanismFirewall},
		CapabilityLabels: labels,
		ReasonCode:       networkenforcement.LifecycleReasonRuleInspected,
	}
	return networkenforcement.SanitizeRuleLifecycleMetadata(networkenforcement.RuleLifecycleMetadata{
		ID:               correlation.RuleGenerationID,
		PlanID:           correlation.PlanID,
		AdapterID:        adapterID,
		Status:           networkenforcement.LifecycleStatusActive,
		Mechanisms:       []networkenforcement.EnforcementMechanism{networkenforcement.EnforcementMechanismFirewall},
		Operations:       []string{"apply_rules", "inspect_rules"},
		PolicySnapshot:   &networkenforcement.PolicySnapshotIdentity{ID: correlation.PolicySnapshotID},
		CapabilityLabels: labels,
		Correlation:      &correlation,
		Inspection:       &proof,
		ReasonCode:       networkenforcement.LifecycleReasonActive,
	})
}

func failedMetadata(expected ExpectedRuleSet, reason networkenforcement.LifecycleReasonCode) networkenforcement.RuleLifecycleMetadata {
	correlation := expected.correlation
	return networkenforcement.SanitizeRuleLifecycleMetadata(networkenforcement.RuleLifecycleMetadata{
		ID:           correlation.RuleGenerationID,
		PlanID:       correlation.PlanID,
		AdapterID:    adapterID,
		Status:       networkenforcement.LifecycleStatusFailed,
		Mechanisms:   []networkenforcement.EnforcementMechanism{networkenforcement.EnforcementMechanismFirewall},
		Correlation:  &correlation,
		ReasonCode:   reason,
		WarningCodes: []networkenforcement.LifecycleWarningCode{networkenforcement.LifecycleWarningRuleInspectionFailed},
	})
}
