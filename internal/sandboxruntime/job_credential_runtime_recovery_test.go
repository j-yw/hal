package sandboxruntime

import (
	"context"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestJobCredentialRuntimeRecoveryProofBindsEverySeedField(t *testing.T) {
	issuedAt := time.Date(2026, time.August, 21, 8, 0, 0, 0, time.UTC)
	inspectedAt := issuedAt.Add(time.Minute)
	seed := d2JobCredentialIdentitySeed(issuedAt)
	proof, err := NewJobCredentialRuntimeAbsenceProof(JobCredentialRuntimeAbsenceProofInput{Seed: seed, AbsenceInspectedAt: inspectedAt})
	if err != nil {
		t.Fatalf("NewJobCredentialRuntimeAbsenceProof: %v", err)
	}
	if err := ValidateJobCredentialRuntimeAbsenceProof(proof, seed, inspectedAt.Add(time.Minute)); err != nil {
		t.Fatalf("ValidateJobCredentialRuntimeAbsenceProof: %v", err)
	}
	for index := range reflect.VisibleFields(reflect.TypeOf(seed)) {
		field := reflect.VisibleFields(reflect.TypeOf(seed))[index]
		mutated := mutateD2IdentitySeedField(t, seed, field.Name)
		if err := ValidateJobCredentialRuntimeAbsenceProof(proof, mutated, inspectedAt.Add(time.Minute)); !errors.Is(err, ErrJobCredentialProofInvalid) {
			t.Errorf("mutated %s validation = %v, want proof invalid", field.Name, err)
		}
	}
	if proof == (JobCredentialRuntimeAbsenceProof{}) {
		t.Fatal("absence proof is zero")
	}
	want := "<sandboxruntime.JobCredentialRuntimeAbsenceProof>"
	for _, rendered := range []string{proof.String(), proof.GoString(), fmt.Sprint(proof), fmt.Sprintf("%+v", proof), fmt.Sprintf("%#v", proof)} {
		if rendered != want {
			t.Errorf("proof rendering = %q", rendered)
		}
	}
	if payload, err := json.Marshal(proof); err == nil || payload != nil {
		t.Fatalf("proof JSON projection = %q, %v", payload, err)
	}
	if payload, err := proof.MarshalText(); err == nil || payload != nil {
		t.Fatalf("proof text projection = %q, %v", payload, err)
	}
	if payload, err := proof.MarshalBinary(); err == nil || payload != nil {
		t.Fatalf("proof binary projection = %q, %v", payload, err)
	}
	if payload, err := proof.GobEncode(); err == nil || payload != nil {
		t.Fatalf("proof gob projection = %q, %v", payload, err)
	}
}

func TestJobCredentialRuntimeRecoveryProofRejectsStaleFutureAndMalformed(t *testing.T) {
	issuedAt := time.Date(2026, time.August, 21, 9, 0, 0, 0, time.UTC)
	seed := d2JobCredentialIdentitySeed(issuedAt)
	proof, err := NewJobCredentialRuntimeAbsenceProof(JobCredentialRuntimeAbsenceProofInput{Seed: seed, AbsenceInspectedAt: issuedAt.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateJobCredentialRuntimeAbsenceProof(proof, seed, issuedAt.Add(time.Minute).Add(MaxJobCredentialRuntimeAbsenceObservationAge+time.Nanosecond)); !errors.Is(err, ErrJobCredentialProofStale) {
		t.Fatalf("stale validation = %v", err)
	}
	if err := ValidateJobCredentialRuntimeAbsenceProof(proof, seed, issuedAt); !errors.Is(err, ErrJobCredentialProofInvalid) {
		t.Fatalf("future validation = %v", err)
	}
	for _, input := range []JobCredentialRuntimeAbsenceProofInput{
		{},
		{Seed: seed},
		{Seed: seed, AbsenceInspectedAt: issuedAt.Add(-time.Nanosecond)},
	} {
		if proof, err := NewJobCredentialRuntimeAbsenceProof(input); proof != (JobCredentialRuntimeAbsenceProof{}) || !errors.Is(err, ErrJobCredentialProofInvalid) {
			t.Errorf("invalid constructor = %#v, %v", proof, err)
		}
	}
	corrupted := proof
	corrupted.token[1] ^= 0xff
	if err := ValidateJobCredentialRuntimeAbsenceProof(corrupted, seed, issuedAt.Add(2*time.Minute)); !errors.Is(err, ErrJobCredentialProofInvalid) {
		t.Fatalf("corrupted validation = %v", err)
	}
}

func TestJobCredentialRuntimeRecoveryCommitReceiptValidationAndRedaction(t *testing.T) {
	receipt := JobCredentialRuntimeRecoveryCommitReceipt{CommitID: d2GuestSessionGeneration(3), FinalizedRevision: 7}
	if err := ValidateJobCredentialRuntimeRecoveryCommitReceipt(receipt); err != nil {
		t.Fatalf("validate receipt: %v", err)
	}
	for _, malformed := range []JobCredentialRuntimeRecoveryCommitReceipt{
		{}, {CommitID: receipt.CommitID}, {CommitID: "not-a-receipt", FinalizedRevision: 7},
	} {
		if err := ValidateJobCredentialRuntimeRecoveryCommitReceipt(malformed); !errors.Is(err, ErrJobCredentialProofInvalid) {
			t.Errorf("malformed receipt validation = %v", err)
		}
	}
	want := "[job-credential-runtime-recovery-commit-receipt]"
	for _, rendered := range []string{receipt.String(), receipt.GoString(), fmt.Sprint(receipt), fmt.Sprintf("%+v", receipt), fmt.Sprintf("%#v", receipt)} {
		if rendered != want || strings.Contains(rendered, receipt.CommitID) {
			t.Errorf("receipt rendering = %q", rendered)
		}
	}
	if payload, err := json.Marshal(receipt); err == nil || payload != nil {
		t.Fatalf("JSON projection = %q, %v", payload, err)
	}
	if payload, err := receipt.MarshalText(); err == nil || payload != nil {
		t.Fatalf("text projection = %q, %v", payload, err)
	}
	if payload, err := receipt.MarshalBinary(); err == nil || payload != nil {
		t.Fatalf("binary projection = %q, %v", payload, err)
	}
	if payload, err := receipt.GobEncode(); err == nil || payload != nil {
		t.Fatalf("gob projection = %q, %v", payload, err)
	}
	var gobPayload strings.Builder
	if err := gob.NewEncoder(&gobPayload).Encode(receipt); err == nil || strings.Contains(gobPayload.String(), receipt.CommitID) {
		t.Fatalf("gob encoder exposed receipt: %v", err)
	}
	xmlPayload, err := xml.Marshal(receipt)
	if strings.Contains(string(xmlPayload), receipt.CommitID) {
		t.Fatalf("XML projection = %q, %v", xmlPayload, err)
	}
}

func TestJobCredentialRuntimeRecoveryAPISchemaIsExact(t *testing.T) {
	if MaxJobCredentialRuntimeAbsenceObservationAge != 5*time.Minute || JobCredentialRuntimeStopReapTimeout != 30*time.Second || JobCredentialRuntimeRecoveryCloseTimeout != 5*time.Second {
		t.Fatal("runtime recovery bounds changed")
	}
	assertFieldOrder(t, reflect.TypeOf(JobCredentialRuntimeAbsenceProofInput{}), []string{"Seed", "AbsenceInspectedAt"})
	assertFieldOrder(t, reflect.TypeOf(JobCredentialRuntimeRecoveryCommitReceipt{}), []string{"CommitID", "FinalizedRevision"})
	var _ JobCredentialRuntimeRecoveryProvider = recoveryProviderContractFake{}
	var _ JobCredentialRuntimeRecoveryBinding = recoveryBindingContractFake{}
}

type recoveryProviderContractFake struct{}

func (recoveryProviderContractFake) BindJobCredentialRuntimeRecovery(context.Context, JobCredentialIdentitySeed) (JobCredentialRuntimeRecoveryBinding, error) {
	return recoveryBindingContractFake{}, nil
}

type recoveryBindingContractFake struct{}

func (recoveryBindingContractFake) RecoverJobCredentials(context.Context, JobCredentialRecoveryRequest) (JobCredentialCleanupProof, error) {
	return JobCredentialCleanupProof{}, nil
}
func (recoveryBindingContractFake) StopReapJobCredentialRuntime(context.Context) (JobCredentialRuntimeAbsenceProof, error) {
	return JobCredentialRuntimeAbsenceProof{}, nil
}
func (recoveryBindingContractFake) FinalizeJobCredentialRuntimeRecovery(context.Context, JobCredentialRuntimeAbsenceProof) (JobCredentialRuntimeRecoveryCommitReceipt, error) {
	return JobCredentialRuntimeRecoveryCommitReceipt{}, nil
}
func (recoveryBindingContractFake) CommitJobCredentialRuntimeRecovery(context.Context, JobCredentialRuntimeRecoveryCommitReceipt) error {
	return nil
}
func (recoveryBindingContractFake) Close(context.Context) error { return nil }
