package sandboxexecution

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestL8D6CredentialCleanupCheckpointSchemaAndDefaultJSON(t *testing.T) {
	typeOf := reflect.TypeOf(FinalizationCheckpoints{})
	if typeOf.NumField() != 5 {
		t.Fatalf("FinalizationCheckpoints fields = %d, want 5", typeOf.NumField())
	}
	want := []struct {
		name   string
		typeOf reflect.Type
		tag    string
	}{
		{name: "CredentialCleanup", typeOf: reflect.TypeOf((*FinalizationCheckpoint)(nil)), tag: `json:"credentialCleanup,omitempty"`},
		{name: "Artifacts", typeOf: reflect.TypeOf(FinalizationCheckpoint{}), tag: `json:"artifacts"`},
		{name: "SyncOut", typeOf: reflect.TypeOf(FinalizationCheckpoint{}), tag: `json:"syncOut"`},
		{name: "LeaseRelease", typeOf: reflect.TypeOf(FinalizationCheckpoint{}), tag: `json:"leaseRelease"`},
		{name: "TerminalPublication", typeOf: reflect.TypeOf(FinalizationCheckpoint{}), tag: `json:"terminalPublication"`},
	}
	for index, expected := range want {
		field := typeOf.Field(index)
		if field.Name != expected.name || field.Type != expected.typeOf || string(field.Tag) != expected.tag {
			t.Fatalf("field %d = %s %v %q, want %s %v %q", index, field.Name, field.Type, field.Tag, expected.name, expected.typeOf, expected.tag)
		}
	}

	encoded, err := json.Marshal(FinalizationCheckpoints{})
	if err != nil {
		t.Fatalf("Marshal(default) error: %v", err)
	}
	if strings.Contains(string(encoded), "credentialCleanup") {
		t.Fatalf("default checkpoint JSON projected credential cleanup: %s", encoded)
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatalf("Unmarshal(default) error: %v", err)
	}
	for _, key := range []string{"artifacts", "syncOut", "leaseRelease", "terminalPublication"} {
		if _, ok := object[key]; !ok {
			t.Fatalf("default checkpoint JSON omitted compatibility key %q: %s", key, encoded)
		}
	}
}

func TestL8D6CredentialCleanupCheckpointValidationAndOrder(t *testing.T) {
	startedAt := time.Date(2026, 8, 21, 1, 0, 0, 0, time.UTC)
	cleanupAt := startedAt.Add(time.Minute)
	artifactAt := cleanupAt.Add(time.Minute)
	leaseAt := artifactAt.Add(time.Minute)
	publicationAt := leaseAt.Add(time.Minute)
	completedAt := publicationAt
	checkpoint := func(at *time.Time) FinalizationCheckpoint {
		return FinalizationCheckpoint{Completed: true, CompletedAt: at}
	}
	valid := FinalizationMetadata{
		ContractVersion:  FinalizationContractVersion,
		State:            FinalizationStateCompleted,
		TerminalJobState: "succeeded",
		Checkpoints: FinalizationCheckpoints{
			CredentialCleanup:   &FinalizationCheckpoint{Completed: true, CompletedAt: &cleanupAt},
			Artifacts:           checkpoint(&artifactAt),
			LeaseRelease:        checkpoint(&leaseAt),
			TerminalPublication: checkpoint(&publicationAt),
		},
		StartedAt:   &startedAt,
		UpdatedAt:   completedAt,
		CompletedAt: &completedAt,
	}
	if err := validateFinalizationMetadata(&valid); err != nil {
		t.Fatalf("validate valid credential cleanup finalization: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*FinalizationMetadata)
		want   string
	}{
		{name: "completed without credential cleanup", mutate: func(value *FinalizationMetadata) {
			value.Checkpoints.CredentialCleanup = &FinalizationCheckpoint{}
		}, want: "credential cleanup"},
		{name: "artifact before credential cleanup", mutate: func(value *FinalizationMetadata) {
			value.State = FinalizationStateFinalizing
			value.CompletedAt = nil
			value.Checkpoints.CredentialCleanup = &FinalizationCheckpoint{}
			value.Checkpoints.LeaseRelease = FinalizationCheckpoint{}
			value.Checkpoints.TerminalPublication = FinalizationCheckpoint{}
		}, want: "artifacts checkpoint precedes credential cleanup"},
		{name: "cleanup timestamp after artifacts", mutate: func(value *FinalizationMetadata) {
			late := artifactAt.Add(time.Minute)
			value.Checkpoints.CredentialCleanup.CompletedAt = &late
		}, want: "timestamps are out of order"},
		{name: "invalid cleanup checkpoint", mutate: func(value *FinalizationMetadata) {
			value.Checkpoints.CredentialCleanup.CompletedAt = nil
		}, want: "credentialCleanup checkpoint requires completedAt"},
		{name: "unproven terminal cleanup", mutate: func(value *FinalizationMetadata) {
			value.State = FinalizationStateBlocked
			value.ReasonCode = "terminal_proof_unavailable"
			value.TerminalJobState = "unknown"
			value.CompletedAt = nil
		}, want: "unproven terminal job state cannot complete checkpoints"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			credential := *valid.Checkpoints.CredentialCleanup
			value.Checkpoints.CredentialCleanup = &credential
			test.mutate(&value)
			err := validateFinalizationMetadata(&value)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}

	compatibility := valid
	compatibility.Checkpoints.CredentialCleanup = nil
	if err := validateFinalizationMetadata(&compatibility); err != nil {
		t.Fatalf("nil credential cleanup changed compatibility validation: %v", err)
	}
}
