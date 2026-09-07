//go:build linux

package firecrackerhost

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestMinimalJailerFinalizationPinsEveryRecordField(t *testing.T) {
	_, _, completion := minimalJailerFinalizedFixture(t)
	frozen := completion.state.frozen
	if !sameMinimalJailerFinalizedRecord(frozen, frozen) {
		t.Fatal("actual finalized record control")
	}
	for index := 0; index < reflect.TypeOf(frozen).NumField(); index++ {
		field := reflect.TypeOf(frozen).Field(index)
		t.Run(field.Name, func(t *testing.T) {
			changed := frozen
			value := reflect.ValueOf(&changed).Elem().Field(index)
			switch value.Kind() {
			case reflect.String:
				value.SetString(value.String() + "changed")
			case reflect.Uint32, reflect.Uint64:
				value.SetUint(value.Uint() + 1)
			case reflect.Int64:
				value.SetInt(value.Int() + 1)
			default:
				t.Fatal("new record field needs an explicit immutable comparison test")
			}
			allowed := field.Name == "Revision" || field.Name == "ReconnectSecret"
			if field.Name == "ControllerState" {
				changed.ControllerState, allowed = "unclaimed", true
			}
			// This exercises exact value comparison, not canonical validity or
			// a fabricated owner. The real wire tests cover admission separately.
			if sameMinimalJailerFinalizedRecord(frozen, changed) != allowed {
				t.Fatal("full-record pin omitted or over-normalized a field")
			}
		})
	}
	for _, state := range []string{"none", "unknown", "controlled changed"} {
		changed := frozen
		changed.ControllerState = state
		if sameMinimalJailerFinalizedRecord(frozen, changed) {
			t.Fatal("invalid normalized controller state")
		}
	}
	changed := frozen
	changed.Revision--
	if sameMinimalJailerFinalizedRecord(frozen, changed) {
		t.Fatal("revision regression normalized away")
	}
}

func TestMinimalJailerFinalizationActualRecordContradictionStaysQuarantined(t *testing.T) {
	for _, mode := range []string{"process_pid", "process_start", "commit", "finalize_target", "absence_revision", "absence_time", "listener", "supervisor", "host_boot", "full_config", "finalizing"} {
		t.Run(mode, func(t *testing.T) {
			f, client, completion := minimalJailerFinalizedFixture(t)
			file := f.owned.store.selected.file
			original, err := io.ReadAll(io.NewSectionReader(file, 0, l8RuntimeOwnerRecordLimit+1))
			if err != nil {
				t.Fatal(err)
			}
			var disk jailerRecoveryDiskRecord
			var owner map[string]json.RawMessage
			if json.Unmarshal(original, &disk) != nil || json.Unmarshal(disk.Owner, &owner) != nil {
				t.Fatal("actual canonical record prerequisite")
			}
			record, err := decodeJailerRecoveryCleanupRecord(original, client.expected)
			if err != nil || record.State != "finalized" || record.ControllerState != "unclaimed" {
				t.Fatal("actual disconnected finalized prerequisite", err)
			}
			set := func(name string, value any) { owner[name], _ = json.Marshal(value) }
			switch mode {
			case "process_pid":
				set("firecrackerPid", record.FirecrackerPID+1)
			case "process_start":
				set("firecrackerStartTime", record.FirecrackerStartTime+1)
			case "commit":
				set("finalizedCommitId", l8RuntimeOwnerTestToken(98))
			case "finalize_target":
				set("finalizeTargetRevision", record.FinalizeTargetRevision-1)
			case "absence_revision":
				set("absenceRevision", record.AbsenceRevision-1)
			case "absence_time":
				set("absenceObservedAtUnixNano", record.AbsenceObservedAtUnixNano+1)
			case "listener":
				set("reconnectListenerIdentity", l8RuntimeOwnerTestToken(98))
			case "supervisor":
				set("supervisorGeneration", l8RuntimeOwnerTestToken(98))
			case "host_boot":
				set("hostBootId", "00000000-0000-0000-0000-000000000098")
			case "full_config":
				disk.ConfigCorrelation = strings.Repeat("d", 64)
			case "finalizing":
				set("state", "finalizing")
				set("finalizeTargetRevision", record.Revision+1)
			}
			disk.Owner, _ = json.Marshal(owner)
			changed, err := json.Marshal(disk)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeJailerRecoveryCleanupRecord(changed, client.expected)
			if err != nil || decoded == record {
				t.Fatal("mutation did not reach a distinct valid canonical record", err)
			}
			write := func(payload []byte) {
				t.Helper()
				if file.Truncate(int64(len(payload))) != nil {
					t.Fatal("fixture record resize")
				}
				if count, err := file.WriteAt(payload, 0); err != nil || count != len(payload) {
					t.Fatal("fixture record write", err)
				}
			}
			defer write(original)
			write(changed)
			connections := 0
			client.ops.connectMinimal = func(context.Context, *os.File, firecrackerRuntimeOwnerRecordV1) (*os.File, error) {
				connections++
				return nil, errL8RuntimeOwnerInvalid
			}
			frozen := completion.state.frozen
			if completion.commit(context.Background()) == nil || !completion.state.quarantined || connections != 0 || completion.state.frozen != frozen || completion.state.acknowledged {
				t.Fatal("canonical identity contradiction reached reconnect or replaced the frozen result")
			}
			write(original)
			if _, err := client.readRecord(); err != nil {
				t.Fatal("restored original canonical bytes prerequisite", err)
			}
			if completion.commit(context.Background()) == nil || connections != 0 || !completion.state.quarantined {
				t.Fatal("restoring candidate bytes erased selected quarantine")
			}
			if f.owned.store.selected.retired || f.owned.store.selected.poisoned {
				t.Fatal("rejected client mutation changed surviving owner's local state")
			}
		})
	}
}
