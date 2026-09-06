package firecrackerhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func jailerRecoveryTestRecord(t *testing.T) (firecrackerRuntimeOwnerRecordV1, jailerRecoverySupervisorConfig) {
	t.Helper()
	config := jailerRecoveryTestSupervisorConfig(t)
	payload, _ := json.Marshal(config)
	digest := sha256.Sum256(payload)
	legacy := l8RuntimeOwnerTestRecord(t, l8RuntimeOwnerTestSeed(), "11111111-1111-4111-8111-111111111111")
	record := firecrackerRuntimeOwnerRecordV1{ContractVersion: jailerRecoveryRecordVersion, State: "starting", ControllerState: "none", HostBootID: legacy.HostBootID, SeedCorrelationDigest: hex.EncodeToString(digest[:]), SupervisorGeneration: legacy.SupervisorGeneration, SupervisorPID: legacy.SupervisorPID, SupervisorStartTime: legacy.SupervisorStartTime, ReconnectListenerIdentity: legacy.ReconnectListenerIdentity, ReconnectSecret: legacy.ReconnectSecret, RuntimeID: config.Job.RuntimeID, RuntimeGeneration: config.Job.RuntimeGeneration, SandboxID: config.Job.SandboxID, ExecutionID: config.Job.ExecutionID, WorkerID: config.Job.WorkerID, HostID: config.Job.HostID}
	return record, config
}

func TestJailerRecoveryRecordDoesNotInventCredentialAuthority(t *testing.T) {
	record, config := jailerRecoveryTestRecord(t)
	data, err := encodeJailerRecoveryRecord(record, config, nil, false)
	if err != nil {
		t.Fatalf("minimal genesis refused: %v", err)
	}
	got, busy, terminal, err := decodeJailerRecoveryRecord(data, config)
	if err != nil || got != record || busy != nil || terminal {
		t.Fatalf("minimal record roundtrip: %v", err)
	}
	for _, key := range []string{"seed", "vsockGeneration", "firecrackerProcessGeneration", "proxySessionId", "networkPlanId", "ruleGenerationId"} {
		if bytes.Contains(data, []byte(`"`+key+`"`)) {
			t.Fatalf("legacy authority field encoded: %s", key)
		}
	}
	if _, err := decodeFirecrackerRuntimeOwnerRecordV1(data, l8RuntimeOwnerTestSeed(), record.HostBootID); err == nil {
		t.Fatal("selected record accepted as credential record")
	}
	for name, mutate := range map[string]func(*firecrackerRuntimeOwnerRecordV1){
		"legacyversion":         func(r *firecrackerRuntimeOwnerRecordV1) { r.ContractVersion = l8RuntimeOwnerContractVersion },
		"fakehelper":            func(r *firecrackerRuntimeOwnerRecordV1) { r.VsockGeneration = "invented" },
		"fakeprocessgeneration": func(r *firecrackerRuntimeOwnerRecordV1) { r.FirecrackerProcessGeneration = "invented" },
		"wrongjob":              func(r *firecrackerRuntimeOwnerRecordV1) { r.RuntimeID = "another-runtime" },
		"wrongconfig":           func(r *firecrackerRuntimeOwnerRecordV1) { r.SeedCorrelationDigest = strings.Repeat("f", 64) },
		"missingowner":          func(r *firecrackerRuntimeOwnerRecordV1) { r.SupervisorStartTime = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := record
			mutate(&changed)
			if _, err := encodeJailerRecoveryRecord(changed, config, nil, false); err == nil {
				t.Fatal("uncorrelated record accepted")
			}
		})
	}
}

func TestJailerRecoveryRecordRequiresActualBusyCorrelation(t *testing.T) {
	record, config := jailerRecoveryTestRecord(t)
	busy := jailerIdentityRecord{Version: 1, UID: config.Policy.UID, GID: config.Policy.GID, State: "busy", RuntimeID: config.Job.RuntimeID, Config: config.Config.SHA256, Nonce: strings.Repeat("a", 64)}
	data, err := encodeJailerRecoveryRecord(record, config, &busy, false)
	if err != nil {
		t.Fatalf("busy correlation refused: %v", err)
	}
	_, got, terminal, err := decodeJailerRecoveryRecord(data, config)
	if err != nil || got == nil || *got != busy || terminal {
		t.Fatalf("busy roundtrip: %v", err)
	}
	for name, mutate := range map[string]func(*jailerIdentityRecord){
		"uid": func(r *jailerIdentityRecord) { r.UID++ }, "gid": func(r *jailerIdentityRecord) { r.GID++ }, "runtime": func(r *jailerIdentityRecord) { r.RuntimeID = "another" }, "digest": func(r *jailerIdentityRecord) { r.Config = strings.Repeat("b", 64) }, "nonce": func(r *jailerIdentityRecord) { r.Nonce = "" }, "idle": func(r *jailerIdentityRecord) { r.State = "idle" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := busy
			mutate(&changed)
			if _, err := encodeJailerRecoveryRecord(record, config, &changed, false); err == nil {
				t.Fatal("unrelated busy accepted")
			}
		})
	}
	if _, err := encodeJailerRecoveryRecord(record, config, nil, true); err == nil {
		t.Fatal("terminal checkpoint without reservation accepted")
	}
}
