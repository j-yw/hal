package firecrackerhost

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8RuntimeOwnerSeedDigestBindsEveryFieldAndCommitReplay(t *testing.T) {
	seed := l8RuntimeOwnerTestSeed()
	digest, err := l8RuntimeOwnerSeedDigest(seed)
	if err != nil || digest == ([32]byte{}) {
		t.Fatalf("seed digest = %x, %v", digest, err)
	}
	seedType := reflect.TypeOf(seed)
	for index := 0; index < seedType.NumField(); index++ {
		field := seedType.Field(index)
		mutated := l8RuntimeOwnerMutateSeedField(t, seed, field.Name)
		neighbor, err := l8RuntimeOwnerSeedDigest(mutated)
		if err != nil || neighbor == digest {
			t.Errorf("mutated %s digest = %x, %v", field.Name, neighbor, err)
		}
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	commitID, err := l8RuntimeOwnerCommitID(key, digest, 8)
	if err != nil || len(commitID) != 43 {
		t.Fatalf("commit ID = %q, %v", commitID, err)
	}
	for _, mutation := range []struct {
		key      []byte
		digest   [32]byte
		revision uint64
	}{
		{key: []byte("1123456789abcdef0123456789abcdef"), digest: digest, revision: 8},
		{key: key, digest: func() [32]byte { value := digest; value[0] ^= 1; return value }(), revision: 8},
		{key: key, digest: digest, revision: 9},
	} {
		neighbor, err := l8RuntimeOwnerCommitID(mutation.key, mutation.digest, mutation.revision)
		if err != nil || neighbor == commitID {
			t.Errorf("replayed commit ID = %q, %v", neighbor, err)
		}
	}
}

func TestL8RuntimeOwnerCommitIDUsesExactNormativeTranscript(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	seedDigest := sha256.Sum256([]byte("fixed seed digest fixture"))
	commitID, err := l8RuntimeOwnerCommitID(key, seedDigest, 8)
	if err != nil {
		t.Fatal(err)
	}
	const want = "WfQnAOYWC8pklZuzUEQTCC74p5hO44wup40eWKANEmw"
	if commitID != want {
		t.Fatalf("commit ID vector = %q, want %q", commitID, want)
	}
}

func TestL8RuntimeOwnerCommitVerifierRecomputesSeedBoundHMAC(t *testing.T) {
	seed := l8RuntimeOwnerTestSeed()
	digest, err := l8RuntimeOwnerSeedDigest(seed)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	commitID, err := l8RuntimeOwnerCommitID(key, digest, 8)
	if err != nil {
		t.Fatal(err)
	}
	receipt := sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt{CommitID: commitID, FinalizedRevision: 8}
	if err := commitJobCredentialRuntimeRecovery(receipt, key, seed, 8); err != nil {
		t.Fatalf("commit verifier: %v", err)
	}
	wrongKey := []byte("1123456789abcdef0123456789abcdef")
	if err := commitJobCredentialRuntimeRecovery(receipt, wrongKey, seed, 8); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("wrong commit verifier = %v", err)
	}
	if err := commitJobCredentialRuntimeRecovery(receipt, key, seed, 9); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("replayed revision verifier = %v", err)
	}
	mutatedSeed := seed
	mutatedSeed.RuntimeID = "runtime-neighbor"
	if err := commitJobCredentialRuntimeRecovery(receipt, key, mutatedSeed, 8); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("substituted seed verifier = %v", err)
	}
	forgedID := l8RuntimeOwnerTestToken(9)
	forged := sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt{CommitID: forgedID, FinalizedRevision: 8}
	if err := commitJobCredentialRuntimeRecovery(forged, key, seed, 8); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("caller-selected commit ID verifier = %v, want invalid", err)
	}
}

func TestL8RuntimeOwnerRecordSchemaIsExact(t *testing.T) {
	typeOf := reflect.TypeOf(firecrackerRuntimeOwnerRecordV1{})
	want := []string{
		"ContractVersion", "Revision", "State", "ControllerState", "AbsenceKind", "AbsenceRevision", "AbsenceObservedAtUnixNano", "FinalizeTargetRevision",
		"HostBootID", "SeedCorrelationDigest", "SupervisorGeneration",
		"SupervisorPID", "SupervisorStartTime", "FirecrackerPID", "FirecrackerStartTime", "FinalizedCommitID",
		"SandboxID", "ExecutionID", "WorkerID", "HostID", "RuntimeDriver", "RuntimeID", "RuntimeGeneration",
		"FirecrackerProcessGeneration", "VsockGeneration", "NetworkPlanID", "PolicySnapshotID", "ProxySessionID",
		"ProxyGenerationID", "TopologyGenerationID", "RuleGenerationID", "ReconnectListenerIdentity", "ReconnectSecret",
	}
	if typeOf.NumField() != len(want) {
		t.Fatalf("record fields = %d, want %d", typeOf.NumField(), len(want))
	}
	for index, name := range want {
		field := typeOf.Field(index)
		if field.Name != name || field.Tag.Get("json") == "" {
			t.Errorf("record field %d = %s %q", index, field.Name, field.Tag)
		}
	}
}

func TestL8RuntimeOwnerRecordValidationRejectsSubstitutionAndPIDReuse(t *testing.T) {
	seed := l8RuntimeOwnerTestSeed()
	bootID := "12345678-1234-4abc-8def-1234567890ab"
	record := l8RuntimeOwnerTestRecord(t, seed, bootID)
	if err := validateFirecrackerRuntimeOwnerRecordV1(record, seed, bootID); err != nil {
		t.Fatalf("valid record: %v", err)
	}
	supervisor := l8RuntimeOwnerProcessObservation{PID: record.SupervisorPID, ParentPID: 1, StartTime: record.SupervisorStartTime, state: 'S', pidfd: 10, pidfdOwned: true}
	firecracker := l8RuntimeOwnerProcessObservation{PID: record.FirecrackerPID, ParentPID: record.SupervisorPID, StartTime: record.FirecrackerStartTime, state: 'S', pidfd: 11, pidfdOwned: true}
	if err := validateL8RuntimeOwnerProcessCorrelation(record, supervisor, firecracker); err != nil {
		t.Fatalf("valid process correlation: %v", err)
	}
	for name, mutate := range map[string]func(*l8RuntimeOwnerProcessObservation){
		"PID reuse":     func(value *l8RuntimeOwnerProcessObservation) { value.StartTime++ },
		"replaced PID":  func(value *l8RuntimeOwnerProcessObservation) { value.PID++ },
		"zombie":        func(value *l8RuntimeOwnerProcessObservation) { value.state = 'Z' },
		"missing pidfd": func(value *l8RuntimeOwnerProcessObservation) { value.pidfd = -1 },
		"unowned pidfd": func(value *l8RuntimeOwnerProcessObservation) { value.pidfdOwned = false },
	} {
		t.Run("process "+name, func(t *testing.T) {
			mutated := firecracker
			mutate(&mutated)
			if err := validateL8RuntimeOwnerProcessCorrelation(record, supervisor, mutated); !errors.Is(err, errL8RuntimeOwnerInvalid) {
				t.Fatalf("correlation = %v", err)
			}
		})
	}
	mutations := map[string]func(*firecrackerRuntimeOwnerRecordV1){
		"old boot": func(value *firecrackerRuntimeOwnerRecordV1) {
			value.HostBootID = "22345678-1234-4abc-8def-1234567890ab"
		},
		"seed substitution":      func(value *firecrackerRuntimeOwnerRecordV1) { value.SeedCorrelationDigest = strings.Repeat("0", 64) },
		"partial child identity": func(value *firecrackerRuntimeOwnerRecordV1) { value.FirecrackerStartTime = 0 },
		"bad state":              func(value *firecrackerRuntimeOwnerRecordV1) { value.State = "running" },
		"finalized ID in absent": func(value *firecrackerRuntimeOwnerRecordV1) { value.FinalizedCommitID = l8RuntimeOwnerTestToken(9) },
		"invalid controller":     func(value *firecrackerRuntimeOwnerRecordV1) { value.ControllerState = "claimable" },
		"missing absence kind":   func(value *firecrackerRuntimeOwnerRecordV1) { value.AbsenceKind = "" },
		"wrong absence kind":     func(value *firecrackerRuntimeOwnerRecordV1) { value.AbsenceKind = "replacement_proc_absence" },
		"future absence revision": func(value *firecrackerRuntimeOwnerRecordV1) {
			value.AbsenceRevision = value.Revision + 1
		},
		"zero absence time": func(value *firecrackerRuntimeOwnerRecordV1) { value.AbsenceObservedAtUnixNano = 0 },
		"pre-seed absence time": func(value *firecrackerRuntimeOwnerRecordV1) {
			value.AbsenceObservedAtUnixNano = seed.IssuedAt.Add(-time.Nanosecond).UnixNano()
		},
		"finalize target in absent": func(value *firecrackerRuntimeOwnerRecordV1) { value.FinalizeTargetRevision = value.Revision + 1 },
		"safe field mismatch":       func(value *firecrackerRuntimeOwnerRecordV1) { value.RuntimeID = "runtime-neighbor" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := record
			mutate(&mutated)
			if err := validateFirecrackerRuntimeOwnerRecordV1(mutated, seed, bootID); !errors.Is(err, errL8RuntimeOwnerInvalid) {
				t.Fatalf("validation = %v", err)
			}
		})
	}
	starting := l8RuntimeOwnerTestGenesis(record)
	if err := validateFirecrackerRuntimeOwnerRecordV1(starting, seed, bootID); err != nil {
		t.Fatalf("revision-zero starting: %v", err)
	}
	revisionOne := starting
	revisionOne.Revision, revisionOne.FirecrackerPID, revisionOne.FirecrackerStartTime = 1, record.FirecrackerPID, record.FirecrackerStartTime
	if err := validateFirecrackerRuntimeOwnerRecordV1(revisionOne, seed, bootID); err != nil {
		t.Fatalf("revision-one starting: %v", err)
	}
	for name, candidate := range map[string]firecrackerRuntimeOwnerRecordV1{
		"starting revision two": func() firecrackerRuntimeOwnerRecordV1 { value := revisionOne; value.Revision = 2; return value }(),
		"starting claimed": func() firecrackerRuntimeOwnerRecordV1 {
			value := starting
			value.ControllerState = "unclaimed"
			return value
		}(),
		"running revision one": func() firecrackerRuntimeOwnerRecordV1 {
			value := revisionOne
			value.State = "running"
			value.ControllerState = "unclaimed"
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateFirecrackerRuntimeOwnerRecordV1(candidate, seed, bootID); !errors.Is(err, errL8RuntimeOwnerInvalid) {
				t.Fatalf("validation = %v", err)
			}
		})
	}

	finalizing := record
	finalizing.State = "finalizing"
	finalizing.Revision++
	finalizing.FinalizeTargetRevision = finalizing.Revision + 1
	finalizing.FinalizedCommitID = l8RuntimeOwnerTestToken(10)
	if err := validateFirecrackerRuntimeOwnerRecordV1(finalizing, seed, bootID); err != nil {
		t.Fatalf("valid finalizing: %v", err)
	}
	finalized := finalizing
	finalized.State = "finalized"
	finalized.Revision = finalizing.FinalizeTargetRevision
	if err := validateFirecrackerRuntimeOwnerRecordV1(finalized, seed, bootID); err != nil {
		t.Fatalf("valid finalized: %v", err)
	}
	for name, mutate := range map[string]func(*firecrackerRuntimeOwnerRecordV1){
		"finalizing wrong target": func(value *firecrackerRuntimeOwnerRecordV1) { value.FinalizeTargetRevision++ },
		"finalizing missing ID":   func(value *firecrackerRuntimeOwnerRecordV1) { value.FinalizedCommitID = "" },
		"finalized future target": func(value *firecrackerRuntimeOwnerRecordV1) { value.FinalizeTargetRevision = value.Revision + 1 },
		"finalized malformed ID":  func(value *firecrackerRuntimeOwnerRecordV1) { value.FinalizedCommitID = "not-a-token" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := finalizing
			if strings.HasPrefix(name, "finalized") {
				candidate = finalized
			}
			mutate(&candidate)
			if err := validateFirecrackerRuntimeOwnerRecordV1(candidate, seed, bootID); !errors.Is(err, errL8RuntimeOwnerInvalid) {
				t.Fatalf("validation = %v", err)
			}
		})
	}
}

func TestL8RuntimeOwnerRecordCodecIsStrictBoundedAndPanicFree(t *testing.T) {
	seed := l8RuntimeOwnerTestSeed()
	bootID := "12345678-1234-4abc-8def-1234567890ab"
	record := l8RuntimeOwnerTestRecord(t, seed, bootID)
	payload, err := encodeFirecrackerRuntimeOwnerRecordV1(record, seed, bootID)
	if err != nil || len(payload) == 0 || payload[len(payload)-1] != '\n' {
		t.Fatalf("encode record = %q, %v", payload, err)
	}
	decoded, err := decodeFirecrackerRuntimeOwnerRecordV1(payload, seed, bootID)
	if err != nil || decoded != record {
		t.Fatalf("decode record = %#v, %v", decoded, err)
	}
	genesisPayload, err := encodeFirecrackerRuntimeOwnerRecordV1(l8RuntimeOwnerTestGenesis(record), seed, bootID)
	if err != nil {
		t.Fatal(err)
	}
	badPayloads := [][]byte{
		nil,
		[]byte(`{"contractVersion":"firecracker-runtime-owner-private-v1","contractVersion":"duplicate"}` + "\n"),
		[]byte(strings.Replace(string(payload), `"contractVersion":`, `"ContractVersion":"substitution","contractVersion":`, 1)),
		[]byte(strings.Replace(string(genesisPayload), `"revision":0`, `"revision":null`, 1)),
		[]byte(strings.Replace(string(payload), `"finalizedCommitId":""`, `"finalizedCommitId":null`, 1)),
		append(append([]byte(nil), payload[:len(payload)-2]...), []byte(`,"unknown":true}`+"\n")...),
		append(append([]byte(nil), payload...), 'x'),
		[]byte(strings.Repeat("x", (16<<10)+1)),
	}
	for index, bad := range badPayloads {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("decode malformed %d panicked: %v", index, recovered)
				}
			}()
			if _, err := decodeFirecrackerRuntimeOwnerRecordV1(bad, seed, bootID); !errors.Is(err, errL8RuntimeOwnerInvalid) {
				t.Errorf("decode malformed %d = %v", index, err)
			}
		}()
	}
}

func TestL8RuntimeOwnerZeroProcessObservationDoesNotOwnFileDescriptor(t *testing.T) {
	if _, ok := reflect.TypeOf(l8RuntimeOwnerProcessObservation{}).FieldByName("pidfdOwned"); !ok {
		t.Fatal("process observation lacks explicit pidfd ownership")
	}
	observation := l8RuntimeOwnerProcessObservation{}
	if err := observation.Close(); err != nil {
		t.Fatalf("close zero observation: %v", err)
	}
}

func TestL8RuntimeOwnerLinuxStoreAndProcessInspectionArePrivate(t *testing.T) {
	if !l8RuntimeOwnerPlatformSupported() {
		t.Skip("Linux-only R1 foundation")
	}
	bootID, err := readL8RuntimeOwnerHostBootID()
	if err != nil || !validL8RuntimeOwnerHostBootID(bootID) {
		t.Fatalf("host boot ID = %q, %v", bootID, err)
	}
	observation, err := inspectL8RuntimeOwnerProcess(uint32(os.Getpid()))
	if err != nil || observation.StartTime == 0 || observation.PID != uint32(os.Getpid()) {
		t.Fatalf("self process observation = %#v, %v", observation, err)
	}
	if err := observation.Close(); err != nil {
		t.Fatalf("close observation: %v", err)
	}

	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	seed := l8RuntimeOwnerTestSeed()
	record := l8RuntimeOwnerTestRecord(t, seed, bootID)
	genesis := l8RuntimeOwnerTestGenesis(record)
	if err := writeL8RuntimeOwnerRecord(directory, genesis, seed, bootID); err != nil {
		t.Fatalf("write owner genesis: %v", err)
	}
	stored := genesis
	stored.Revision = 1
	stored.FirecrackerPID = record.FirecrackerPID
	stored.FirecrackerStartTime = record.FirecrackerStartTime
	if err := writeL8RuntimeOwnerRecord(directory, stored, seed, bootID); err != nil {
		t.Fatalf("write owner record: %v", err)
	}
	loaded, err := readL8RuntimeOwnerRecord(directory, seed, bootID)
	if err != nil || loaded != stored {
		t.Fatalf("read owner record = %#v, %v", loaded, err)
	}
	info, err := os.Lstat(filepath.Join(directory, l8RuntimeOwnerRecordName))
	if err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("record mode = %v, %v", info, err)
	}
	if err := os.Remove(filepath.Join(directory, l8RuntimeOwnerRecordName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(directory, "missing"), filepath.Join(directory, l8RuntimeOwnerRecordName)); err != nil {
		t.Fatal(err)
	}
	if _, err := readL8RuntimeOwnerRecord(directory, seed, bootID); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("symlink record read = %v", err)
	}
}

func l8RuntimeOwnerTestSeed() sandboxruntime.JobCredentialIdentitySeed {
	return sandboxruntime.JobCredentialIdentitySeed{
		SandboxID: "sandbox-1", ExecutionID: "execution-1", WorkerID: "worker-1", HostID: "host-1",
		RuntimeDriver: "microvm", RuntimeID: "runtime-1", RuntimeGeneration: "runtime-generation-1",
		FirecrackerProcessGeneration: "process-generation-1", VsockGeneration: "vsock-generation-1",
		WorkerJobID: "job-1", SubmissionID: "submission-1", PlanID: "plan-1",
		ActivationGeneration: "activation-generation-1", CredentialGeneration: "credential-generation-1",
		NetworkPlanID: "network-plan-1", PolicySnapshotID: "policy-snapshot-1", ProxySessionID: "proxy-session-1",
		ProxyGenerationID: "proxy-generation-1", TopologyGenerationID: "topology-generation-1", RuleGenerationID: "rule-generation-1",
		AdmissionGrantID: "grant-1", PrincipalID: "principal-1", TemplatePolicyID: "template-policy-1", WorkspacePolicyID: "workspace-policy-1",
		ControllerKeyGeneration: "controller-key-generation-1", GuestBootGeneration: "guest-boot-generation-1",
		GuestImageGeneration: "guest-image-generation-1", GuestImageDigest: "sha256-" + strings.Repeat("0", 64),
		AdmissionGrantRevision: 4, BindingIDs: []string{"binding-http", "binding-file"},
		DeliveryModes: []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeHTTPProxy, sandboxruntime.JobCredentialDeliveryModeFileTmpfs},
		IssuedAt:      time.Date(2026, time.August, 21, 8, 0, 0, 0, time.UTC),
	}
}

func l8RuntimeOwnerMutateSeedField(t *testing.T, seed sandboxruntime.JobCredentialIdentitySeed, name string) sandboxruntime.JobCredentialIdentitySeed {
	t.Helper()
	value := reflect.ValueOf(&seed).Elem().FieldByName(name)
	switch name {
	case "GuestImageDigest":
		value.SetString("sha256-" + strings.Repeat("1", 64))
	case "BindingIDs":
		value.Set(reflect.ValueOf([]string{"binding-file", "binding-http"}))
	case "DeliveryModes":
		value.Set(reflect.ValueOf([]sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeFileTmpfs, sandboxruntime.JobCredentialDeliveryModeHTTPProxy}))
	case "IssuedAt":
		value.Set(reflect.ValueOf(seed.IssuedAt.Add(time.Second)))
	default:
		switch value.Kind() {
		case reflect.String:
			value.SetString(value.String() + "-neighbor")
		case reflect.Uint64:
			value.SetUint(value.Uint() + 1)
		default:
			t.Fatalf("unsupported field %s", name)
		}
	}
	return seed
}

func l8RuntimeOwnerTestRecord(t *testing.T, seed sandboxruntime.JobCredentialIdentitySeed, bootID string) firecrackerRuntimeOwnerRecordV1 {
	t.Helper()
	digest, err := l8RuntimeOwnerSeedDigest(seed)
	if err != nil {
		t.Fatal(err)
	}
	return firecrackerRuntimeOwnerRecordV1{
		ContractVersion: "firecracker-runtime-owner-private-v1", Revision: 8, State: "absent", ControllerState: "unclaimed",
		AbsenceKind: "direct_wait", AbsenceRevision: 8, AbsenceObservedAtUnixNano: seed.IssuedAt.Add(time.Second).UnixNano(), HostBootID: bootID,
		SeedCorrelationDigest: hex.EncodeToString(digest[:]), SupervisorGeneration: l8RuntimeOwnerTestToken(1),
		SupervisorPID: 101, SupervisorStartTime: 202, FirecrackerPID: 303, FirecrackerStartTime: 404,
		SandboxID: seed.SandboxID, ExecutionID: seed.ExecutionID, WorkerID: seed.WorkerID, HostID: seed.HostID,
		RuntimeDriver: seed.RuntimeDriver, RuntimeID: seed.RuntimeID, RuntimeGeneration: seed.RuntimeGeneration,
		FirecrackerProcessGeneration: seed.FirecrackerProcessGeneration, VsockGeneration: seed.VsockGeneration,
		NetworkPlanID: seed.NetworkPlanID, PolicySnapshotID: seed.PolicySnapshotID, ProxySessionID: seed.ProxySessionID,
		ProxyGenerationID: seed.ProxyGenerationID, TopologyGenerationID: seed.TopologyGenerationID, RuleGenerationID: seed.RuleGenerationID,
		ReconnectListenerIdentity: l8RuntimeOwnerTestToken(2), ReconnectSecret: l8RuntimeOwnerTestToken(3),
	}
}

func l8RuntimeOwnerTestGenesis(record firecrackerRuntimeOwnerRecordV1) firecrackerRuntimeOwnerRecordV1 {
	record.Revision = 0
	record.State = "starting"
	record.ControllerState = "none"
	record.AbsenceKind = ""
	record.AbsenceRevision = 0
	record.AbsenceObservedAtUnixNano = 0
	record.FinalizeTargetRevision = 0
	record.FirecrackerPID = 0
	record.FirecrackerStartTime = 0
	return record
}

func l8RuntimeOwnerTestToken(fill byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{fill}), 32)))
}
