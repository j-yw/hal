package firecrackerhost

import (
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

func TestL8RuntimeOwnerRecordValidationRejectsSubstitutionAndPIDReuse(t *testing.T) {
	seed := l8RuntimeOwnerTestSeed()
	bootID := "12345678-1234-4abc-8def-1234567890ab"
	record := l8RuntimeOwnerTestRecord(t, seed, bootID)
	if err := validateFirecrackerRuntimeOwnerRecordV1(record, seed, bootID); err != nil {
		t.Fatalf("valid record: %v", err)
	}
	mutations := map[string]func(*firecrackerRuntimeOwnerRecordV1){
		"old boot": func(value *firecrackerRuntimeOwnerRecordV1) {
			value.HostBootID = "22345678-1234-4abc-8def-1234567890ab"
		},
		"seed substitution":      func(value *firecrackerRuntimeOwnerRecordV1) { value.SeedCorrelationDigest = strings.Repeat("0", 64) },
		"supervisor PID reuse":   func(value *firecrackerRuntimeOwnerRecordV1) { value.SupervisorStartTime++ },
		"firecracker PID reuse":  func(value *firecrackerRuntimeOwnerRecordV1) { value.FirecrackerStartTime++ },
		"partial child identity": func(value *firecrackerRuntimeOwnerRecordV1) { value.FirecrackerStartTime = 0 },
		"bad state":              func(value *firecrackerRuntimeOwnerRecordV1) { value.State = "running" },
		"finalized ID in absent": func(value *firecrackerRuntimeOwnerRecordV1) { value.FinalizedCommitID = l8RuntimeOwnerTestToken(9) },
		"safe field mismatch":    func(value *firecrackerRuntimeOwnerRecordV1) { value.RuntimeID = "runtime-neighbor" },
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
	starting := record
	starting.Revision, starting.State, starting.FirecrackerPID, starting.FirecrackerStartTime = 0, "starting", 0, 0
	if err := validateFirecrackerRuntimeOwnerRecordV1(starting, seed, bootID); err != nil {
		t.Fatalf("revision-zero starting: %v", err)
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
	badPayloads := [][]byte{
		nil,
		[]byte(`{"contractVersion":"firecracker-runtime-owner-private-v1","contractVersion":"duplicate"}` + "\n"),
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
	if err := writeL8RuntimeOwnerRecord(directory, record, seed, bootID); err != nil {
		t.Fatalf("write owner record: %v", err)
	}
	loaded, err := readL8RuntimeOwnerRecord(directory, seed, bootID)
	if err != nil || loaded != record {
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
		ContractVersion: "firecracker-runtime-owner-private-v1", Revision: 8, State: "absent", HostBootID: bootID,
		SeedCorrelationDigest: strings.ToLower(fmtHex(digest[:])), SupervisorGeneration: l8RuntimeOwnerTestToken(1),
		SupervisorPID: 101, SupervisorStartTime: 202, FirecrackerPID: 303, FirecrackerStartTime: 404,
		SandboxID: seed.SandboxID, ExecutionID: seed.ExecutionID, WorkerID: seed.WorkerID, HostID: seed.HostID,
		RuntimeDriver: seed.RuntimeDriver, RuntimeID: seed.RuntimeID, RuntimeGeneration: seed.RuntimeGeneration,
		FirecrackerProcessGeneration: seed.FirecrackerProcessGeneration, VsockGeneration: seed.VsockGeneration,
		NetworkPlanID: seed.NetworkPlanID, PolicySnapshotID: seed.PolicySnapshotID, ProxySessionID: seed.ProxySessionID,
		ProxyGenerationID: seed.ProxyGenerationID, TopologyGenerationID: seed.TopologyGenerationID, RuleGenerationID: seed.RuleGenerationID,
		ReconnectListenerIdentity: l8RuntimeOwnerTestToken(2), ReconnectSecret: l8RuntimeOwnerTestToken(3),
	}
}

func l8RuntimeOwnerTestToken(fill byte) string {
	return strings.TrimRight(base64URL([]byte(strings.Repeat(string([]byte{fill}), 32))), "=")
}

// Test-only red stubs. Green production removes this block unchanged from the
// behavioral tests above.
var errL8RuntimeOwnerInvalid = errors.New("runtime owner invalid")
var errL8RuntimeOwnerUnsupported = errors.New("runtime owner unsupported")

const l8RuntimeOwnerRecordName = "runtime-owner.json"

type firecrackerRuntimeOwnerRecordV1 struct {
	ContractVersion, State, HostBootID, SeedCorrelationDigest, SupervisorGeneration string
	Revision                                                                        uint64
	SupervisorPID                                                                   uint32
	SupervisorStartTime                                                             uint64
	FirecrackerPID                                                                  uint32
	FirecrackerStartTime                                                            uint64
	FinalizedCommitID, SandboxID, ExecutionID, WorkerID, HostID, RuntimeDriver      string
	RuntimeID, RuntimeGeneration, FirecrackerProcessGeneration, VsockGeneration     string
	NetworkPlanID, PolicySnapshotID, ProxySessionID, ProxyGenerationID              string
	TopologyGenerationID, RuleGenerationID, ReconnectListenerIdentity               string
	ReconnectSecret                                                                 string
}

type l8RuntimeOwnerProcessObservation struct {
	PID       uint32
	StartTime uint64
}

func (l8RuntimeOwnerProcessObservation) Close() error { return nil }
func l8RuntimeOwnerSeedDigest(sandboxruntime.JobCredentialIdentitySeed) ([32]byte, error) {
	return [32]byte{}, errL8RuntimeOwnerInvalid
}
func l8RuntimeOwnerCommitID([]byte, [32]byte, uint64) (string, error) {
	return "", errL8RuntimeOwnerInvalid
}
func validateFirecrackerRuntimeOwnerRecordV1(firecrackerRuntimeOwnerRecordV1, sandboxruntime.JobCredentialIdentitySeed, string) error {
	return errL8RuntimeOwnerInvalid
}
func encodeFirecrackerRuntimeOwnerRecordV1(firecrackerRuntimeOwnerRecordV1, sandboxruntime.JobCredentialIdentitySeed, string) ([]byte, error) {
	return nil, errL8RuntimeOwnerInvalid
}
func decodeFirecrackerRuntimeOwnerRecordV1([]byte, sandboxruntime.JobCredentialIdentitySeed, string) (firecrackerRuntimeOwnerRecordV1, error) {
	return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
}
func l8RuntimeOwnerPlatformSupported() bool { return false }
func readL8RuntimeOwnerHostBootID() (string, error) {
	return "", errL8RuntimeOwnerInvalid
}
func validL8RuntimeOwnerHostBootID(string) bool { return false }
func inspectL8RuntimeOwnerProcess(uint32) (l8RuntimeOwnerProcessObservation, error) {
	return l8RuntimeOwnerProcessObservation{}, errL8RuntimeOwnerInvalid
}
func writeL8RuntimeOwnerRecord(string, firecrackerRuntimeOwnerRecordV1, sandboxruntime.JobCredentialIdentitySeed, string) error {
	return errL8RuntimeOwnerInvalid
}
func readL8RuntimeOwnerRecord(string, sandboxruntime.JobCredentialIdentitySeed, string) (firecrackerRuntimeOwnerRecordV1, error) {
	return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
}

func fmtHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	output := make([]byte, len(value)*2)
	for index, item := range value {
		output[index*2], output[index*2+1] = alphabet[item>>4], alphabet[item&15]
	}
	return string(output)
}

func base64URL(value []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var result strings.Builder
	for index := 0; index < len(value); index += 3 {
		remaining := len(value) - index
		chunk := uint32(value[index]) << 16
		if remaining > 1 {
			chunk |= uint32(value[index+1]) << 8
		}
		if remaining > 2 {
			chunk |= uint32(value[index+2])
		}
		result.WriteByte(alphabet[(chunk>>18)&63])
		result.WriteByte(alphabet[(chunk>>12)&63])
		if remaining > 1 {
			result.WriteByte(alphabet[(chunk>>6)&63])
		}
		if remaining > 2 {
			result.WriteByte(alphabet[chunk&63])
		}
	}
	return result.String()
}
