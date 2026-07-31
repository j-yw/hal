package rootlesspodman

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

const (
	defaultRawPacketInspectBytes = int64(256 << 10)
	hardMaxRawPacketInspectBytes = int64(256 << 10)
	defaultRawPacketProcBytes    = int64(64 << 10)
	rawPacketProofPrefix         = "raw-packet-proof-"
)

var requiredPodmanDefaultCapabilityDrops = [...]string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_KILL",
	"CAP_NET_BIND_SERVICE",
	"CAP_SETFCAP",
	"CAP_SETGID",
	"CAP_SETPCAP",
	"CAP_SETUID",
	"CAP_SYS_CHROOT",
}

// ErrRawPacketIsolationUnverified is the redaction-safe fail-closed result for
// missing, stale, malformed, or mismatched live capability evidence.
var ErrRawPacketIsolationUnverified = errors.New("rootless Podman raw packet isolation unverified")

// RawPacketProcessInspector verifies the exact host process referred to by a
// Podman container's init PID. Implementations return no process metadata so
// PIDs and proc paths cannot be copied into safe proof or errors.
type RawPacketProcessInspector interface {
	VerifyRawPacketProcess(context.Context, int, int64) error
}

// PodmanRawPacketIsolationVerifierOptions supplies the exact stopped-created
// L7 runtime identity and the two independent live inspection boundaries.
// The target must carry the full Podman container ID, not a name or prefix.
type PodmanRawPacketIsolationVerifierOptions struct {
	LifecycleRunner  LifecycleCommandRunner
	ProcessInspector RawPacketProcessInspector
	PodmanPath       string
	Identity         NetworkTopologyIdentity
	Target           sandboxruntime.Target
	Now              func() time.Time
	MaxInspectBytes  int64
}

// PodmanRawPacketIsolationVerifier mechanically correlates Podman inspect
// state with the host's exact /proc init-process state. Its method shape
// intentionally satisfies linuxrules.RawPacketIsolationVerifier without
// importing the concrete linuxrules package and creating a package cycle.
type PodmanRawPacketIsolationVerifier struct {
	lifecycleRunner  LifecycleCommandRunner
	processInspector RawPacketProcessInspector
	podmanPath       string
	identity         NetworkTopologyIdentity
	target           sandboxruntime.Target
	now              func() time.Time
	maxInspectBytes  int64
	invalid          bool
}

// NewPodmanRawPacketIsolationVerifier constructs the explicit L7 verifier.
// Verification still fails closed until every live dependency and exact safe
// generation identity is present.
func NewPodmanRawPacketIsolationVerifier(options PodmanRawPacketIsolationVerifierOptions) *PodmanRawPacketIsolationVerifier {
	podmanPath := strings.TrimSpace(options.PodmanPath)
	if podmanPath == "" {
		podmanPath = DefaultPodmanExecutable
	}
	processInspector := options.ProcessInspector
	if processInspector == nil {
		processInspector = defaultRawPacketProcessInspector()
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	maxInspectBytes := options.MaxInspectBytes
	invalid := maxInspectBytes < 0 || maxInspectBytes > hardMaxRawPacketInspectBytes
	if maxInspectBytes == 0 {
		maxInspectBytes = defaultRawPacketInspectBytes
	}
	return &PodmanRawPacketIsolationVerifier{
		lifecycleRunner: options.LifecycleRunner, processInspector: processInspector,
		podmanPath: podmanPath, identity: options.Identity, target: options.Target,
		now: now, maxInspectBytes: maxInspectBytes, invalid: invalid,
	}
}

func (v *PodmanRawPacketIsolationVerifier) VerifyRawPacketIsolation(ctx context.Context, correlation networkenforcement.EnforcementCorrelation) (networkenforcement.RawPacketIsolationProof, error) {
	if v == nil || v.invalid || v.lifecycleRunner == nil || v.processInspector == nil || v.now == nil ||
		!validNetworkTopologyIdentity(v.identity) || !validRawPacketIsolationTarget(v.target) ||
		!networkenforcement.EnforcementCorrelationsEqual(correlation, rawPacketIsolationCorrelation(v.identity)) {
		return networkenforcement.RawPacketIsolationProof{}, rawPacketIsolationError()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return networkenforcement.RawPacketIsolationProof{}, rawPacketIsolationError()
	}

	before, err := v.inspectExactContainer(ctx)
	if err != nil {
		return networkenforcement.RawPacketIsolationProof{}, rawPacketIsolationError()
	}
	if err := v.processInspector.VerifyRawPacketProcess(ctx, before.PID, defaultRawPacketProcBytes); err != nil {
		return networkenforcement.RawPacketIsolationProof{}, rawPacketIsolationError()
	}
	if err := ctx.Err(); err != nil {
		return networkenforcement.RawPacketIsolationProof{}, rawPacketIsolationError()
	}
	after, err := v.inspectExactContainer(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		return networkenforcement.RawPacketIsolationProof{}, rawPacketIsolationError()
	}

	verifiedAt := v.now().UnixMilli()
	if verifiedAt <= 0 {
		return networkenforcement.RawPacketIsolationProof{}, rawPacketIsolationError()
	}
	proofCorrelation := networkenforcement.SanitizeEnforcementCorrelation(correlation)
	proof := networkenforcement.SanitizeRawPacketIsolationProof(networkenforcement.RawPacketIsolationProof{
		ID:                  rawPacketIsolationProofID(proofCorrelation),
		Status:              networkenforcement.RawPacketIsolationStatusVerified,
		VerifiedAtUnixMilli: verifiedAt,
		Correlation:         &proofCorrelation,
		ReasonCode:          networkenforcement.LifecycleReasonRawPacketIsolationVerified,
	})
	if !networkenforcement.RawPacketIsolationProofMatches(proof, correlation) {
		return networkenforcement.RawPacketIsolationProof{}, rawPacketIsolationError()
	}
	return proof, nil
}

type rawPacketContainerInspection struct {
	ID          string
	Name        string
	PID         int
	StartedAt   string
	Labels      map[string]string
	Privileged  bool
	NetworkMode string
	CapAdd      []string
	CapDrop     []string
	SecurityOpt []string
	Binds       []string
	Mounts      []rawPacketInspectMount
}

type rawPacketInspectPayload struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	State struct {
		Running   *bool  `json:"Running"`
		Status    string `json:"Status"`
		PID       *int   `json:"Pid"`
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		Privileged  *bool    `json:"Privileged"`
		NetworkMode string   `json:"NetworkMode"`
		CapAdd      []string `json:"CapAdd"`
		CapDrop     []string `json:"CapDrop"`
		SecurityOpt []string `json:"SecurityOpt"`
		Binds       []string `json:"Binds"`
	} `json:"HostConfig"`
	Mounts []rawPacketInspectMount `json:"Mounts"`
}

type rawPacketInspectMount struct {
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
}

func (v *PodmanRawPacketIsolationVerifier) inspectExactContainer(ctx context.Context) (rawPacketContainerInspection, error) {
	result, err := v.lifecycleRunner.RunLifecycleCommand(ctx, CommandRequest{
		Operation: OperationInspect,
		Args:      []string{v.podmanPath, "inspect", "--type", "container", v.target.Runtime.RuntimeID},
	})
	if err != nil || result.ExitCode != 0 || len(result.Stdout) == 0 || int64(len(result.Stdout)) > v.maxInspectBytes {
		return rawPacketContainerInspection{}, ErrRawPacketIsolationUnverified
	}
	if err := rejectDuplicateJSONKeys([]byte(result.Stdout)); err != nil {
		return rawPacketContainerInspection{}, ErrRawPacketIsolationUnverified
	}
	decoder := json.NewDecoder(strings.NewReader(result.Stdout))
	decoder.UseNumber()
	var payloads []rawPacketInspectPayload
	if err := decoder.Decode(&payloads); err != nil || len(payloads) != 1 {
		return rawPacketContainerInspection{}, ErrRawPacketIsolationUnverified
	}
	if err := requireJSONEOF(decoder); err != nil {
		return rawPacketContainerInspection{}, ErrRawPacketIsolationUnverified
	}
	return v.validateRawPacketInspectPayload(payloads[0])
}

func (v *PodmanRawPacketIsolationVerifier) validateRawPacketInspectPayload(payload rawPacketInspectPayload) (rawPacketContainerInspection, error) {
	if payload.ID != v.target.Runtime.RuntimeID || payload.ID != v.target.ID || payload.Name != v.target.Name ||
		payload.State.Running == nil || !*payload.State.Running || payload.State.Status != "running" ||
		payload.State.PID == nil || *payload.State.PID <= 1 || *payload.State.PID > 1<<30 ||
		payload.State.StartedAt == "" || !validRawPacketStartedAt(payload.State.StartedAt) ||
		payload.HostConfig.Privileged == nil || *payload.HostConfig.Privileged ||
		!validRawPacketNetworkMode(payload.HostConfig.NetworkMode) ||
		payload.HostConfig.CapAdd == nil || len(payload.HostConfig.CapAdd) != 0 ||
		!validRawPacketCapDrop(payload.HostConfig.CapDrop) ||
		!validRawPacketSecurityOpt(payload.HostConfig.SecurityOpt) ||
		payload.HostConfig.Binds == nil || len(payload.HostConfig.Binds) != 0 ||
		payload.Mounts == nil || len(payload.Mounts) != 0 ||
		!rawPacketLabelsMatch(payload.Config.Labels, v.identity, v.target.Name) {
		return rawPacketContainerInspection{}, ErrRawPacketIsolationUnverified
	}
	return rawPacketContainerInspection{
		ID: payload.ID, Name: payload.Name, PID: *payload.State.PID, StartedAt: payload.State.StartedAt,
		Labels: cloneStringMap(payload.Config.Labels), Privileged: *payload.HostConfig.Privileged,
		NetworkMode: payload.HostConfig.NetworkMode, CapAdd: cloneStringSlice(payload.HostConfig.CapAdd),
		CapDrop: cloneStringSlice(payload.HostConfig.CapDrop), SecurityOpt: cloneStringSlice(payload.HostConfig.SecurityOpt),
		Binds: cloneStringSlice(payload.HostConfig.Binds), Mounts: append([]rawPacketInspectMount(nil), payload.Mounts...),
	}, nil
}

func validRawPacketIsolationTarget(target sandboxruntime.Target) bool {
	return safeTopologyIdentifier(target.ID) && safeTopologyIdentifier(target.Name) &&
		target.ID == target.Runtime.RuntimeID && target.Runtime.Driver == DriverID
}

func validRawPacketStartedAt(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && !parsed.IsZero()
}

func validRawPacketNetworkMode(value string) bool {
	value = strings.TrimSpace(value)
	return value == "pasta" || strings.HasPrefix(value, "pasta:")
}

func validRawPacketCapDrop(values []string) bool {
	if len(values) == 0 {
		return false
	}
	seen := make(map[string]bool, len(values))
	for _, raw := range values {
		value := strings.ToUpper(strings.TrimSpace(raw))
		if value == "ALL" || value == "CAP_ALL" {
			return len(values) == 1
		}
		if seen[value] || !strings.HasPrefix(value, "CAP_") || !safeCapabilityName(value) {
			return false
		}
		seen[value] = true
	}
	for _, required := range requiredPodmanDefaultCapabilityDrops {
		if !seen[required] {
			return false
		}
	}
	return true
}

func safeCapabilityName(value string) bool {
	if len(value) <= len("CAP_") || len(value) > 64 {
		return false
	}
	for _, r := range value[len("CAP_"):] {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

func validRawPacketSecurityOpt(values []string) bool {
	if len(values) != 1 {
		return false
	}
	value := strings.ToLower(strings.TrimSpace(values[0]))
	return value == "no-new-privileges" || value == "no-new-privileges=true"
}

func rawPacketLabelsMatch(labels map[string]string, identity NetworkTopologyIdentity, name string) bool {
	if labels == nil {
		return false
	}
	expected := map[string]string{
		labelRuntime: DriverID, labelSandboxName: name,
		topologyGenerationLabel: identity.TopologyGenerationID,
		runtimeGenerationLabel:  identity.RuntimeGenerationID,
		ruleGenerationLabel:     identity.RuleGenerationID,
	}
	for key, value := range expected {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func rawPacketIsolationCorrelation(identity NetworkTopologyIdentity) networkenforcement.EnforcementCorrelation {
	return networkenforcement.EnforcementCorrelation{
		SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID, WorkerID: identity.WorkerID,
		RuntimeID: identity.RuntimeGenerationID, PlanID: identity.PlanID, PolicySnapshotID: identity.PolicySnapshotID,
		ProxySessionID: identity.ProxySessionID, ProxyGenerationID: identity.ProxyGenerationID,
		TopologyGenerationID: identity.TopologyGenerationID, RuleGenerationID: identity.RuleGenerationID,
	}
}

func rawPacketIsolationProofID(correlation networkenforcement.EnforcementCorrelation) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{
		correlation.SandboxID, correlation.ExecutionID, correlation.WorkerID, correlation.RuntimeID,
		correlation.PlanID, correlation.PolicySnapshotID, correlation.ProxySessionID,
		correlation.ProxyGenerationID, correlation.TopologyGenerationID, correlation.RuleGenerationID,
	}, "\x00")))
	return rawPacketProofPrefix + hex.EncodeToString(digest[:16])
}

func rawPacketIsolationError() error {
	return fmt.Errorf("rootless Podman raw packet verification failed: %w", ErrRawPacketIsolationUnverified)
}

func rejectDuplicateJSONKeys(payload []byte) error {
	if len(payload) == 0 || bytes.IndexByte(payload, 0) >= 0 {
		return ErrRawPacketIsolationUnverified
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := consumeStrictJSONValue(decoder); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func consumeStrictJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return ErrRawPacketIsolationUnverified
			}
			seen[key] = true
			if err := consumeStrictJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrRawPacketIsolationUnverified
		}
	case '[':
		for decoder.More() {
			if err := consumeStrictJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrRawPacketIsolationUnverified
		}
	default:
		return ErrRawPacketIsolationUnverified
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return ErrRawPacketIsolationUnverified
}

func validateRawPacketProcStatus(payload []byte, maxBytes int64) error {
	if maxBytes <= 0 || len(payload) == 0 || int64(len(payload)) > maxBytes || payload[len(payload)-1] != '\n' || bytes.IndexByte(payload, 0) >= 0 {
		return ErrRawPacketIsolationUnverified
	}
	required := map[string]string{
		"CapInh": "0000000000000000", "CapPrm": "0000000000000000",
		"CapEff": "0000000000000000", "CapBnd": "0000000000000000",
		"CapAmb": "0000000000000000", "NoNewPrivs": "1",
	}
	seen := make(map[string]bool, len(required))
	for _, line := range strings.Split(string(payload[:len(payload)-1]), "\n") {
		if strings.ContainsRune(line, '\r') {
			return ErrRawPacketIsolationUnverified
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		expected, requiredField := required[key]
		if !requiredField {
			continue
		}
		if seen[key] || strings.TrimSpace(value) != expected {
			return ErrRawPacketIsolationUnverified
		}
		seen[key] = true
	}
	for key := range required {
		if !seen[key] {
			return ErrRawPacketIsolationUnverified
		}
	}
	return nil
}

func parseRawPacketProcStartTime(payload []byte, expectedPID int) (string, error) {
	if len(payload) == 0 || payload[len(payload)-1] != '\n' || bytes.IndexByte(payload, 0) >= 0 {
		return "", ErrRawPacketIsolationUnverified
	}
	line := strings.TrimSuffix(string(payload), "\n")
	firstSpace := strings.IndexByte(line, ' ')
	lastParen := strings.LastIndexByte(line, ')')
	if firstSpace <= 0 || lastParen <= firstSpace || lastParen+2 > len(line) {
		return "", ErrRawPacketIsolationUnverified
	}
	pid, err := strconv.Atoi(line[:firstSpace])
	if err != nil || pid != expectedPID {
		return "", ErrRawPacketIsolationUnverified
	}
	fields := strings.Fields(line[lastParen+1:])
	if len(fields) < 20 {
		return "", ErrRawPacketIsolationUnverified
	}
	startTime := fields[19]
	value, err := strconv.ParseUint(startTime, 10, 64)
	if err != nil || value == 0 || strconv.FormatUint(value, 10) != startTime {
		return "", ErrRawPacketIsolationUnverified
	}
	return startTime, nil
}
