package v2control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const (
	testExecProxyURL      = "http://proxy-runtime/.well-known/hal/credential-http/v1/azure-openai-responses-v1/deployments/model-1"
	testExecNow           = int64(1700000000000)
	testExecJobEnd        = int64(1700001800000)
	testExecSessEnd       = int64(1700001900000)
	testExecSessionDigest = "iaQbfxpg50wx_Vd-KNW31vsy14Pncip3rlX9pNb4Tzw"
)

func TestCredentialExecExactRequestAndSuccessVectors(t *testing.T) {
	correlation := testCredentialExecCorrelation(t, validChildIdentity(t), true)
	plan := testCredentialExecPlan(t, true)
	request, err := NewCredentialExecRequest(testRequestID(t), correlation, plan)
	if err != nil {
		t.Fatal(err)
	}
	identityWire, err := MarshalJobIdentity(validChildIdentity(t))
	if err != nil {
		t.Fatal(err)
	}
	sessionIdentity := mustExecSessionIdentity(t, validChildIdentity(t))
	digest, err := GuestCredentialSessionIdentityDigest(sessionIdentity)
	if err != nil {
		t.Fatal(err)
	}
	jobDigest, err := JobIdentityDigest(validChildIdentity(t))
	if err != nil {
		t.Fatal(err)
	}
	if digest == jobDigest {
		t.Fatal("session-bound envelope digest collapsed to bare job identity digest")
	}
	if got := EncodeIdentityDigest(NewIdentityDigest(digest)); got != testExecSessionDigest {
		t.Fatalf("session digest vector = %q", got)
	}
	wantRequest := `{"protocolVersion":"guest-agent-v2","operation":"exec","requestId":"AQIDBAUGBwgJCgsMDQ4PEA","identityDigest":"` + testExecSessionDigest + `","body":{"identity":` + string(identityWire) + `,"revision":3,"execBindingId":"exec-binding-3","plan":{"args":["/usr/bin/tool","run"],"env":[{"name":"MODE","source":"literal","value":"batch"},{"name":"HTTP_PROXY","source":"generated","value":"` + testExecProxyURL + `"},{"name":"HTTPS_PROXY","source":"generated","value":"` + testExecProxyURL + `"},{"name":"http_proxy","source":"generated","value":"` + testExecProxyURL + `"},{"name":"https_proxy","source":"generated","value":"` + testExecProxyURL + `"}],"workDir":"/workspace","stdinMaxBytes":1024,"stdoutMaxBytes":2048,"stderrMaxBytes":4096,"timing":{"kind":"timeout_millis","value":30000}},"privateRecordCount":1,"privateAggregateBytes":321,"privateAggregateSha256":"` + strings.Repeat("a", 64) + `"}}`
	wire, err := EncodeCredentialExecRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if string(wire) != wantRequest {
		t.Fatalf("request wire:\n got %s\nwant %s", wire, wantRequest)
	}
	decoded, err := DecodeCredentialExecRequest(correlation, wire)
	if err != nil {
		t.Fatal(err)
	}
	assertCredentialExecRequest(t, decoded, request)

	emptyDigest := sha256.Sum256(nil)
	response, err := NewCredentialExecSuccessResponse(decoded, 7,
		0, hex.EncodeToString(emptyDigest[:]),
		2048, strings.Repeat("b", 64), true,
		3, strings.Repeat("c", 64), false,
		strings.Repeat("d", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	wantSuccess := `{"protocolVersion":"guest-agent-v2","operation":"exec","requestId":"AQIDBAUGBwgJCgsMDQ4PEA","identityDigest":"` + testExecSessionDigest + `","ok":true,"body":{"revision":3,"exitCode":7,"stdinBytes":0,"stdinSha256":"` + hex.EncodeToString(emptyDigest[:]) + `","stdoutBytes":2048,"stdoutSha256":"` + strings.Repeat("b", 64) + `","stdoutTruncated":true,"stderrBytes":3,"stderrSha256":"` + strings.Repeat("c", 64) + `","stderrTruncated":false,"execTransactionSha256":"` + strings.Repeat("d", 64) + `"}}`
	responseWire, err := EncodeCredentialExecSuccessResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if string(responseWire) != wantSuccess {
		t.Fatalf("success wire:\n got %s\nwant %s", responseWire, wantSuccess)
	}
	decodedResponse, err := DecodeCredentialExecSuccessResponse(decoded, responseWire)
	if err != nil {
		t.Fatal(err)
	}
	if decodedResponse.Revision() != 3 || decodedResponse.ExitCode() != 7 ||
		decodedResponse.StdoutBytes() != 2048 || !decodedResponse.StdoutTruncated() ||
		decodedResponse.StderrBytes() != 3 || decodedResponse.StderrTruncated() {
		t.Fatalf("decoded success metadata changed")
	}
}

func TestCredentialExecNoHTTPRequiresEmptyPrivateShapeAndNoProxyQuartet(t *testing.T) {
	identity := execIdentityWithoutHTTP(t)
	correlation := testCredentialExecCorrelation(t, identity, false)
	request, err := NewCredentialExecRequest(testRequestID(t), correlation, testCredentialExecPlan(t, false))
	if err != nil {
		t.Fatal(err)
	}
	if request.PrivateRecordCount() != 0 || request.PrivateAggregateBytes() != 0 || request.PrivateAggregateSHA256() != emptySHA256Hex {
		t.Fatal("no-HTTP private declaration is not the exact empty shape")
	}
	wire, err := EncodeCredentialExecRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "HTTP_PROXY") || strings.Contains(string(wire), testExecProxyURL) {
		t.Fatalf("no-HTTP request contains proxy environment: %s", wire)
	}
}

func TestExecPlanCatalogBoundsAndCorrelationMatrix(t *testing.T) {
	validTiming := mustExecTiming(t, ExecTimingTimeoutMillis, 1)
	validEnv := []ExecEnvironment{mustExecEnvironment(t, "MODE", ExecEnvironmentLiteral, "x")}
	tests := []struct {
		name    string
		args    []string
		env     []ExecEnvironment
		workDir string
		stdin   uint32
		stdout  uint32
		stderr  uint32
		timing  ExecTiming
	}{
		{name: "zero args", env: validEnv, workDir: "/w", stdin: 1, stdout: 1, stderr: 1, timing: validTiming},
		{name: "blank arg0", args: []string{" \t"}, env: validEnv, workDir: "/w", stdin: 1, stdout: 1, stderr: 1, timing: validTiming},
		{name: "arg control", args: []string{"a\n"}, env: validEnv, workDir: "/w", stdin: 1, stdout: 1, stderr: 1, timing: validTiming},
		{name: "arg too large", args: []string{strings.Repeat("a", MaxExecArgumentBytes+1)}, env: validEnv, workDir: "/w", stdin: 1, stdout: 1, stderr: 1, timing: validTiming},
		{name: "relative workdir", args: []string{"a"}, env: validEnv, workDir: "w", stdin: 1, stdout: 1, stderr: 1, timing: validTiming},
		{name: "unclean workdir", args: []string{"a"}, env: validEnv, workDir: "/w/../x", stdin: 1, stdout: 1, stderr: 1, timing: validTiming},
		{name: "zero stream", args: []string{"a"}, env: validEnv, workDir: "/w", stdout: 1, stderr: 1, timing: validTiming},
		{name: "stream too large", args: []string{"a"}, env: validEnv, workDir: "/w", stdin: MaxExecStreamBytes + 1, stdout: 1, stderr: 1, timing: validTiming},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewExecPlan(test.args, test.env, test.workDir, test.stdin, test.stdout, test.stderr, test.timing); !errors.Is(err, ErrInvalidExecPlan) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	for _, test := range []struct {
		name, source, value string
	}{
		{"ordinary lowercase", "literal", "x"},
		{"secret source", "secret", "x"},
		{"protected base", "literal", "x"},
		{"proxy literal", "literal", testExecProxyURL},
		{"value NUL", "literal", "x\x00y"},
	} {
		name := mapExecEnvironmentTestName(test.name)
		if _, err := NewExecEnvironment(name, ExecEnvironmentSource(test.source), test.value); !errors.Is(err, ErrInvalidExecEnvironment) {
			t.Errorf("%s error = %v", test.name, err)
		}
	}

	partial := []ExecEnvironment{mustExecEnvironment(t, "HTTP_PROXY", ExecEnvironmentGenerated, testExecProxyURL)}
	if _, err := NewExecPlan([]string{"a"}, partial, "/w", 1, 1, 1, validTiming); !errors.Is(err, ErrInvalidExecPlan) {
		t.Fatalf("partial quartet error = %v", err)
	}
	duplicate := append(validEnv, validEnv[0])
	if _, err := NewExecPlan([]string{"a"}, duplicate, "/w", 1, 1, 1, validTiming); !errors.Is(err, ErrInvalidExecPlan) {
		t.Fatalf("duplicate environment error = %v", err)
	}

	plan := testCredentialExecPlan(t, true)
	if err := ValidateExecPlanProxyBaseURL(plan, testExecProxyURL); err != nil {
		t.Fatal(err)
	}
	if err := ValidateExecPlanProxyBaseURL(plan, testExecProxyURL+"-other"); !errors.Is(err, ErrExecProxyCorrelationMismatch) {
		t.Fatalf("proxy mismatch error = %v", err)
	}
}

func TestCredentialExecTimingCorrelationUsesCallerTimeOnly(t *testing.T) {
	identity := validChildIdentity(t)
	tests := []struct {
		name    string
		kind    ExecTimingKind
		value   int64
		now     int64
		jobEnd  int64
		sessEnd int64
		valid   bool
	}{
		{name: "timeout at hard bound", kind: ExecTimingTimeoutMillis, value: 1000, now: testExecNow, jobEnd: testExecNow + 1000, sessEnd: testExecNow + 2000, valid: true},
		{name: "timeout beyond job", kind: ExecTimingTimeoutMillis, value: 1001, now: testExecNow, jobEnd: testExecNow + 1000, sessEnd: testExecNow + 2000},
		{name: "deadline at hard bound", kind: ExecTimingDeadlineUnixMillis, value: testExecNow + 1000, now: testExecNow, jobEnd: testExecNow + 2000, sessEnd: testExecNow + 1000, valid: true},
		{name: "deadline beyond session", kind: ExecTimingDeadlineUnixMillis, value: testExecNow + 1001, now: testExecNow, jobEnd: testExecNow + 2000, sessEnd: testExecNow + 1000},
		{name: "expired job", kind: ExecTimingTimeoutMillis, value: 1, now: testExecNow, jobEnd: testExecNow, sessEnd: testExecNow + 1000},
		{name: "hard lifetime over 35 minutes", kind: ExecTimingTimeoutMillis, value: 1, now: testExecNow, jobEnd: testExecNow + MaxExecHardLifetimeMillis + 1, sessEnd: testExecNow + 1000},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			timing := mustExecTiming(t, test.kind, test.value)
			environment := make([]ExecEnvironment, 0, 4)
			for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
				environment = append(environment, mustExecEnvironment(t, name, ExecEnvironmentGenerated, testExecProxyURL))
			}
			plan, err := NewExecPlan([]string{"a"}, environment, "/w", 1, 1, 1, timing)
			if err != nil {
				t.Fatal(err)
			}
			corr, err := NewCredentialExecCorrelation(mustExecSessionIdentity(t, identity), 3, "exec-binding-3", true, testExecProxyURL, 1, 1, strings.Repeat("a", 64), test.now, test.jobEnd, test.sessEnd)
			if err == nil {
				_, err = NewCredentialExecRequest(testRequestID(t), corr, plan)
			}
			if (err == nil) != test.valid {
				t.Fatalf("error = %v, valid=%t", err, test.valid)
			}
		})
	}
}

func TestCredentialExecStrictJSONMalformedTruncationAndTrailingMatrix(t *testing.T) {
	correlation := testCredentialExecCorrelation(t, validChildIdentity(t), true)
	request, err := NewCredentialExecRequest(testRequestID(t), correlation, testCredentialExecPlan(t, true))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeCredentialExecRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	text := string(wire)
	mutations := []string{
		" " + text, text + "\n", text + `{}`, `null`,
		strings.Replace(text, `"operation":"exec"`, `"operation":"Exec"`, 1),
		strings.Replace(text, `"body":{`, `"unknown":0,"body":{`, 1),
		strings.Replace(text, `"plan":{`, `"plan":null,"discard":{`, 1),
		strings.Replace(text, `"revision":3`, `"revision":3.0`, 1),
		strings.Replace(text, `"stdinMaxBytes":1024`, `"stdinMaxBytes":1.024e3`, 1),
		strings.Replace(text, `"protocolVersion":"guest-agent-v2"`, `"protocolVersion":"guest-agent-v2","protocolVersion":"guest-agent-v2"`, 1),
		strings.Replace(text, `"workDir":"/workspace"`, `"workDir":"/workspace","workDir":"/workspace"`, 1),
		strings.Replace(text, `"privateRecordCount":1`, `"privateRecordCount":null`, 1),
		strings.Replace(text, `"args":[`, `"args":null,"discard":[`, 1),
		strings.Replace(text, `"env":[`, `"env":null,"discard":[`, 1),
		strings.Replace(text, `"args":["/usr/bin/tool","run"],"env"`, `"env":[],"args":["/usr/bin/tool","run"],"discard"`, 1),
	}
	for index, mutation := range mutations {
		if _, err := DecodeCredentialExecRequest(correlation, []byte(mutation)); !errors.Is(err, ErrInvalidCredentialExecRequestJSON) {
			t.Errorf("mutation %d error = %v", index, err)
		}
	}
	for length := 0; length < len(wire); length++ {
		if _, err := DecodeCredentialExecRequest(correlation, wire[:length]); !errors.Is(err, ErrInvalidCredentialExecRequestJSON) {
			t.Fatalf("truncation %d error = %v", length, err)
		}
	}
	invalidUTF8 := append(append([]byte(nil), wire...), 0xff)
	if _, err := DecodeCredentialExecRequest(correlation, invalidUTF8); !errors.Is(err, ErrInvalidCredentialExecRequestJSON) {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
}

func TestCredentialExecPreparedCorrelationRejectsEveryMismatch(t *testing.T) {
	base := testCredentialExecCorrelation(t, validChildIdentity(t), true)
	request, err := NewCredentialExecRequest(testRequestID(t), base, testCredentialExecPlan(t, true))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeCredentialExecRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	otherIdentity := validChildIdentity(t)
	otherIdentity.SandboxID = "sandbox-2"
	otherSessionID := filledSessionID(0x2a)
	otherIdentity.GuestSessionGeneration = sessionGeneration(otherSessionID)
	tests := []CredentialExecCorrelation{
		mustCredentialExecCorrelationWithSessionID(t, otherSessionID, otherIdentity, 3, "exec-binding-3", true, testExecProxyURL, 1, 321, strings.Repeat("a", 64)),
		mustCredentialExecCorrelation(t, validChildIdentity(t), 4, "exec-binding-3", true, testExecProxyURL, 1, 321, strings.Repeat("a", 64)),
		mustCredentialExecCorrelation(t, validChildIdentity(t), 3, "exec-binding-4", true, testExecProxyURL, 1, 321, strings.Repeat("a", 64)),
		mustCredentialExecCorrelation(t, validChildIdentity(t), 3, "exec-binding-3", true, testExecProxyURL+"-other", 1, 321, strings.Repeat("a", 64)),
		mustCredentialExecCorrelation(t, validChildIdentity(t), 3, "exec-binding-3", true, testExecProxyURL, 1, 322, strings.Repeat("a", 64)),
		mustCredentialExecCorrelation(t, validChildIdentity(t), 3, "exec-binding-3", true, testExecProxyURL, 1, 321, strings.Repeat("b", 64)),
	}
	for index, correlation := range tests {
		if _, err := DecodeCredentialExecRequest(correlation, wire); !errors.Is(err, ErrCredentialExecCorrelationMismatch) {
			t.Errorf("mismatch %d error = %v", index, err)
		}
	}
}

func TestCredentialExecSuccessBoundsDigestsTruncationAndCorrelation(t *testing.T) {
	request := testCredentialExecRequest(t, true)
	empty := emptySHA256Hex
	tests := []struct {
		name                                           string
		exit                                           int32
		stdin, stdout, stderr                          uint64
		stdinHash, stdoutHash, stderrHash, transaction string
		stdoutTruncated, stderrTruncated               bool
	}{
		{name: "negative exit", exit: -1, stdinHash: empty, stdoutHash: empty, stderrHash: empty, transaction: strings.Repeat("d", 64)},
		{name: "stdin over max", stdin: 1025, stdinHash: strings.Repeat("a", 64), stdoutHash: empty, stderrHash: empty, transaction: strings.Repeat("d", 64)},
		{name: "stdout over max", stdout: 2049, stdinHash: empty, stdoutHash: strings.Repeat("b", 64), stderrHash: empty, transaction: strings.Repeat("d", 64)},
		{name: "stderr over max", stderr: 4097, stdinHash: empty, stdoutHash: empty, stderrHash: strings.Repeat("c", 64), transaction: strings.Repeat("d", 64)},
		{name: "empty stdin wrong digest", stdinHash: strings.Repeat("a", 64), stdoutHash: empty, stderrHash: empty, transaction: strings.Repeat("d", 64)},
		{name: "nonempty stdout empty digest", stdout: 1, stdinHash: empty, stdoutHash: empty, stderrHash: empty, transaction: strings.Repeat("d", 64)},
		{name: "stdout truncated below max", stdout: 2047, stdinHash: empty, stdoutHash: strings.Repeat("b", 64), stderrHash: empty, transaction: strings.Repeat("d", 64), stdoutTruncated: true},
		{name: "stderr truncated below max", stderr: 4095, stdinHash: empty, stdoutHash: empty, stderrHash: strings.Repeat("c", 64), transaction: strings.Repeat("d", 64), stderrTruncated: true},
		{name: "uppercase digest", stdinHash: empty, stdoutHash: empty, stderrHash: empty, transaction: strings.Repeat("D", 64)},
		{name: "missing transaction digest", stdinHash: empty, stdoutHash: empty, stderrHash: empty},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewCredentialExecSuccessResponse(request, test.exit,
				test.stdin, test.stdinHash, test.stdout, test.stdoutHash, test.stdoutTruncated,
				test.stderr, test.stderrHash, test.stderrTruncated, test.transaction)
			if !errors.Is(err, ErrInvalidCredentialExecSuccess) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	valid, err := NewCredentialExecSuccessResponse(request, 0, 0, empty, 0, empty, false, 0, empty, false, strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeCredentialExecSuccessResponse(valid)
	if err != nil {
		t.Fatal(err)
	}
	other := testCredentialExecRequestWithRequestID(t, 0x7f)
	if _, err := DecodeCredentialExecSuccessResponse(other, wire); !errors.Is(err, ErrCredentialExecSuccessCorrelationMismatch) {
		t.Fatalf("request correlation error = %v", err)
	}
	mutations := []string{
		strings.Replace(string(wire), `"revision":3`, `"revision":4`, 1),
		strings.Replace(string(wire), `"ok":true`, `"ok":false`, 1),
		strings.Replace(string(wire), `"stdoutBytes":0`, `"stdoutBytes":0.0`, 1),
		string(wire) + `{}`,
	}
	for index, mutation := range mutations {
		_, err := DecodeCredentialExecSuccessResponse(request, []byte(mutation))
		want := ErrInvalidCredentialExecSuccessJSON
		if index == 0 {
			want = ErrCredentialExecSuccessCorrelationMismatch
		}
		if !errors.Is(err, want) {
			t.Errorf("success mutation %d error = %v", index, err)
		}
	}
	for length := 0; length < len(wire); length++ {
		if _, err := DecodeCredentialExecSuccessResponse(request, wire[:length]); !errors.Is(err, ErrInvalidCredentialExecSuccessJSON) {
			t.Fatalf("success truncation %d error = %v", length, err)
		}
	}
}

func TestCredentialExecOpaqueFormattingSerializationAndCopySafety(t *testing.T) {
	correlation := testCredentialExecCorrelation(t, validChildIdentity(t), true)
	plan := testCredentialExecPlan(t, true)
	request, err := NewCredentialExecRequest(testRequestID(t), correlation, plan)
	if err != nil {
		t.Fatal(err)
	}
	response, err := NewCredentialExecSuccessResponse(request, 0, 0, emptySHA256Hex, 0, emptySHA256Hex, false, 0, emptySHA256Hex, false, strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	values := []struct {
		name        string
		value       any
		placeholder string
	}{
		{"environment", plan.Environment()[0], "<v2control.ExecEnvironment>"},
		{"timing", plan.Timing(), "<v2control.ExecTiming>"},
		{"plan", plan, "<v2control.ExecPlan>"},
		{"correlation", correlation, "<v2control.CredentialExecCorrelation>"},
		{"request", request, "<v2control.CredentialExecRequest>"},
		{"success", response, "<v2control.CredentialExecSuccessResponse>"},
	}
	for _, test := range values {
		for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
			if got := fmt.Sprintf(format, test.value); got != test.placeholder {
				t.Errorf("%s %s = %q", test.name, format, got)
			}
		}
		if _, err := json.Marshal(test.value); !errors.Is(err, ErrCredentialExecSerialization) {
			t.Errorf("%s JSON error = %v", test.name, err)
		}
	}

	before, err := EncodeCredentialExecRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"private":"value"}`), &request); !errors.Is(err, ErrCredentialExecSerialization) {
		t.Fatalf("denied unmarshal error = %v", err)
	}
	after, err := EncodeCredentialExecRequest(request)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatal("denied unmarshal mutated request")
	}

	args := plan.Args()
	args[0] = "changed"
	env := plan.Environment()
	env[0] = mustExecEnvironment(t, "OTHER", ExecEnvironmentLiteral, "changed")
	if plan.Args()[0] != "/usr/bin/tool" || plan.Environment()[0].Name() != "MODE" {
		t.Fatal("plan accessor exposed mutable backing state")
	}
	identity := request.Identity()
	identity.Bindings[0].BindingID = "changed"
	if request.Identity().Bindings[0].BindingID == "changed" {
		t.Fatal("request identity accessor exposed mutable backing state")
	}
}

func testCredentialExecCorrelation(t *testing.T, identity JobIdentity, hasHTTP bool) CredentialExecCorrelation {
	t.Helper()
	if hasHTTP {
		return mustCredentialExecCorrelation(t, identity, 3, "exec-binding-3", true, testExecProxyURL, 1, 321, strings.Repeat("a", 64))
	}
	return mustCredentialExecCorrelation(t, identity, 3, "exec-binding-3", false, "", 0, 0, emptySHA256Hex)
}

func mustCredentialExecCorrelation(t *testing.T, identity JobIdentity, revision uint64, binding string, hasHTTP bool, proxyURL string, count uint32, size uint64, digest string) CredentialExecCorrelation {
	t.Helper()
	return mustCredentialExecCorrelationWithSessionID(t, sequentialSessionID(), identity, revision, binding, hasHTTP, proxyURL, count, size, digest)
}

func mustCredentialExecCorrelationWithSessionID(t *testing.T, sessionID [32]byte, identity JobIdentity, revision uint64, binding string, hasHTTP bool, proxyURL string, count uint32, size uint64, digest string) CredentialExecCorrelation {
	t.Helper()
	sessionIdentity, err := NewGuestCredentialSessionIdentity(sessionID, identity)
	if err != nil {
		t.Fatal(err)
	}
	correlation, err := NewCredentialExecCorrelation(sessionIdentity, revision, binding, hasHTTP, proxyURL, count, size, digest, testExecNow, testExecJobEnd, testExecSessEnd)
	if err != nil {
		t.Fatal(err)
	}
	return correlation
}

func testCredentialExecPlan(t *testing.T, withHTTP bool) ExecPlan {
	t.Helper()
	env := []ExecEnvironment{mustExecEnvironment(t, "MODE", ExecEnvironmentLiteral, "batch")}
	if withHTTP {
		for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
			env = append(env, mustExecEnvironment(t, name, ExecEnvironmentGenerated, testExecProxyURL))
		}
	}
	plan, err := NewExecPlan([]string{"/usr/bin/tool", "run"}, env, "/workspace", 1024, 2048, 4096, mustExecTiming(t, ExecTimingTimeoutMillis, 30000))
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func testCredentialExecRequest(t *testing.T, withHTTP bool) CredentialExecRequest {
	t.Helper()
	identity := validChildIdentity(t)
	if !withHTTP {
		identity = execIdentityWithoutHTTP(t)
	}
	request, err := NewCredentialExecRequest(testRequestID(t), testCredentialExecCorrelation(t, identity, withHTTP), testCredentialExecPlan(t, withHTTP))
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func testCredentialExecRequestWithRequestID(t *testing.T, first byte) CredentialExecRequest {
	t.Helper()
	var raw [16]byte
	raw[0] = first
	id, err := NewRequestID(raw)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewCredentialExecRequest(id, testCredentialExecCorrelation(t, validChildIdentity(t), true), testCredentialExecPlan(t, true))
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func mustExecEnvironment(t *testing.T, name string, source ExecEnvironmentSource, value string) ExecEnvironment {
	t.Helper()
	env, err := NewExecEnvironment(name, source, value)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func mustExecTiming(t *testing.T, kind ExecTimingKind, value int64) ExecTiming {
	t.Helper()
	timing, err := NewExecTiming(kind, value)
	if err != nil {
		t.Fatal(err)
	}
	return timing
}

func execIdentityWithoutHTTP(t *testing.T) JobIdentity {
	t.Helper()
	identity := validChildIdentity(t)
	identity.Bindings = []JobBinding{{BindingID: "binding-file", Mode: DeliveryMode("file_tmpfs")}}
	identity.NetworkPlanID = ""
	identity.PolicySnapshotID = ""
	identity.ProxySessionID = ""
	identity.ProxyGenerationID = ""
	identity.TopologyGenerationID = ""
	identity.RuleGenerationID = ""
	if err := ValidateJobIdentity(identity); err != nil {
		t.Fatal(err)
	}
	return identity
}

func mustExecSessionIdentity(t *testing.T, identity JobIdentity) GuestCredentialSessionIdentity {
	t.Helper()
	sessionIdentity, err := NewGuestCredentialSessionIdentity(sequentialSessionID(), identity)
	if err != nil {
		t.Fatal(err)
	}
	return sessionIdentity
}

func assertCredentialExecRequest(t *testing.T, got, want CredentialExecRequest) {
	t.Helper()
	gotWire, gotErr := EncodeCredentialExecRequest(got)
	wantWire, wantErr := EncodeCredentialExecRequest(want)
	if gotErr != nil || wantErr != nil || !reflect.DeepEqual(gotWire, wantWire) {
		t.Fatalf("request mismatch: gotErr=%v wantErr=%v", gotErr, wantErr)
	}
}

func mapExecEnvironmentTestName(name string) string {
	switch name {
	case "ordinary lowercase":
		return "lowercase"
	case "protected base":
		return "AZURE_OPENAI_BASE_URL"
	case "proxy literal":
		return "HTTP_PROXY"
	default:
		return "MODE"
	}
}
