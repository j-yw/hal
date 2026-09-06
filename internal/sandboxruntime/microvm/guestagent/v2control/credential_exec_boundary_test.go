package v2control

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

func TestExecPlanEveryScalarAndAggregateBoundary(t *testing.T) {
	timeoutMaximum := mustExecTiming(t, ExecTimingTimeoutMillis, MaxExecTimeoutMillis)
	deadlineMinimum := mustExecTiming(t, ExecTimingDeadlineUnixMillis, MinExecDeadlineMillis)
	deadlineMaximum := mustExecTiming(t, ExecTimingDeadlineUnixMillis, MaxExecDeadlineMillis)
	for _, timing := range []ExecTiming{timeoutMaximum, deadlineMinimum, deadlineMaximum} {
		if _, err := NewExecPlan([]string{"a"}, nil, "/w", MaxExecStreamBytes, MaxExecStreamBytes, MaxExecStreamBytes, timing); err != nil {
			t.Fatalf("valid boundary plan: %v", err)
		}
	}
	for _, test := range []struct {
		kind  ExecTimingKind
		value int64
	}{
		{ExecTimingTimeoutMillis, 0},
		{ExecTimingTimeoutMillis, MaxExecTimeoutMillis + 1},
		{ExecTimingDeadlineUnixMillis, MinExecDeadlineMillis - 1},
		{ExecTimingDeadlineUnixMillis, MaxExecDeadlineMillis + 1},
		{ExecTimingKind("timeoutMillis"), 1},
	} {
		if _, err := NewExecTiming(test.kind, test.value); !errors.Is(err, ErrInvalidExecTiming) {
			t.Errorf("timing %q/%d error = %v", test.kind, test.value, err)
		}
	}

	maximumArgument := strings.Repeat("a", MaxExecArgumentBytes)
	if _, err := NewExecPlan([]string{maximumArgument}, nil, "/w", 1, 1, 1, timeoutMaximum); err != nil {
		t.Fatalf("maximum argument: %v", err)
	}
	maximumArguments := make([]string, MaxExecArguments)
	for index := range maximumArguments {
		maximumArguments[index] = "a"
	}
	if _, err := NewExecPlan(maximumArguments, nil, "/w", 1, 1, 1, timeoutMaximum); err != nil {
		t.Fatalf("maximum argument count: %v", err)
	}
	if _, err := NewExecPlan(append(maximumArguments, "a"), nil, "/w", 1, 1, 1, timeoutMaximum); !errors.Is(err, ErrInvalidExecPlan) {
		t.Fatalf("argument count plus one error = %v", err)
	}
	if _, err := NewExecPlan([]string{string([]byte{0xff})}, nil, "/w", 1, 1, 1, timeoutMaximum); !errors.Is(err, ErrInvalidExecPlan) {
		t.Fatalf("invalid argument UTF-8 error = %v", err)
	}

	maximumName := "A" + strings.Repeat("Z", MaxExecEnvironmentNameBytes-1)
	maximumValue := strings.Repeat("v", MaxExecEnvironmentValueBytes)
	maximumEntry := mustExecEnvironment(t, maximumName, ExecEnvironmentLiteral, maximumValue)
	if _, err := NewExecPlan([]string{"a"}, []ExecEnvironment{maximumEntry}, "/w", 1, 1, 1, timeoutMaximum); err != nil {
		t.Fatalf("maximum environment scalar: %v", err)
	}
	if _, err := NewExecEnvironment(maximumName+"Z", ExecEnvironmentLiteral, ""); !errors.Is(err, ErrInvalidExecEnvironment) {
		t.Fatalf("environment name plus one error = %v", err)
	}
	if _, err := NewExecEnvironment("A", ExecEnvironmentLiteral, maximumValue+"v"); !errors.Is(err, ErrInvalidExecEnvironment) {
		t.Fatalf("environment value plus one error = %v", err)
	}
	maximumEnvironment := make([]ExecEnvironment, MaxExecEnvironmentEntries)
	for index := range maximumEnvironment {
		maximumEnvironment[index] = mustExecEnvironment(t, fmt.Sprintf("E_%03d", index), ExecEnvironmentInherited, "")
	}
	if _, err := NewExecPlan([]string{"a"}, maximumEnvironment, "/w", 1, 1, 1, timeoutMaximum); err != nil {
		t.Fatalf("maximum environment count: %v", err)
	}
	plusOneEnvironment := append(append([]ExecEnvironment(nil), maximumEnvironment...), mustExecEnvironment(t, "E_EXTRA", ExecEnvironmentLiteral, ""))
	if _, err := NewExecPlan([]string{"a"}, plusOneEnvironment, "/w", 1, 1, 1, timeoutMaximum); !errors.Is(err, ErrInvalidExecPlan) {
		t.Fatalf("environment count plus one error = %v", err)
	}

	maximumWorkDirectory := "/" + strings.Repeat("w", MaxExecWorkDirectoryBytes-1)
	if _, err := NewExecPlan([]string{"a"}, nil, maximumWorkDirectory, 1, 1, 1, timeoutMaximum); err != nil {
		t.Fatalf("maximum work directory: %v", err)
	}
	for _, workDirectory := range []string{
		maximumWorkDirectory + "w", "/w/", "/w//x", "/w\\x", "/w\x00x", "/w\nx", " /w", "/w ", "https://host/path",
	} {
		if _, err := NewExecPlan([]string{"a"}, nil, workDirectory, 1, 1, 1, timeoutMaximum); !errors.Is(err, ErrInvalidExecPlan) {
			t.Errorf("work directory %q error = %v", workDirectory, err)
		}
	}

	exactAggregateArgs := make([]string, 8)
	for index := 0; index < 7; index++ {
		exactAggregateArgs[index] = strings.Repeat("a", MaxExecArgumentBytes)
	}
	exactAggregateArgs[7] = strings.Repeat("a", 8144)
	exactPlan, err := NewExecPlan(exactAggregateArgs, nil, "/w", 1, 1, 1, timeoutMaximum)
	if err != nil {
		t.Fatal(err)
	}
	if got := execPlanBinaryLength(exactPlan); got != MaxExecPlanBytes {
		t.Fatalf("exact aggregate length = %d", got)
	}
	exactAggregateArgs[7] += "a"
	if _, err := NewExecPlan(exactAggregateArgs, nil, "/w", 1, 1, 1, timeoutMaximum); !errors.Is(err, ErrInvalidExecPlan) {
		t.Fatalf("aggregate plus one error = %v", err)
	}
}

func TestExecPlanControlPredicateExactlyMatchesFrozenV1(t *testing.T) {
	timing := mustExecTiming(t, ExecTimingTimeoutMillis, 1)
	for _, value := range []string{"argument-\u0080", "/work-\u0080"} {
		args, workDirectory := []string{value}, "/work"
		if strings.HasPrefix(value, "/") {
			args, workDirectory = []string{"tool"}, value
		}
		if _, err := NewExecPlan(args, nil, workDirectory, 1, 1, 1, timing); err != nil {
			t.Errorf("frozen-v1 non-ASCII control boundary %q rejected: %v", value, err)
		}
	}
	for _, character := range []rune{0x1f, 0x7f} {
		if _, err := NewExecPlan([]string{"tool" + string(character)}, nil, "/work", 1, 1, 1, timing); !errors.Is(err, ErrInvalidExecPlan) {
			t.Errorf("argument control U+%04X error = %v", character, err)
		}
		if _, err := NewExecPlan([]string{"tool"}, nil, "/work"+string(character), 1, 1, 1, timing); !errors.Is(err, ErrInvalidExecPlan) {
			t.Errorf("work directory control U+%04X error = %v", character, err)
		}
	}
}

func TestCredentialExecPrivateShapeAndPreparedHTTPBoundaryMatrix(t *testing.T) {
	httpIdentity := validChildIdentity(t)
	noHTTPIdentity := execIdentityWithoutHTTP(t)
	validDigest := strings.Repeat("a", 64)
	tests := []struct {
		name      string
		identity  JobIdentity
		hasHTTP   bool
		proxy     string
		count     uint32
		bytes     uint64
		digest    string
		revision  uint64
		binding   string
		wantValid bool
	}{
		{name: "HTTP minimum", identity: httpIdentity, hasHTTP: true, proxy: testExecProxyURL, count: 1, bytes: 1, digest: validDigest, revision: 1, binding: "x", wantValid: true},
		{name: "HTTP maximum", identity: httpIdentity, hasHTTP: true, proxy: testExecProxyURL, count: 1, bytes: MaxExecPrivateBytes, digest: validDigest, revision: 1, binding: "x", wantValid: true},
		{name: "HTTP zero count", identity: httpIdentity, hasHTTP: true, proxy: testExecProxyURL, bytes: 1, digest: validDigest, revision: 1, binding: "x"},
		{name: "HTTP count two", identity: httpIdentity, hasHTTP: true, proxy: testExecProxyURL, count: 2, bytes: 1, digest: validDigest, revision: 1, binding: "x"},
		{name: "HTTP zero bytes", identity: httpIdentity, hasHTTP: true, proxy: testExecProxyURL, count: 1, digest: validDigest, revision: 1, binding: "x"},
		{name: "HTTP bytes plus one", identity: httpIdentity, hasHTTP: true, proxy: testExecProxyURL, count: 1, bytes: MaxExecPrivateBytes + 1, digest: validDigest, revision: 1, binding: "x"},
		{name: "HTTP empty digest", identity: httpIdentity, hasHTTP: true, proxy: testExecProxyURL, count: 1, bytes: 1, digest: emptySHA256Hex, revision: 1, binding: "x"},
		{name: "HTTP uppercase digest", identity: httpIdentity, hasHTTP: true, proxy: testExecProxyURL, count: 1, bytes: 1, digest: strings.Repeat("A", 64), revision: 1, binding: "x"},
		{name: "HTTP missing proxy", identity: httpIdentity, hasHTTP: true, count: 1, bytes: 1, digest: validDigest, revision: 1, binding: "x"},
		{name: "HTTP shape false", identity: httpIdentity, proxy: "", digest: emptySHA256Hex, revision: 1, binding: "x"},
		{name: "no HTTP exact empty", identity: noHTTPIdentity, digest: emptySHA256Hex, revision: 1, binding: "x", wantValid: true},
		{name: "no HTTP private", identity: noHTTPIdentity, count: 1, bytes: 1, digest: validDigest, revision: 1, binding: "x"},
		{name: "no HTTP proxy", identity: noHTTPIdentity, proxy: testExecProxyURL, digest: emptySHA256Hex, revision: 1, binding: "x"},
		{name: "zero revision", identity: noHTTPIdentity, digest: emptySHA256Hex, binding: "x"},
		{name: "unsafe binding", identity: noHTTPIdentity, digest: emptySHA256Hex, revision: 1, binding: "private/path"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewCredentialExecCorrelation(mustExecSessionIdentity(t, test.identity), test.revision, test.binding,
				test.hasHTTP, test.proxy, test.count, test.bytes, test.digest,
				testExecNow, testExecJobEnd, testExecSessEnd)
			if (err == nil) != test.wantValid {
				t.Fatalf("error = %v, valid=%t", err, test.wantValid)
			}
		})
	}
}

func TestCredentialExecRequestEveryRequiredFieldRejectsOmissionNullDuplicateAndCaseAlias(t *testing.T) {
	request := testCredentialExecRequest(t, true)
	correlation := request.state.correlation
	wire, err := EncodeCredentialExecRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	identityWire, err := MarshalJobIdentity(request.Identity())
	if err != nil {
		t.Fatal(err)
	}
	fields := []string{
		`"protocolVersion":"guest-agent-v2"`, `"operation":"exec"`,
		`"requestId":"AQIDBAUGBwgJCgsMDQ4PEA"`, `"identityDigest":"` + EncodeIdentityDigest(request.IdentityDigest()) + `"`,
		`"identity":` + string(identityWire), `"revision":3`, `"execBindingId":"exec-binding-3"`,
		`"args":["/usr/bin/tool","run"]`,
		`"name":"MODE"`, `"source":"literal"`, `"value":"batch"`,
		`"workDir":"/workspace"`, `"stdinMaxBytes":1024`, `"stdoutMaxBytes":2048`, `"stderrMaxBytes":4096`,
		`"kind":"timeout_millis"`, `"value":30000`,
		`"privateRecordCount":1`, `"privateAggregateBytes":321`, `"privateAggregateSha256":"` + strings.Repeat("a", 64) + `"`,
	}
	for _, field := range fields {
		field := field
		t.Run(field[:min(len(field), 40)], func(t *testing.T) {
			for name, mutation := range map[string]string{
				"omitted":    omitExactJSONField(t, string(wire), field),
				"null":       replaceExactJSONFieldWithNull(t, string(wire), field),
				"duplicate":  duplicateExactJSONField(t, string(wire), field),
				"case alias": caseAliasExactJSONField(t, string(wire), field),
			} {
				if _, err := DecodeCredentialExecRequest(correlation, []byte(mutation)); !errors.Is(err, ErrInvalidCredentialExecRequestJSON) {
					t.Errorf("%s error = %v", name, err)
				}
			}
		})
	}
}

func TestCredentialExecRequestEveryRequiredContainerRejectsOmissionNullDuplicateAndCaseAlias(t *testing.T) {
	request := testCredentialExecRequest(t, true)
	correlation := request.state.correlation
	wire, err := EncodeCredentialExecRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	text := string(wire)
	body := exactJSONSegment(t, text, `"body":`, len(text)-1)
	planEnd := strings.Index(text, `,"privateRecordCount":`)
	if planEnd < 0 {
		t.Fatal("plan end not found")
	}
	plan := exactJSONSegment(t, text, `"plan":`, planEnd)
	environmentEnd := strings.Index(text, `,"workDir":`)
	if environmentEnd < 0 {
		t.Fatal("environment end not found")
	}
	environment := exactJSONSegment(t, text, `"env":`, environmentEnd)
	timingEnd := strings.Index(text, `},"privateRecordCount":`)
	if timingEnd < 0 {
		t.Fatal("timing end not found")
	}
	timingEnd++
	timing := exactJSONSegment(t, text, `"timing":`, timingEnd)
	for _, field := range []string{body, plan, environment, timing} {
		field := field
		t.Run(exactJSONFieldKey(t, field), func(t *testing.T) {
			for name, mutation := range map[string]string{
				"omitted":    omitExactJSONField(t, text, field),
				"null":       replaceExactJSONFieldWithNull(t, text, field),
				"duplicate":  duplicateExactJSONField(t, text, field),
				"case alias": caseAliasExactJSONField(t, text, field),
			} {
				if _, err := DecodeCredentialExecRequest(correlation, []byte(mutation)); !errors.Is(err, ErrInvalidCredentialExecRequestJSON) {
					t.Errorf("%s error = %v", name, err)
				}
			}
		})
	}
}

func TestCredentialExecSuccessEveryRequiredFieldRejectsOmissionNullDuplicateAndCaseAlias(t *testing.T) {
	request := testCredentialExecRequest(t, true)
	response, err := NewCredentialExecSuccessResponse(request, 0, 0, emptySHA256Hex, 0, emptySHA256Hex, false, 0, emptySHA256Hex, false, strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeCredentialExecSuccessResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	fields := []string{
		`"protocolVersion":"guest-agent-v2"`, `"operation":"exec"`,
		`"requestId":"AQIDBAUGBwgJCgsMDQ4PEA"`, `"identityDigest":"` + EncodeIdentityDigest(request.IdentityDigest()) + `"`,
		`"ok":true`, `"revision":3`, `"exitCode":0`, `"stdinBytes":0`, `"stdinSha256":"` + emptySHA256Hex + `"`,
		`"stdoutBytes":0`, `"stdoutSha256":"` + emptySHA256Hex + `"`, `"stdoutTruncated":false`,
		`"stderrBytes":0`, `"stderrSha256":"` + emptySHA256Hex + `"`, `"stderrTruncated":false`,
		`"execTransactionSha256":"` + strings.Repeat("d", 64) + `"`,
	}
	for _, field := range fields {
		field := field
		t.Run(field[:min(len(field), 40)], func(t *testing.T) {
			for name, mutation := range map[string]string{
				"omitted":    omitExactJSONField(t, string(wire), field),
				"null":       replaceExactJSONFieldWithNull(t, string(wire), field),
				"duplicate":  duplicateExactJSONField(t, string(wire), field),
				"case alias": caseAliasExactJSONField(t, string(wire), field),
			} {
				if _, err := DecodeCredentialExecSuccessResponse(request, []byte(mutation)); !errors.Is(err, ErrInvalidCredentialExecSuccessJSON) {
					t.Errorf("%s error = %v", name, err)
				}
			}
		})
	}
}

func TestCredentialExecSuccessBodyContainerIsStrict(t *testing.T) {
	request := testCredentialExecRequest(t, true)
	response, err := NewCredentialExecSuccessResponse(request, 0, 0, emptySHA256Hex, 0, emptySHA256Hex, false, 0, emptySHA256Hex, false, strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeCredentialExecSuccessResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	text := string(wire)
	body := exactJSONSegment(t, text, `"body":`, len(text)-1)
	for name, mutation := range map[string]string{
		"omitted":    omitExactJSONField(t, text, body),
		"null":       replaceExactJSONFieldWithNull(t, text, body),
		"duplicate":  duplicateExactJSONField(t, text, body),
		"case alias": caseAliasExactJSONField(t, text, body),
	} {
		if _, err := DecodeCredentialExecSuccessResponse(request, []byte(mutation)); !errors.Is(err, ErrInvalidCredentialExecSuccessJSON) {
			t.Errorf("%s error = %v", name, err)
		}
	}
}

func TestCredentialExecJSONSizeDepthAndTokenBounds(t *testing.T) {
	if maxCredentialExecJSONBytes != session.MaxControlPlaintextBytes {
		t.Fatalf("exec JSON maximum = %d, session control maximum = %d", maxCredentialExecJSONBytes, session.MaxControlPlaintextBytes)
	}
	request := testCredentialExecRequest(t, true)
	wire, err := EncodeCredentialExecRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	atBound := make([]byte, maxCredentialExecJSONBytes)
	copy(atBound, wire)
	for index := len(wire); index < len(atBound); index++ {
		atBound[index] = ' '
	}
	if !validCredentialExecJSONInput(atBound) {
		t.Fatal("exact maximum failed JSON preflight")
	}
	if _, err := DecodeCredentialExecRequest(request.state.correlation, atBound); !errors.Is(err, ErrInvalidCredentialExecRequestJSON) {
		t.Fatalf("noncanonical exact maximum error = %v", err)
	}
	plusOne := append(append([]byte(nil), atBound...), ' ')
	if validCredentialExecJSONInput(plusOne) {
		t.Fatal("maximum plus one passed JSON preflight")
	}

	atDepth := []byte(`[[[[[[]]]]]]`)
	overDepth := []byte(`[[[[[[[]]]]]]]`)
	if !validCredentialExecJSONInput(atDepth) || validCredentialExecJSONInput(overDepth) {
		t.Fatal("JSON depth boundary changed")
	}
	if !validCredentialExecJSONInput(wire) {
		t.Fatal("canonical request failed JSON preflight")
	}

	tokenHeavy := "[" + strings.Repeat("0,", maxCredentialExecJSONTokens) + "0]"
	if validCredentialExecJSONInput([]byte(tokenHeavy)) {
		t.Fatal("token maximum plus one passed JSON preflight")
	}
}

func TestCredentialExecAllGenericMarshalersDeniedAndUnmarshalersNonmutating(t *testing.T) {
	request := testCredentialExecRequest(t, true)
	response, err := NewCredentialExecSuccessResponse(request, 0, 0, emptySHA256Hex, 0, emptySHA256Hex, false, 0, emptySHA256Hex, false, strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	values := []struct {
		name  string
		value any
	}{
		{"environment", request.Plan().Environment()[0]},
		{"timing", request.Plan().Timing()},
		{"plan", request.Plan()},
		{"correlation", request.state.correlation},
		{"request", request},
		{"success", response},
	}
	for _, test := range values {
		if _, err := test.value.(encoding.TextMarshaler).MarshalText(); !errors.Is(err, ErrCredentialExecSerialization) {
			t.Errorf("%s text marshal error = %v", test.name, err)
		}
		if _, err := test.value.(encoding.BinaryMarshaler).MarshalBinary(); !errors.Is(err, ErrCredentialExecSerialization) {
			t.Errorf("%s binary marshal error = %v", test.name, err)
		}
	}

	before, err := EncodeCredentialExecSuccessResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.UnmarshalText([]byte("private")); !errors.Is(err, ErrCredentialExecSerialization) {
		t.Fatal(err)
	}
	if err := response.UnmarshalBinary([]byte("private")); !errors.Is(err, ErrCredentialExecSerialization) {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"private":"value"}`), &response); !errors.Is(err, ErrCredentialExecSerialization) {
		t.Fatal(err)
	}
	after, err := EncodeCredentialExecSuccessResponse(response)
	if err != nil || string(after) != string(before) {
		t.Fatal("denied success unmarshal mutated receiver")
	}
}

func omitExactJSONField(t *testing.T, wire, field string) string {
	t.Helper()
	if strings.Count(wire, field) != 1 {
		t.Fatalf("field %q count = %d", field, strings.Count(wire, field))
	}
	if strings.Contains(wire, field+",") {
		return strings.Replace(wire, field+",", "", 1)
	}
	if strings.Contains(wire, ","+field) {
		return strings.Replace(wire, ","+field, "", 1)
	}
	t.Fatalf("field %q has no object separator", field)
	return ""
}

func replaceExactJSONFieldWithNull(t *testing.T, wire, field string) string {
	t.Helper()
	key := exactJSONFieldKey(t, field)
	return strings.Replace(wire, field, key+":null", 1)
}

func duplicateExactJSONField(t *testing.T, wire, field string) string {
	t.Helper()
	return strings.Replace(wire, field, field+","+field, 1)
}

func caseAliasExactJSONField(t *testing.T, wire, field string) string {
	t.Helper()
	key := exactJSONFieldKey(t, field)
	if len(key) < 3 {
		t.Fatalf("short key %q", key)
	}
	alias := `"` + strings.ToUpper(key[1:2]) + key[2:]
	return strings.Replace(wire, key, alias, 1)
}

func exactJSONFieldKey(t *testing.T, field string) string {
	t.Helper()
	separator := strings.Index(field, ":")
	if separator < 3 || field[0] != '"' {
		t.Fatalf("invalid exact field %q", field)
	}
	return field[:separator]
}

func exactJSONSegment(t *testing.T, wire, startMarker string, end int) string {
	t.Helper()
	start := strings.Index(wire, startMarker)
	if start < 0 || end <= start || end > len(wire) {
		t.Fatalf("segment %q bounds %d..%d", startMarker, start, end)
	}
	return wire[start:end]
}
