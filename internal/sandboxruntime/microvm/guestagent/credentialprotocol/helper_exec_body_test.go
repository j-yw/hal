package credentialprotocol

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestHelperExecCanonicalIndependentWireVectors(t *testing.T) {
	t.Parallel()

	plan := HelperExecPlan{
		Arguments: []string{"/bin/x"}, WorkDirectory: "/",
		StdinMode: HelperExecStreamModePipe, StdoutMode: HelperExecStreamModePipe, StderrMode: HelperExecStreamModePipe,
		StdinMaxBytes: 1, StdoutMaxBytes: 2, StderrMaxBytes: 3,
		Timing: HelperExecTiming{Kind: HelperExecTimingTimeoutMillis, Value: 1},
	}
	execWire, err := EncodeHelperExecBody(HelperExecBody{Revision: 1, ExecBindingID: "exec", Plan: plan})
	if err != nil {
		t.Fatalf("EncodeHelperExecBody: %v", err)
	}
	wantExec := helperExecMustHex(t,
		"0000000000000001"+
			"000465786563"+
			"00000000"+
			"0000000000000000000000000000000000000000000000000000000000000000"+
			"0001"+
			"00062f62696e2f78"+
			"0000"+
			"00012f"+
			"010101"+
			"000000010000000200000003"+
			"010000000000000001")
	if !bytes.Equal(execWire, wantExec) {
		t.Fatalf("0x15 body = %x, want %x", execWire, wantExec)
	}

	privateBytes := []byte("sec")
	private, err := NewHelperExecPrivateBody(2, sha256.Sum256(privateBytes), privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer private.Wipe()
	privateWire, err := EncodeHelperExecPrivateBody(private)
	if err != nil {
		t.Fatal(err)
	}
	wantPrivate := helperExecMustHex(t, "0000000000000002"+"00000003"+"add93534eeb463800fe0ed0946048d33636dd2a014fab92e8a37f77ce98c740b"+"736563")
	if !bytes.Equal(privateWire, wantPrivate) {
		t.Fatalf("0x17 body = %x, want %x", privateWire, wantPrivate)
	}

	payload := []byte("out")
	stream, err := NewHelperExecStreamBody(3, HelperExecStreamStdout, HelperExecStreamFlagsNone, 5, sha256.Sum256(payload), payload)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Wipe()
	streamWire, err := EncodeHelperExecStreamBody(stream)
	if err != nil {
		t.Fatal(err)
	}
	wantStream := helperExecMustHex(t, "0000000000000003"+"02"+"00"+"0000"+"0000000000000005"+"00000003"+"762069bc07a6e1b5df123a5ae7bd91c10daa04694fbaa17fba0cd6a8dcce8f22"+"6f7574")
	if !bytes.Equal(streamWire, wantStream) {
		t.Fatalf("0x18 body = %x, want %x", streamWire, wantStream)
	}

	creditWire, err := EncodeHelperExecCreditBody(HelperExecCreditBody{Revision: 4, StreamKind: HelperExecStreamStderr, NextOffset: 9})
	if err != nil {
		t.Fatal(err)
	}
	wantCredit := helperExecMustHex(t, "0000000000000004"+"03"+"00000000000000"+"0000000000000009")
	if !bytes.Equal(creditWire, wantCredit) {
		t.Fatalf("0x19 body = %x, want %x", creditWire, wantCredit)
	}
}

func TestHelperExecBodyExactVectorAndRoundTrip(t *testing.T) {
	t.Parallel()

	privateDigest := sha256.Sum256([]byte("private-binding"))
	body := HelperExecBody{
		Revision:             7,
		ExecBindingID:        "exec-binding",
		PrivateBindingLength: 15,
		PrivateBindingSHA256: privateDigest,
		Plan: HelperExecPlan{
			Arguments: []string{"/usr/bin/pi", "--mode", "json"},
			Environment: []HelperExecEnvironment{
				{Name: "HAL_MODE", Source: HelperExecEnvironmentLiteral, Value: "production"},
				{Name: "HTTP_PROXY", Source: HelperExecEnvironmentGenerated, Value: "http://proxy"},
				{Name: "HTTPS_PROXY", Source: HelperExecEnvironmentGenerated, Value: "http://proxy"},
				{Name: "http_proxy", Source: HelperExecEnvironmentGenerated, Value: "http://proxy"},
				{Name: "https_proxy", Source: HelperExecEnvironmentGenerated, Value: "http://proxy"},
			},
			WorkDirectory: "/workspace/project",
			StdinMode:     HelperExecStreamModePipe, StdoutMode: HelperExecStreamModePipe, StderrMode: HelperExecStreamModePipe,
			StdinMaxBytes: 1, StdoutMaxBytes: MaxHelperExecStreamAggregateBytes, StderrMaxBytes: 4096,
			Timing: HelperExecTiming{Kind: HelperExecTimingTimeoutMillis, Value: 30000},
		},
	}

	encoded, err := EncodeHelperExecBody(body)
	if err != nil {
		t.Fatalf("EncodeHelperExecBody: %v", err)
	}
	if binary.BigEndian.Uint64(encoded[:8]) != 7 || binary.BigEndian.Uint16(encoded[8:10]) != uint16(len("exec-binding")) {
		t.Fatalf("exec prefix = %x", encoded[:10])
	}
	if got := string(encoded[10 : 10+len("exec-binding")]); got != "exec-binding" {
		t.Fatalf("exec binding = %q", got)
	}
	privateOffset := 10 + len("exec-binding")
	if got := binary.BigEndian.Uint32(encoded[privateOffset : privateOffset+4]); got != 15 {
		t.Fatalf("private length = %d", got)
	}
	if !bytes.Equal(encoded[privateOffset+4:privateOffset+36], privateDigest[:]) {
		t.Fatal("private digest is not in the locked field position")
	}

	decoded, err := DecodeHelperExecBody(encoded)
	if err != nil {
		t.Fatalf("DecodeHelperExecBody: %v", err)
	}
	if !reflect.DeepEqual(decoded, body) {
		t.Fatalf("decoded = %#v, want %#v", decoded, body)
	}
	encoded[privateOffset+36+2] ^= 0xff
	if reflect.DeepEqual(decoded.Plan.Arguments, body.Plan.Arguments) == false {
		t.Fatal("decoded plan unexpectedly changed after wire mutation")
	}
}

func TestHelperExecPlanBoundsAndClosedCatalogs(t *testing.T) {
	t.Parallel()

	valid := helperExecPlanForTest()
	if _, err := EncodeHelperExecPlan(valid); err != nil {
		t.Fatalf("valid plan: %v", err)
	}
	exact := valid
	exact.Environment = nil
	exact.WorkDirectory = "/"
	exact.Arguments = make([]string, 8)
	for index := 0; index < 7; index++ {
		exact.Arguments[index] = strings.Repeat("x", MaxHelperExecArgumentBytes)
	}
	exact.Arguments[7] = strings.Repeat("x", 8145)
	exactWire, err := EncodeHelperExecPlan(exact)
	if err != nil || len(exactWire) != MaxHelperExecPlanBytes {
		t.Fatalf("exact 64-KiB plan length/error = %d/%v", len(exactWire), err)
	}
	tooLarge := exact
	tooLarge.Arguments = append([]string(nil), exact.Arguments...)
	tooLarge.Arguments[7] += "x"
	if _, err := EncodeHelperExecPlan(tooLarge); !errors.Is(err, ErrHelperExecPlanLength) {
		t.Fatalf("aggregate plan error = %v, want ErrHelperExecPlanLength", err)
	}

	tests := []struct {
		name string
		edit func(*HelperExecPlan)
		want error
	}{
		{name: "no args", edit: func(plan *HelperExecPlan) { plan.Arguments = nil }, want: ErrHelperExecArgumentCount},
		{name: "too many args", edit: func(plan *HelperExecPlan) { plan.Arguments = make([]string, MaxHelperExecArguments+1) }, want: ErrHelperExecArgumentCount},
		{name: "blank argv zero", edit: func(plan *HelperExecPlan) { plan.Arguments[0] = " \t" }, want: ErrHelperExecArgument},
		{name: "arg control", edit: func(plan *HelperExecPlan) { plan.Arguments[0] = "a\n" }, want: ErrHelperExecArgument},
		{name: "arg invalid utf8", edit: func(plan *HelperExecPlan) { plan.Arguments[0] = string([]byte{0xff}) }, want: ErrHelperExecArgument},
		{name: "arg plus one", edit: func(plan *HelperExecPlan) { plan.Arguments[0] = strings.Repeat("x", MaxHelperExecArgumentBytes+1) }, want: ErrHelperExecArgument},
		{name: "too many env", edit: func(plan *HelperExecPlan) {
			plan.Environment = make([]HelperExecEnvironment, MaxHelperExecEnvironmentEntries+1)
		}, want: ErrHelperExecEnvironmentCount},
		{name: "duplicate env", edit: func(plan *HelperExecPlan) {
			plan.Environment = append(plan.Environment, HelperExecEnvironment{Name: "PATH", Source: HelperExecEnvironmentInherited})
		}, want: ErrHelperExecEnvironmentName},
		{name: "bad env name", edit: func(plan *HelperExecPlan) { plan.Environment[0].Name = "bad-name" }, want: ErrHelperExecEnvironmentName},
		{name: "protected base", edit: func(plan *HelperExecPlan) { plan.Environment[0].Name = "AZURE_OPENAI_BASE_URL" }, want: ErrHelperExecEnvironmentProtected},
		{name: "protected key", edit: func(plan *HelperExecPlan) { plan.Environment[0].Name = "AZURE_OPENAI_API_KEY" }, want: ErrHelperExecEnvironmentProtected},
		{name: "protected version", edit: func(plan *HelperExecPlan) { plan.Environment[0].Name = "AZURE_OPENAI_API_VERSION" }, want: ErrHelperExecEnvironmentProtected},
		{name: "unknown source", edit: func(plan *HelperExecPlan) { plan.Environment[0].Source = 0 }, want: ErrUnknownHelperExecEnvironmentSource},
		{name: "env value plus one", edit: func(plan *HelperExecPlan) {
			plan.Environment[0].Value = strings.Repeat("x", MaxHelperExecEnvironmentValueBytes+1)
		}, want: ErrHelperExecEnvironmentValue},
		{name: "env value nul", edit: func(plan *HelperExecPlan) { plan.Environment[0].Value = "x\x00y" }, want: ErrHelperExecEnvironmentValue},
		{name: "proxy wrong source", edit: func(plan *HelperExecPlan) { plan.Environment[1].Source = HelperExecEnvironmentLiteral }, want: ErrHelperExecProxyEnvironment},
		{name: "proxy missing quartet", edit: func(plan *HelperExecPlan) { plan.Environment = plan.Environment[:4] }, want: ErrHelperExecProxyEnvironment},
		{name: "proxy unequal", edit: func(plan *HelperExecPlan) { plan.Environment[4].Value = "http://other" }, want: ErrHelperExecProxyEnvironment},
		{name: "relative workdir", edit: func(plan *HelperExecPlan) { plan.WorkDirectory = "workspace" }, want: ErrHelperExecWorkDirectory},
		{name: "unclean workdir", edit: func(plan *HelperExecPlan) { plan.WorkDirectory = "/workspace/../private" }, want: ErrHelperExecWorkDirectory},
		{name: "mode zero", edit: func(plan *HelperExecPlan) { plan.StdinMode = 0 }, want: ErrUnknownHelperExecStreamMode},
		{name: "stdin max zero", edit: func(plan *HelperExecPlan) { plan.StdinMaxBytes = 0 }, want: ErrHelperExecStreamMaximum},
		{name: "stderr max plus one", edit: func(plan *HelperExecPlan) { plan.StderrMaxBytes = MaxHelperExecStreamAggregateBytes + 1 }, want: ErrHelperExecStreamMaximum},
		{name: "timing zero kind", edit: func(plan *HelperExecPlan) { plan.Timing.Kind = 0 }, want: ErrUnknownHelperExecTimingKind},
		{name: "timeout zero", edit: func(plan *HelperExecPlan) { plan.Timing.Value = 0 }, want: ErrHelperExecTimingValue},
		{name: "timeout plus one", edit: func(plan *HelperExecPlan) { plan.Timing.Value = MaxHelperExecTimeoutMillis + 1 }, want: ErrHelperExecTimingValue},
		{name: "deadline below", edit: func(plan *HelperExecPlan) {
			plan.Timing.Kind = HelperExecTimingDeadlineUnixMillis
			plan.Timing.Value = MinHelperExecDeadlineUnixMillis - 1
		}, want: ErrHelperExecTimingValue},
		{name: "deadline above", edit: func(plan *HelperExecPlan) {
			plan.Timing.Kind = HelperExecTimingDeadlineUnixMillis
			plan.Timing.Value = MaxHelperExecDeadlineUnixMillis + 1
		}, want: ErrHelperExecTimingValue},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			plan := helperExecPlanForTest()
			test.edit(&plan)
			if _, err := EncodeHelperExecPlan(plan); !errors.Is(err, test.want) {
				t.Fatalf("EncodeHelperExecPlan error = %v, want %v", err, test.want)
			}
		})
	}

	withoutProxy := helperExecPlanForTest()
	withoutProxy.Environment = withoutProxy.Environment[:1]
	withoutProxyWire, err := EncodeHelperExecPlan(withoutProxy)
	if err != nil {
		t.Fatalf("plan without optional generated quartet: %v", err)
	}
	for length := 0; length < len(withoutProxyWire); length++ {
		if _, err := DecodeHelperExecPlan(withoutProxyWire[:length]); !errors.Is(err, ErrHelperExecPlanLength) {
			t.Fatalf("plan truncation %d error = %v", length, err)
		}
	}
	if _, err := DecodeHelperExecPlan(append(append([]byte(nil), withoutProxyWire...), 0)); !errors.Is(err, ErrHelperExecPlanTrailingData) {
		t.Fatalf("plan trailing error = %v", err)
	}
}

func TestHelperExecPlanAcceptsEveryExactV1Bound(t *testing.T) {
	t.Parallel()

	maxArguments := helperExecPlanForTest()
	maxArguments.Environment = nil
	maxArguments.Arguments = make([]string, MaxHelperExecArguments)
	for index := range maxArguments.Arguments {
		maxArguments.Arguments[index] = "x"
	}
	if _, err := EncodeHelperExecPlan(maxArguments); err != nil {
		t.Fatalf("maximum argument count: %v", err)
	}

	maxEnvironment := helperExecPlanForTest()
	maxEnvironment.Environment = make([]HelperExecEnvironment, MaxHelperExecEnvironmentEntries)
	for index := range maxEnvironment.Environment {
		maxEnvironment.Environment[index] = HelperExecEnvironment{Name: fmt.Sprintf("ENV_%03d", index), Source: HelperExecEnvironmentInherited}
	}
	if _, err := EncodeHelperExecPlan(maxEnvironment); err != nil {
		t.Fatalf("maximum environment count: %v", err)
	}

	maxName := helperExecPlanForTest()
	maxName.Environment = []HelperExecEnvironment{{Name: strings.Repeat("A", MaxHelperExecEnvironmentNameBytes), Source: HelperExecEnvironmentLiteral}}
	if _, err := EncodeHelperExecPlan(maxName); err != nil {
		t.Fatalf("maximum environment name: %v", err)
	}
	maxName.Environment[0].Name += "A"
	if _, err := EncodeHelperExecPlan(maxName); !errors.Is(err, ErrHelperExecEnvironmentName) {
		t.Fatalf("environment name plus one error = %v", err)
	}

	maxValue := helperExecPlanForTest()
	maxValue.Environment = []HelperExecEnvironment{{Name: "VALUE", Source: HelperExecEnvironmentLiteral, Value: strings.Repeat("x", MaxHelperExecEnvironmentValueBytes)}}
	if _, err := EncodeHelperExecPlan(maxValue); err != nil {
		t.Fatalf("maximum environment value: %v", err)
	}

	maxWorkDirectory := helperExecPlanForTest()
	maxWorkDirectory.Environment = nil
	maxWorkDirectory.WorkDirectory = "/" + strings.Repeat("w", MaxHelperExecWorkDirectoryBytes-1)
	if _, err := EncodeHelperExecPlan(maxWorkDirectory); err != nil {
		t.Fatalf("maximum work directory: %v", err)
	}
	maxWorkDirectory.WorkDirectory += "w"
	if _, err := EncodeHelperExecPlan(maxWorkDirectory); !errors.Is(err, ErrHelperExecWorkDirectory) {
		t.Fatalf("work directory plus one error = %v", err)
	}

	for _, timing := range []HelperExecTiming{
		{Kind: HelperExecTimingTimeoutMillis, Value: MaxHelperExecTimeoutMillis},
		{Kind: HelperExecTimingDeadlineUnixMillis, Value: MinHelperExecDeadlineUnixMillis},
		{Kind: HelperExecTimingDeadlineUnixMillis, Value: MaxHelperExecDeadlineUnixMillis},
	} {
		plan := helperExecPlanForTest()
		plan.Timing = timing
		if _, err := EncodeHelperExecPlan(plan); err != nil {
			t.Fatalf("timing %#v: %v", timing, err)
		}
	}

	if MaxHelperExecArguments != 128 || MaxHelperExecArgumentBytes != 8192 || MaxHelperExecEnvironmentEntries != 256 || MaxHelperExecEnvironmentNameBytes != 128 || MaxHelperExecEnvironmentValueBytes != 8192 || MaxHelperExecWorkDirectoryBytes != 4096 || MaxHelperExecStreamAggregateBytes != 4*1024*1024 || MaxHelperExecTimeoutMillis != 24*60*60*1000 {
		t.Fatal("helper exec v1-derived bounds drifted")
	}
}

func TestHelperExecCorrelatesPreparedHTTPIntentAndProvedProxyBaseURL(t *testing.T) {
	t.Parallel()

	const provedProxyBaseURL = "http://proved-runtime-proxy"
	plan := helperExecPlanForTest()
	for index := range plan.Environment {
		if helperExecProxyEnvironment(plan.Environment[index].Name) {
			plan.Environment[index].Value = provedProxyBaseURL
		}
	}
	if err := ValidateHelperExecPlanProxyBaseURL(plan, provedProxyBaseURL); err != nil {
		t.Fatalf("matching proved proxy URL: %v", err)
	}
	if err := ValidateHelperExecPlanProxyBaseURL(plan, "http://neighbor-runtime-proxy"); !errors.Is(err, ErrHelperExecProxyEnvironment) {
		t.Fatalf("mismatched proved proxy URL error = %v", err)
	}
	withoutQuartet := plan
	withoutQuartet.Environment = withoutQuartet.Environment[:1]
	if err := ValidateHelperExecPlanProxyBaseURL(withoutQuartet, provedProxyBaseURL); !errors.Is(err, ErrHelperExecProxyEnvironment) {
		t.Fatalf("missing proved proxy quartet error = %v", err)
	}

	privateDigest := sha256.Sum256([]byte("binding"))
	httpBody := HelperExecBody{
		Revision: 2, ExecBindingID: "exec", PrivateBindingLength: 7,
		PrivateBindingSHA256: privateDigest, Plan: plan,
	}
	httpManifest := []HelperBindingManifestRecord{{BindingID: "http", Mode: DeliveryModeHTTPProxy}}
	if err := ValidateHelperExecBodyForPreparedManifest(httpBody, httpManifest, "exec", 2, provedProxyBaseURL); err != nil {
		t.Fatalf("matching HTTP intent: %v", err)
	}
	neighboringBinding := httpBody
	neighboringBinding.ExecBindingID = "neighbor"
	if err := ValidateHelperExecBodyForPreparedManifest(neighboringBinding, httpManifest, "exec", 2, provedProxyBaseURL); !errors.Is(err, ErrHelperExecPreparedManifest) {
		t.Fatalf("neighboring exec binding error = %v", err)
	}
	for _, revision := range []uint64{1, 3} {
		changedRevision := httpBody
		changedRevision.Revision = revision
		if err := ValidateHelperExecBodyForPreparedManifest(changedRevision, httpManifest, "exec", 2, provedProxyBaseURL); !errors.Is(err, ErrHelperExecPreparedManifest) {
			t.Fatalf("noncurrent revision %d error = %v", revision, err)
		}
	}
	zeroPrivate := httpBody
	zeroPrivate.PrivateBindingLength = 0
	zeroPrivate.PrivateBindingSHA256 = [32]byte{}
	if err := ValidateHelperExecBodyForPreparedManifest(zeroPrivate, httpManifest, "exec", 2, provedProxyBaseURL); !errors.Is(err, ErrHelperExecPreparedManifest) {
		t.Fatalf("HTTP without private declaration error = %v", err)
	}
	if err := ValidateHelperExecBodyForPreparedManifest(httpBody, httpManifest, "exec", 2, "http://neighbor-runtime-proxy"); !errors.Is(err, ErrHelperExecProxyEnvironment) {
		t.Fatalf("HTTP proxy correlation mismatch error = %v", err)
	}

	fileManifest := []HelperBindingManifestRecord{{
		BindingID: "file", Mode: DeliveryModeFileTmpfs, TargetPath: "credential",
		DeclaredFileBytes: 1, FileSHA256: sha256.Sum256([]byte("x")),
	}}
	fileBody := zeroPrivate
	fileBody.Plan = withoutQuartet
	if err := ValidateHelperExecBodyForPreparedManifest(fileBody, fileManifest, "exec", 2, ""); err != nil {
		t.Fatalf("file-only zero-private intent: %v", err)
	}
	if err := ValidateHelperExecBodyForPreparedManifest(httpBody, fileManifest, "exec", 2, provedProxyBaseURL); !errors.Is(err, ErrHelperExecPreparedManifest) {
		t.Fatalf("file-only nonzero private error = %v", err)
	}
	fileWithProxy := fileBody
	fileWithProxy.Plan = plan
	if err := ValidateHelperExecBodyForPreparedManifest(fileWithProxy, fileManifest, "exec", 2, provedProxyBaseURL); !errors.Is(err, ErrHelperExecPreparedManifest) {
		t.Fatalf("file-only proxy quartet error = %v", err)
	}

	seed := "proxy-url-secret-canary"
	if strings.Contains(fmt.Sprint(ValidateHelperExecPlanProxyBaseURL(plan, seed)), seed) {
		t.Fatal("correlation error leaked expected proxy URL")
	}
}

func TestHelperExecBodyPrivateShapeAndDecoderStrictness(t *testing.T) {
	t.Parallel()

	withoutPrivate := HelperExecBody{Revision: 1, ExecBindingID: "exec", Plan: helperExecPlanForTest()}
	wire, err := EncodeHelperExecBody(withoutPrivate)
	if err != nil {
		t.Fatalf("zero private: %v", err)
	}
	if _, err := DecodeHelperExecBody(wire); err != nil {
		t.Fatalf("decode zero private: %v", err)
	}

	bad := withoutPrivate
	bad.PrivateBindingSHA256 = sha256.Sum256(nil)
	if _, err := EncodeHelperExecBody(bad); !errors.Is(err, ErrHelperExecPrivateShape) {
		t.Fatalf("zero length nonzero digest error = %v", err)
	}
	bad = withoutPrivate
	bad.PrivateBindingLength = 1
	if _, err := EncodeHelperExecBody(bad); !errors.Is(err, ErrHelperExecPrivateShape) {
		t.Fatalf("nonzero length zero digest error = %v", err)
	}
	bad.PrivateBindingSHA256 = sha256.Sum256([]byte("x"))
	bad.PrivateBindingLength = MaxHelperExecPrivateBytes + 1
	if _, err := EncodeHelperExecBody(bad); !errors.Is(err, ErrHelperExecPrivateShape) {
		t.Fatalf("private plus one error = %v", err)
	}
	bad = withoutPrivate
	bad.Revision = 0
	if _, err := EncodeHelperExecBody(bad); !errors.Is(err, ErrHelperExecRevision) {
		t.Fatalf("zero revision error = %v", err)
	}

	for length := 0; length < len(wire); length++ {
		if _, err := DecodeHelperExecBody(wire[:length]); !errors.Is(err, ErrHelperExecBodyLength) {
			t.Fatalf("truncation at %d error = %v", length, err)
		}
	}
	if _, err := DecodeHelperExecBody(append(append([]byte(nil), wire...), 0)); !errors.Is(err, ErrHelperExecBodyTrailingData) {
		t.Fatalf("trailing error = %v", err)
	}
	if _, err := DecodeHelperExecBody(make([]byte, MaxHelperPacketBodyBytes+1)); !errors.Is(err, ErrHelperExecBodyLength) {
		t.Fatalf("72-KiB plus-one body error = %v", err)
	}
	maximumPlan := helperExecPlanForTest()
	maximumPlan.Environment = nil
	maximumPlan.WorkDirectory = "/"
	maximumPlan.Arguments = make([]string, 8)
	for index := 0; index < 7; index++ {
		maximumPlan.Arguments[index] = strings.Repeat("x", MaxHelperExecArgumentBytes)
	}
	maximumPlan.Arguments[7] = strings.Repeat("x", 8145)
	maximumBody, err := EncodeHelperExecBody(HelperExecBody{Revision: 1, ExecBindingID: strings.Repeat("x", MaxBodyTokenBytes), Plan: maximumPlan})
	if err != nil || len(maximumBody) > MaxHelperPacketBodyBytes {
		t.Fatalf("maximum exec body length/error = %d/%v", len(maximumBody), err)
	}
}

func TestHelperExecPrivateOwnershipDigestAndWipe(t *testing.T) {
	t.Parallel()

	private := make([]byte, 7, 31)
	copy(private, "private")
	digest := sha256.Sum256(private)
	body, err := NewHelperExecPrivateBody(3, digest, private)
	if err != nil {
		t.Fatalf("NewHelperExecPrivateBody: %v", err)
	}
	alias := *body
	privateBacking := body.state.privateBinding[:cap(body.state.privateBinding)]
	private[0] = 'X'
	got := make([]byte, 7)
	if n, err := alias.CopyPrivateBinding(got); err != nil || n != 7 || string(got) != "private" {
		t.Fatalf("CopyPrivateBinding = %q, %d, %v", got, n, err)
	}
	tooSmall := bytes.Repeat([]byte{0x7a}, 6)
	if n, err := body.CopyPrivateBinding(tooSmall); n != 0 || !errors.Is(err, ErrHelperExecPrivateDestination) || !bytes.Equal(tooSmall, bytes.Repeat([]byte{0x7a}, 6)) {
		t.Fatalf("short copy = %d, %v, %x", n, err, tooSmall)
	}
	wire, err := EncodeHelperExecPrivateBody(body)
	if err != nil {
		t.Fatalf("EncodeHelperExecPrivateBody: %v", err)
	}
	decoded, err := DecodeHelperExecPrivateBody(wire)
	if err != nil {
		t.Fatalf("DecodeHelperExecPrivateBody: %v", err)
	}
	defer decoded.Wipe()
	for length := 0; length < len(wire); length++ {
		if value, err := DecodeHelperExecPrivateBody(wire[:length]); !errors.Is(err, ErrHelperExecPrivateBodyLength) {
			if value != nil {
				value.Wipe()
			}
			t.Fatalf("private truncation %d error = %v", length, err)
		}
	}
	if value, err := DecodeHelperExecPrivateBody(append(append([]byte(nil), wire...), 0)); !errors.Is(err, ErrHelperExecPrivateTrailingData) {
		if value != nil {
			value.Wipe()
		}
		t.Fatalf("private trailing error = %v", err)
	}
	badPrivate := append([]byte(nil), wire...)
	clear(badPrivate[0:8])
	if _, err := DecodeHelperExecPrivateBody(badPrivate); !errors.Is(err, ErrHelperExecRevision) {
		t.Fatalf("private revision error = %v", err)
	}
	badPrivate = append([]byte(nil), wire...)
	clear(badPrivate[8:12])
	if _, err := DecodeHelperExecPrivateBody(badPrivate); !errors.Is(err, ErrHelperExecPrivateShape) {
		t.Fatalf("private zero length error = %v", err)
	}
	badPrivate = append([]byte(nil), wire...)
	badPrivate[12] ^= 0xff
	if _, err := DecodeHelperExecPrivateBody(badPrivate); !errors.Is(err, ErrHelperExecPrivateDigest) {
		t.Fatalf("private digest error = %v", err)
	}
	alias.Wipe()
	if body.state.privateBinding != nil || !body.state.wiped || body.state.revision != 0 || body.state.privateBindingLength != 0 || body.state.privateBindingSHA256 != [32]byte{} || body.Revision() != 0 || body.PrivateBindingLength() != 0 || body.PrivateBindingSHA256() != [32]byte{} {
		t.Fatal("wipe did not clear shared private owner")
	}
	if !allHelperExecZero(privateBacking) {
		t.Fatal("wipe did not clear the full-capacity private allocation")
	}
	if _, err := EncodeHelperExecPrivateBody(body); !errors.Is(err, ErrHelperExecPrivateWiped) {
		t.Fatalf("encode after wipe error = %v", err)
	}

	if decoded.state.privateBinding == nil || cap(decoded.state.privateBinding) != len(decoded.state.privateBinding) {
		t.Fatal("decoded private owner is not tightly allocated")
	}
	wire[len(wire)-1] ^= 0xff
	copyOut := make([]byte, decoded.PrivateBindingLength())
	if _, err := decoded.CopyPrivateBinding(copyOut); err != nil || string(copyOut) != "private" {
		t.Fatal("decoded private owner aliases wire input")
	}
}

func TestHelperExecPrivateAndStreamOwnersAcceptExact64KiB(t *testing.T) {
	t.Parallel()

	privateBytes := bytes.Repeat([]byte{0x41}, MaxHelperExecPrivateBytes)
	private, err := NewHelperExecPrivateBody(1, sha256.Sum256(privateBytes), privateBytes)
	if err != nil {
		t.Fatalf("maximum private owner: %v", err)
	}
	private.Wipe()
	if value, err := NewHelperExecPrivateBody(1, sha256.Sum256(nil), nil); value != nil || !errors.Is(err, ErrHelperExecPrivateShape) {
		if value != nil {
			value.Wipe()
		}
		t.Fatalf("empty private owner = %#v, %v", value, err)
	}
	privatePlusOne := bytes.Repeat([]byte{0x41}, MaxHelperExecPrivateBytes+1)
	if value, err := NewHelperExecPrivateBody(1, sha256.Sum256(privatePlusOne), privatePlusOne); value != nil || !errors.Is(err, ErrHelperExecPrivateShape) {
		if value != nil {
			value.Wipe()
		}
		t.Fatalf("private plus one owner = %#v, %v", value, err)
	}

	payload := bytes.Repeat([]byte{0x42}, MaxHelperExecStreamPayloadBytes)
	stream, err := NewHelperExecStreamBody(1, HelperExecStreamStdout, HelperExecStreamFlagsNone, 0, sha256.Sum256(payload), payload)
	if err != nil {
		t.Fatalf("maximum stream owner: %v", err)
	}
	stream.Wipe()
}

func TestHelperExecCodecsPreserveFullPositiveRevisionRange(t *testing.T) {
	t.Parallel()

	const revision = ^uint64(0)
	plan := helperExecPlanForTest()
	execWire, err := EncodeHelperExecBody(HelperExecBody{Revision: revision, ExecBindingID: "exec", Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeHelperExecBody(execWire); err != nil || decoded.Revision != revision {
		t.Fatalf("exec revision = %d, %v", decoded.Revision, err)
	}

	privateBytes := []byte("p")
	private, err := NewHelperExecPrivateBody(revision, sha256.Sum256(privateBytes), privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer private.Wipe()
	privateWire, _ := EncodeHelperExecPrivateBody(private)
	decodedPrivate, err := DecodeHelperExecPrivateBody(privateWire)
	if err != nil || decodedPrivate.Revision() != revision {
		t.Fatalf("private revision = %d, %v", decodedPrivate.Revision(), err)
	}
	decodedPrivate.Wipe()

	payload := []byte("s")
	stream, err := NewHelperExecStreamBody(revision, HelperExecStreamStdout, HelperExecStreamFlagsNone, 0, sha256.Sum256(payload), payload)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Wipe()
	streamWire, _ := EncodeHelperExecStreamBody(stream)
	decodedStream, err := DecodeHelperExecStreamBody(streamWire)
	if err != nil || decodedStream.Revision() != revision {
		t.Fatalf("stream revision = %d, %v", decodedStream.Revision(), err)
	}
	decodedStream.Wipe()

	creditWire, err := EncodeHelperExecCreditBody(HelperExecCreditBody{Revision: revision, StreamKind: HelperExecStreamStdin})
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeHelperExecCreditBody(creditWire); err != nil || decoded.Revision != revision {
		t.Fatalf("credit revision = %d, %v", decoded.Revision, err)
	}
}

func TestHelperExecStreamExactShapeOwnershipAndEOF(t *testing.T) {
	t.Parallel()

	payload := make([]byte, 3, 19)
	copy(payload, "out")
	digest := sha256.Sum256(payload)
	body, err := NewHelperExecStreamBody(9, HelperExecStreamStdout, HelperExecStreamFlagsNone, 17, digest, payload)
	if err != nil {
		t.Fatalf("NewHelperExecStreamBody: %v", err)
	}
	alias := *body
	payloadBacking := body.state.payload[:cap(body.state.payload)]
	wire, err := EncodeHelperExecStreamBody(body)
	if err != nil {
		t.Fatalf("EncodeHelperExecStreamBody: %v", err)
	}
	if len(wire) != helperExecStreamFixedBytes+3 || wire[8] != 2 || wire[9] != 0 || wire[10] != 0 || wire[11] != 0 || binary.BigEndian.Uint64(wire[12:20]) != 17 || binary.BigEndian.Uint32(wire[20:24]) != 3 {
		t.Fatalf("stream wire = %x", wire)
	}
	decoded, err := DecodeHelperExecStreamBody(wire)
	if err != nil {
		t.Fatalf("DecodeHelperExecStreamBody: %v", err)
	}
	defer decoded.Wipe()
	for length := 0; length < len(wire); length++ {
		if value, err := DecodeHelperExecStreamBody(wire[:length]); !errors.Is(err, ErrHelperExecStreamBodyLength) {
			if value != nil {
				value.Wipe()
			}
			t.Fatalf("stream truncation %d error = %v", length, err)
		}
	}
	if value, err := DecodeHelperExecStreamBody(append(append([]byte(nil), wire...), 0)); !errors.Is(err, ErrHelperExecStreamTrailingData) {
		if value != nil {
			value.Wipe()
		}
		t.Fatalf("stream trailing error = %v", err)
	}
	payload[0] = 'X'
	got := make([]byte, 3)
	if n, err := body.CopyPayload(got); err != nil || n != 3 || string(got) != "out" {
		t.Fatalf("CopyPayload = %q, %d, %v", got, n, err)
	}
	short := []byte{1, 2}
	if n, err := body.CopyPayload(short); n != 0 || !errors.Is(err, ErrHelperExecStreamDestination) || !bytes.Equal(short, []byte{1, 2}) {
		t.Fatalf("short stream copy = %d, %v, %x", n, err, short)
	}
	alias.Wipe()
	if body.state.payload != nil || !body.state.wiped || body.state.revision != 0 || body.state.streamKind != 0 || body.state.flags != 0 || body.state.offset != 0 || body.state.payloadLength != 0 || body.state.payloadSHA256 != [32]byte{} || body.Revision() != 0 || body.StreamKind() != 0 || body.Flags() != 0 || body.Offset() != 0 || body.PayloadLength() != 0 || body.PayloadSHA256() != [32]byte{} || !allHelperExecZero(payloadBacking) {
		t.Fatal("stream wipe did not clear full capacity across aliases")
	}

	emptyDigest := sha256.Sum256(nil)
	eof, err := NewHelperExecStreamBody(9, HelperExecStreamStdin, HelperExecStreamFlagEOF, 20, emptyDigest, nil)
	if err != nil {
		t.Fatalf("EOF constructor: %v", err)
	}
	defer eof.Wipe()
	eofWire, err := EncodeHelperExecStreamBody(eof)
	if err != nil || len(eofWire) != helperExecStreamFixedBytes {
		t.Fatalf("EOF wire length/error = %d/%v", len(eofWire), err)
	}

	tests := []struct {
		name     string
		revision uint64
		kind     HelperExecStreamKind
		flags    HelperExecStreamFlags
		digest   [32]byte
		payload  []byte
		want     error
	}{
		{name: "zero revision", kind: HelperExecStreamStdin, digest: digest, payload: []byte("out"), want: ErrHelperExecRevision},
		{name: "unknown kind", revision: 1, digest: digest, payload: []byte("out"), want: ErrUnknownHelperExecStreamKind},
		{name: "unknown flags", revision: 1, kind: HelperExecStreamStdin, flags: 2, digest: digest, payload: []byte("out"), want: ErrHelperExecStreamFlags},
		{name: "empty data", revision: 1, kind: HelperExecStreamStdin, digest: emptyDigest, want: ErrHelperExecStreamPayloadLength},
		{name: "data digest mismatch", revision: 1, kind: HelperExecStreamStdin, digest: emptyDigest, payload: []byte("out"), want: ErrHelperExecStreamPayloadDigest},
		{name: "EOF payload", revision: 1, kind: HelperExecStreamStdin, flags: HelperExecStreamFlagEOF, digest: digest, payload: []byte("out"), want: ErrHelperExecStreamPayloadLength},
		{name: "EOF digest", revision: 1, kind: HelperExecStreamStdin, flags: HelperExecStreamFlagEOF, digest: digest, want: ErrHelperExecStreamPayloadDigest},
		{name: "plus one", revision: 1, kind: HelperExecStreamStdin, digest: sha256.Sum256(make([]byte, MaxHelperExecStreamPayloadBytes+1)), payload: make([]byte, MaxHelperExecStreamPayloadBytes+1), want: ErrHelperExecStreamPayloadLength},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			value, err := NewHelperExecStreamBody(test.revision, test.kind, test.flags, 0, test.digest, test.payload)
			if value != nil {
				value.Wipe()
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}

	badReserved := append([]byte(nil), eofWire...)
	badReserved[10] = 1
	if _, err := DecodeHelperExecStreamBody(badReserved); !errors.Is(err, ErrHelperExecStreamReserved) {
		t.Fatalf("reserved error = %v", err)
	}
	badStream := append([]byte(nil), wire...)
	clear(badStream[0:8])
	if _, err := DecodeHelperExecStreamBody(badStream); !errors.Is(err, ErrHelperExecRevision) {
		t.Fatalf("stream revision error = %v", err)
	}
	badStream = append([]byte(nil), wire...)
	badStream[8] = 0
	if _, err := DecodeHelperExecStreamBody(badStream); !errors.Is(err, ErrUnknownHelperExecStreamKind) {
		t.Fatalf("stream kind error = %v", err)
	}
	badStream = append([]byte(nil), wire...)
	badStream[9] = 2
	if _, err := DecodeHelperExecStreamBody(badStream); !errors.Is(err, ErrHelperExecStreamFlags) {
		t.Fatalf("stream flags error = %v", err)
	}
	badStream = append([]byte(nil), wire...)
	badStream[24] ^= 0xff
	if _, err := DecodeHelperExecStreamBody(badStream); !errors.Is(err, ErrHelperExecStreamPayloadDigest) {
		t.Fatalf("stream digest error = %v", err)
	}
}

func TestHelperExecCreditIsExact24Bytes(t *testing.T) {
	t.Parallel()

	body := HelperExecCreditBody{Revision: 11, StreamKind: HelperExecStreamStderr, NextOffset: 0x0102030405060708}
	wire, err := EncodeHelperExecCreditBody(body)
	if err != nil {
		t.Fatalf("EncodeHelperExecCreditBody: %v", err)
	}
	if len(wire) != HelperExecCreditBodyBytes || HelperExecCreditBodyBytes != 24 {
		t.Fatalf("credit length = %d constant = %d", len(wire), HelperExecCreditBodyBytes)
	}
	want := make([]byte, 24)
	binary.BigEndian.PutUint64(want[0:8], 11)
	want[8] = 3
	binary.BigEndian.PutUint64(want[16:24], 0x0102030405060708)
	if !bytes.Equal(wire, want) {
		t.Fatalf("credit = %x, want %x", wire, want)
	}
	decoded, err := DecodeHelperExecCreditBody(wire)
	if err != nil || decoded != body {
		t.Fatalf("decoded = %#v, %v", decoded, err)
	}
	for length := 0; length < len(wire); length++ {
		if _, err := DecodeHelperExecCreditBody(wire[:length]); !errors.Is(err, ErrHelperExecCreditBodyLength) {
			t.Fatalf("truncated %d error = %v", length, err)
		}
	}
	if _, err := DecodeHelperExecCreditBody(append(wire, 0)); !errors.Is(err, ErrHelperExecCreditTrailingData) {
		t.Fatalf("trailing error = %v", err)
	}
	badReserved := append([]byte(nil), wire...)
	badReserved[15] = 1
	if _, err := DecodeHelperExecCreditBody(badReserved); !errors.Is(err, ErrHelperExecCreditReserved) {
		t.Fatalf("reserved error = %v", err)
	}
	if _, err := EncodeHelperExecCreditBody(HelperExecCreditBody{StreamKind: HelperExecStreamStdin}); !errors.Is(err, ErrHelperExecRevision) {
		t.Fatalf("zero revision encode error = %v", err)
	}
	if _, err := EncodeHelperExecCreditBody(HelperExecCreditBody{Revision: 1}); !errors.Is(err, ErrUnknownHelperExecStreamKind) {
		t.Fatalf("zero kind encode error = %v", err)
	}
	badRevision := append([]byte(nil), wire...)
	clear(badRevision[:8])
	if _, err := DecodeHelperExecCreditBody(badRevision); !errors.Is(err, ErrHelperExecRevision) {
		t.Fatalf("zero revision decode error = %v", err)
	}
	badKind := append([]byte(nil), wire...)
	badKind[8] = 4
	if _, err := DecodeHelperExecCreditBody(badKind); !errors.Is(err, ErrUnknownHelperExecStreamKind) {
		t.Fatalf("unknown kind decode error = %v", err)
	}
}

func TestHelperExecPrivateAndStreamOwnersDenyFormattingAndSerialization(t *testing.T) {
	t.Parallel()

	privateBytes := []byte("private-marker")
	private, err := NewHelperExecPrivateBody(1, sha256.Sum256(privateBytes), privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer private.Wipe()
	streamBytes := []byte("stream-marker")
	stream, err := NewHelperExecStreamBody(1, HelperExecStreamStdout, HelperExecStreamFlagsNone, 0, sha256.Sum256(streamBytes), streamBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Wipe()

	plan := helperExecPlanForTest()
	exec := HelperExecBody{Revision: 1, ExecBindingID: "binding", Plan: plan}
	for _, value := range []any{plan.Environment[0], &plan.Environment[0], plan.Timing, &plan.Timing, plan, &plan, exec, &exec, *private, private, *stream, stream, HelperExecCreditBody{Revision: 1, StreamKind: HelperExecStreamStdin}} {
		formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x", value, value, value, value, value, value)
		if strings.Contains(formatted, "marker") || strings.Contains(formatted, "[112 114") {
			t.Fatalf("%T formatting leaked: %q", value, formatted)
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrHelperExecBodySerialization) {
			t.Fatalf("json.Marshal(%T) error = %v", value, err)
		}
		if _, err := value.(encoding.TextMarshaler).MarshalText(); !errors.Is(err, ErrHelperExecBodySerialization) {
			t.Fatalf("MarshalText(%T) error = %v", value, err)
		}
		if _, err := value.(encoding.BinaryMarshaler).MarshalBinary(); !errors.Is(err, ErrHelperExecBodySerialization) {
			t.Fatalf("MarshalBinary(%T) error = %v", value, err)
		}
	}

	privateBefore := *private.state
	streamBefore := *stream.state
	privateBytesBefore := make([]byte, private.PrivateBindingLength())
	_, _ = private.CopyPrivateBinding(privateBytesBefore)
	streamBytesBefore := make([]byte, stream.PayloadLength())
	_, _ = stream.CopyPayload(streamBytesBefore)
	for _, target := range []any{private, stream} {
		if err := json.Unmarshal([]byte(`{"state":"private-marker"}`), target); !errors.Is(err, ErrHelperExecBodySerialization) {
			t.Fatalf("json.Unmarshal(%T) error = %v", target, err)
		}
		if err := target.(encoding.TextUnmarshaler).UnmarshalText([]byte("private-marker")); !errors.Is(err, ErrHelperExecBodySerialization) {
			t.Fatalf("UnmarshalText(%T) error = %v", target, err)
		}
		if err := target.(encoding.BinaryUnmarshaler).UnmarshalBinary([]byte("private-marker")); !errors.Is(err, ErrHelperExecBodySerialization) {
			t.Fatalf("UnmarshalBinary(%T) error = %v", target, err)
		}
	}
	if !reflect.DeepEqual(*private.state, privateBefore) || !reflect.DeepEqual(*stream.state, streamBefore) {
		t.Fatal("denied unmarshal mutated an opaque owner")
	}
	privateBytesAfter := make([]byte, private.PrivateBindingLength())
	_, _ = private.CopyPrivateBinding(privateBytesAfter)
	streamBytesAfter := make([]byte, stream.PayloadLength())
	_, _ = stream.CopyPayload(streamBytesAfter)
	if !bytes.Equal(privateBytesAfter, privateBytesBefore) || !bytes.Equal(streamBytesAfter, streamBytesBefore) {
		t.Fatal("denied unmarshal mutated opaque bytes")
	}

	for _, target := range []any{&HelperExecEnvironment{}, &HelperExecTiming{}, &HelperExecPlan{}, &HelperExecBody{}, &HelperExecCreditBody{}} {
		if err := json.Unmarshal([]byte(`{"Arguments":["private-marker"],"Value":"private-marker"}`), target); !errors.Is(err, ErrHelperExecBodySerialization) {
			t.Fatalf("json.Unmarshal(%T) error = %v", target, err)
		}
		if err := target.(encoding.TextUnmarshaler).UnmarshalText([]byte("private-marker")); !errors.Is(err, ErrHelperExecBodySerialization) {
			t.Fatalf("UnmarshalText(%T) error = %v", target, err)
		}
		if err := target.(encoding.BinaryUnmarshaler).UnmarshalBinary([]byte("private-marker")); !errors.Is(err, ErrHelperExecBodySerialization) {
			t.Fatalf("UnmarshalBinary(%T) error = %v", target, err)
		}
		if !reflect.ValueOf(target).Elem().IsZero() {
			t.Fatalf("denied generic decode mutated %T", target)
		}
	}
}

func TestHelperExecPublicTypesHaveExactFieldsAndNoTags(t *testing.T) {
	t.Parallel()

	assertFields := func(value any, names ...string) {
		t.Helper()
		typeOf := reflect.TypeOf(value)
		if typeOf.NumField() != len(names) {
			t.Fatalf("%s fields = %d, want %d", typeOf, typeOf.NumField(), len(names))
		}
		for index, name := range names {
			field := typeOf.Field(index)
			if field.Name != name || field.Tag != "" {
				t.Errorf("%s field %d = %s tag %q, want %s no tag", typeOf, index, field.Name, field.Tag, name)
			}
		}
	}
	assertFields(HelperExecEnvironment{}, "Name", "Source", "Value")
	assertFields(HelperExecTiming{}, "Kind", "Value")
	assertFields(HelperExecPlan{}, "Arguments", "Environment", "WorkDirectory", "StdinMode", "StdoutMode", "StderrMode", "StdinMaxBytes", "StdoutMaxBytes", "StderrMaxBytes", "Timing")
	assertFields(HelperExecBody{}, "Revision", "ExecBindingID", "PrivateBindingLength", "PrivateBindingSHA256", "Plan")
	assertFields(HelperExecCreditBody{}, "Revision", "StreamKind", "NextOffset")
	for _, value := range []any{HelperExecPrivateBody{}, HelperExecStreamBody{}} {
		typeOf := reflect.TypeOf(value)
		if typeOf.NumField() != 1 || typeOf.Field(0).Name != "state" || typeOf.Field(0).IsExported() || typeOf.Field(0).Tag != "" {
			t.Errorf("%s opaque fields are not exact", typeOf)
		}
	}
	assertFields(helperExecStreamState{}, "revision", "streamKind", "flags", "offset", "payloadLength", "payloadSHA256", "payload", "wiped")
}

func helperExecPlanForTest() HelperExecPlan {
	return HelperExecPlan{
		Arguments: []string{"/usr/bin/pi"},
		Environment: []HelperExecEnvironment{
			{Name: "PATH", Source: HelperExecEnvironmentInherited},
			{Name: "HTTP_PROXY", Source: HelperExecEnvironmentGenerated, Value: "http://proxy"},
			{Name: "HTTPS_PROXY", Source: HelperExecEnvironmentGenerated, Value: "http://proxy"},
			{Name: "http_proxy", Source: HelperExecEnvironmentGenerated, Value: "http://proxy"},
			{Name: "https_proxy", Source: HelperExecEnvironmentGenerated, Value: "http://proxy"},
		},
		WorkDirectory: "/workspace",
		StdinMode:     HelperExecStreamModePipe, StdoutMode: HelperExecStreamModePipe, StderrMode: HelperExecStreamModePipe,
		StdinMaxBytes: 1, StdoutMaxBytes: 1, StderrMaxBytes: 1,
		Timing: HelperExecTiming{Kind: HelperExecTimingTimeoutMillis, Value: 1},
	}
}

func allHelperExecZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func helperExecMustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	return decoded
}
