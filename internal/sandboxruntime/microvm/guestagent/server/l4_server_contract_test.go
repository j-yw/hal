package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

func TestL4ServerPublicDefaultsAndStates(t *testing.T) {
	const (
		oneMiB   = int64(1024 * 1024)
		eightMiB = int64(8 * 1024 * 1024)
	)
	tests := []struct {
		name string
		got  any
		want any
	}{
		{name: "default request bytes", got: DefaultMaxRequestBytes, want: oneMiB},
		{name: "default response bytes", got: DefaultMaxResponseBytes, want: oneMiB},
		{name: "minimum response bytes", got: MinimumMaxResponseBytes, want: int64(512)},
		{name: "maximum message bytes", got: MaximumEncodedMessageBytes, want: eightMiB},
		{name: "default concurrent", got: DefaultMaxConcurrent, want: 1},
		{name: "maximum concurrent", got: MaximumMaxConcurrent, want: 64},
		{name: "default operation time", got: DefaultMaxOperationTime, want: 24 * time.Hour},
		{name: "maximum operation time", got: MaximumMaxOperationTime, want: 24 * time.Hour},
		{name: "default shutdown time", got: DefaultMaxShutdownTime, want: 30 * time.Second},
		{name: "maximum shutdown time", got: MaximumMaxShutdownTime, want: 2 * time.Minute},
		{name: "maximum JSON depth", got: MaximumJSONNestingDepth, want: 32},
		{name: "default stdin bytes", got: DefaultExecStdinBytes, want: int64(512 * 1024)},
		{name: "default stdout bytes", got: DefaultExecStdoutBytes, want: int64(256 * 1024)},
		{name: "default stderr bytes", got: DefaultExecStderrBytes, want: int64(256 * 1024)},
		{name: "default copy bytes", got: DefaultCopyBytes, want: int64(512 * 1024)},
		{name: "new state", got: string(StateNew), want: "new"},
		{name: "serving state", got: string(StateServing), want: "serving"},
		{name: "draining state", got: string(StateDraining), want: "draining"},
		{name: "stopped state", got: string(StateStopped), want: "stopped"},
		{name: "failed state", got: string(StateFailed), want: "failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("value = %#v, want %#v", tt.got, tt.want)
			}
		})
	}

	transport := newL4BlockingTransport()
	run := startL4Server(t, Options{Transport: transport, Backend: &l4FakeBackend{}})
	if run.limits.MaxRequestBytes != DefaultMaxRequestBytes {
		t.Fatalf("transport request limit = %d, want %d", run.limits.MaxRequestBytes, DefaultMaxRequestBytes)
	}
	if run.limits.MaxResponseBytes != DefaultMaxResponseBytes {
		t.Fatalf("transport response limit = %d, want %d", run.limits.MaxResponseBytes, DefaultMaxResponseBytes)
	}
	if got := string(run.server.State()); got != "serving" {
		t.Fatalf("State() = %q, want serving", got)
	}
}

func TestL4ServerConstructorValidation(t *testing.T) {
	valid := func() Options {
		return Options{
			Transport: newL4BlockingTransport(),
			Backend:   &l4FakeBackend{},
		}
	}
	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{name: "nil transport", mutate: func(options *Options) { options.Transport = nil }},
		{name: "nil backend", mutate: func(options *Options) { options.Backend = nil }},
		{name: "negative request limit", mutate: func(options *Options) { options.MaxRequestBytes = -1 }},
		{name: "request above maximum", mutate: func(options *Options) { options.MaxRequestBytes = MaximumEncodedMessageBytes + 1 }},
		{name: "negative response limit", mutate: func(options *Options) { options.MaxResponseBytes = -1 }},
		{name: "response below minimum", mutate: func(options *Options) { options.MaxResponseBytes = MinimumMaxResponseBytes - 1 }},
		{name: "response above maximum", mutate: func(options *Options) { options.MaxResponseBytes = MaximumEncodedMessageBytes + 1 }},
		{name: "negative concurrency", mutate: func(options *Options) { options.MaxConcurrent = -1 }},
		{name: "concurrency above maximum", mutate: func(options *Options) { options.MaxConcurrent = MaximumMaxConcurrent + 1 }},
		{name: "negative operation time", mutate: func(options *Options) { options.MaxOperationTime = -1 }},
		{name: "operation time above maximum", mutate: func(options *Options) { options.MaxOperationTime = MaximumMaxOperationTime + time.Nanosecond }},
		{name: "negative shutdown time", mutate: func(options *Options) { options.MaxShutdownTime = -1 }},
		{name: "shutdown time above maximum", mutate: func(options *Options) { options.MaxShutdownTime = MaximumMaxShutdownTime + time.Nanosecond }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := valid()
			tt.mutate(&options)
			if server, err := New(options); err == nil {
				if server != nil {
					_ = server.Shutdown(context.Background())
				}
				t.Fatal("New() error = nil, want constructor validation failure")
			}
		})
	}
}

func TestL4ServerDispatchesAllV1OperationsFromWireBytes(t *testing.T) {
	copyInData := []byte("copy-in")
	copyInDigest := l4Digest(copyInData)
	copyOutData := []byte("copy-out")
	copyOutDigest := l4Digest(copyOutData)
	backend := &l4FakeBackend{
		execResult: ExecResult{
			ExitCode:        7,
			Stdout:          []byte{0x00, 0xff},
			Stderr:          []byte("err"),
			StdoutTruncated: true,
		},
		copyInResult: CopyResult{
			SizeBytes: int64(len(copyInData)),
			Digest:    copyInDigest,
		},
		copyOutResult: CopyResult{
			Data:      copyOutData,
			SizeBytes: int64(len(copyOutData)),
			Digest:    copyOutDigest,
		},
	}
	resolver := &l4Resolver{value: "resolved"}
	run := startL4Server(t, Options{
		Transport:           newL4BlockingTransport(),
		Backend:             backend,
		EnvironmentResolver: resolver,
	})

	readiness := l4HandleJSON[guestagent.ReadinessResponse](t, run.server, guestagent.ReadinessRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationReadiness,
	})
	if !readiness.Ready || readiness.Status != guestagent.ReadinessStatusReady {
		t.Fatalf("readiness = %#v, want canonical ready response", readiness)
	}

	execResponse := l4HandleJSON[guestagent.ExecResponse](t, run.server, guestagent.ExecRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationExec,
		Args:            []string{"tool", "arg"},
		Env:             []guestagent.EnvironmentEntry{{Name: "HAL_MODE", Source: guestagent.EnvironmentSourceGenerated}},
		WorkDir:         "/workspace/project",
		Stdin: &guestagent.StreamMetadata{
			SizeBytes: 3,
			MaxBytes:  8,
			Data:      base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0xff}),
			Encoding:  guestagent.PayloadEncodingBase64,
		},
		Stdout: guestagent.StreamMetadata{MaxBytes: 32},
		Stderr: guestagent.StreamMetadata{MaxBytes: 16},
	})
	if execResponse.ExitCode != 7 ||
		execResponse.Stdout.Data != base64.StdEncoding.EncodeToString([]byte{0x00, 0xff}) ||
		execResponse.Stdout.Encoding != guestagent.PayloadEncodingBase64 ||
		!execResponse.Stdout.Truncated ||
		execResponse.Stderr.Data != base64.StdEncoding.EncodeToString([]byte("err")) {
		t.Fatalf("exec response = %#v, want bounded binary result", execResponse)
	}

	copyInResponse := l4HandleJSON[guestagent.CopyInResponse](t, run.server, guestagent.CopyInRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationCopyIn,
		DestinationPath: "/workspace/input.bin",
		Payload: guestagent.PayloadMetadata{
			SizeBytes: int64(len(copyInData)),
			MaxBytes:  32,
			Digest:    copyInDigest,
			Encoding:  guestagent.PayloadEncodingBase64,
			Data:      base64.StdEncoding.EncodeToString(copyInData),
		},
	})
	if copyInResponse.Written.SizeBytes != int64(len(copyInData)) || copyInResponse.Written.Digest != copyInDigest {
		t.Fatalf("copy_in response = %#v, want size and digest", copyInResponse)
	}

	copyOutResponse := l4HandleJSON[guestagent.CopyOutResponse](t, run.server, guestagent.CopyOutRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationCopyOut,
		SourcePath:      "/workspace/output.bin",
		Payload: guestagent.PayloadMetadata{
			MaxBytes: 32,
			Encoding: guestagent.PayloadEncodingBase64,
		},
	})
	if copyOutResponse.Payload.Data != base64.StdEncoding.EncodeToString(copyOutData) ||
		copyOutResponse.Payload.SizeBytes != int64(len(copyOutData)) ||
		copyOutResponse.Payload.Digest != copyOutDigest {
		t.Fatalf("copy_out response = %#v, want exact payload", copyOutResponse)
	}

	if backend.readyCalls.Load() != 1 || backend.execCalls.Load() != 1 ||
		backend.copyInCalls.Load() != 1 || backend.copyOutCalls.Load() != 1 {
		t.Fatalf("backend calls readiness=%d exec=%d copy_in=%d copy_out=%d, want one each",
			backend.readyCalls.Load(), backend.execCalls.Load(), backend.copyInCalls.Load(), backend.copyOutCalls.Load())
	}
	if resolver.calls.Load() != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolver.calls.Load())
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if got := backend.execPlans[0].Environment; len(got) != 1 || got[0] != "HAL_MODE=resolved" {
		t.Fatalf("exec environment = %#v, want resolver assignment", got)
	}
	if got := backend.execPlans[0].Stdin; string(got) != string([]byte{0x00, 0x01, 0xff}) {
		t.Fatalf("exec stdin = %v, want decoded bytes", got)
	}
	if got := backend.copyInPlans[0].Data; string(got) != string(copyInData) {
		t.Fatalf("copy_in data = %q, want %q", got, copyInData)
	}
}

func TestL4ServerStrictRequestFailuresNeverReachBackend(t *testing.T) {
	deep := `{"protocolVersion":"guest-agent-v1","operation":"readiness","extra":` +
		strings.Repeat("[", MaximumJSONNestingDepth+1) + `0` +
		strings.Repeat("]", MaximumJSONNestingDepth+1) + `}`
	tests := []struct {
		name string
		body []byte
		code guestagent.ErrorCode
	}{
		{name: "empty", body: nil, code: guestagent.ErrorCodeMalformedRequest},
		{name: "null", body: []byte(`null`), code: guestagent.ErrorCodeMalformedRequest},
		{name: "array", body: []byte(`[]`), code: guestagent.ErrorCodeMalformedRequest},
		{name: "invalid UTF-8", body: []byte{0xff}, code: guestagent.ErrorCodeMalformedRequest},
		{name: "trailing document", body: []byte(`{"protocolVersion":"guest-agent-v1","operation":"readiness"} {}`), code: guestagent.ErrorCodeMalformedRequest},
		{name: "duplicate header", body: []byte(`{"protocolVersion":"guest-agent-v1","protocolVersion":"guest-agent-v1","operation":"readiness"}`), code: guestagent.ErrorCodeMalformedRequest},
		{name: "duplicate nested", body: []byte(`{"protocolVersion":"guest-agent-v1","operation":"exec","args":["tool"],"env":[{"name":"A","name":"B"}],"workDir":"/workspace","stdout":{},"stderr":{}}`), code: guestagent.ErrorCodeMalformedRequest},
		{name: "noncanonical nested alias", body: []byte(`{"protocolVersion":"guest-agent-v1","operation":"exec","args":["tool"],"env":[{"name":"A","Name":"B"}],"workDir":"/workspace","stdout":{},"stderr":{}}`), code: guestagent.ErrorCodeMalformedRequest},
		{name: "null argument scalar", body: []byte(`{"protocolVersion":"guest-agent-v1","operation":"exec","args":["tool",null],"workDir":"/workspace","stdout":{"maxBytes":16},"stderr":{"maxBytes":16}}`), code: guestagent.ErrorCodeMalformedRequest},
		{name: "null metadata scalar", body: []byte(`{"protocolVersion":"guest-agent-v1","operation":"exec","args":["tool"],"workDir":"/workspace","stdout":{"maxBytes":16,"truncated":null},"stderr":{"maxBytes":16}}`), code: guestagent.ErrorCodeMalformedRequest},
		{name: "null timing scalar", body: []byte(`{"protocolVersion":"guest-agent-v1","operation":"readiness","timing":{"timeoutMillis":null}}`), code: guestagent.ErrorCodeMalformedRequest},
		{name: "padded raw encoding", body: []byte(`{"protocolVersion":"guest-agent-v1","operation":"exec","args":["tool"],"workDir":"/workspace","stdout":{"maxBytes":16,"encoding":" raw "},"stderr":{"maxBytes":16}}`), code: guestagent.ErrorCodeInvalidMetadata},
		{name: "padded base64 encoding", body: []byte(`{"protocolVersion":"guest-agent-v1","operation":"exec","args":["tool"],"workDir":"/workspace","stdout":{"maxBytes":16,"encoding":" base64 "},"stderr":{"maxBytes":16}}`), code: guestagent.ErrorCodeInvalidMetadata},
		{name: "padded chunked encoding", body: []byte(`{"protocolVersion":"guest-agent-v1","operation":"exec","args":["tool"],"workDir":"/workspace","stdout":{"maxBytes":16,"encoding":" chunked "},"stderr":{"maxBytes":16}}`), code: guestagent.ErrorCodeInvalidMetadata},
		{name: "unknown top field", body: []byte(`{"protocolVersion":"guest-agent-v1","operation":"readiness","extra":true}`), code: guestagent.ErrorCodeMalformedRequest},
		{name: "unknown nested field", body: []byte(`{"protocolVersion":"guest-agent-v1","operation":"readiness","timing":{"extra":1}}`), code: guestagent.ErrorCodeMalformedRequest},
		{name: "excessive nesting", body: []byte(deep), code: guestagent.ErrorCodeMalformedRequest},
		{name: "unsupported version", body: []byte(`{"protocolVersion":"guest-agent-v2","operation":"readiness"}`), code: guestagent.ErrorCodeUnsupportedProtocolVersion},
		{name: "unknown operation", body: []byte(`{"protocolVersion":"guest-agent-v1","operation":"destroy"}`), code: guestagent.ErrorCodeUnknownOperation},
		{name: "invalid DTO", body: []byte(`{"protocolVersion":"guest-agent-v1","operation":"exec","args":[],"workDir":"/workspace","stdout":{},"stderr":{}}`), code: guestagent.ErrorCodeMissingRequiredField},
		{name: "dot path segment", body: []byte(`{"protocolVersion":"guest-agent-v1","operation":"exec","args":["tool"],"workDir":"/workspace/dir/./file","stdout":{"maxBytes":16},"stderr":{"maxBytes":16}}`), code: guestagent.ErrorCodeMalformedPath},
		{name: "trailing path separator", body: []byte(`{"protocolVersion":"guest-agent-v1","operation":"copy_out","sourcePath":"/workspace/dir/","payload":{"maxBytes":16,"encoding":"base64"}}`), code: guestagent.ErrorCodeMalformedPath},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &l4FakeBackend{}
			run := startL4Server(t, Options{Transport: newL4BlockingTransport(), Backend: backend})
			response := run.server.Handle(context.Background(), Request{Encoded: tt.body})
			l4RequireResponseCode(t, response, tt.code)
			if got := backend.totalOperationCalls(); got != 0 {
				t.Fatalf("backend operation calls = %d, want 0", got)
			}
		})
	}
}

func TestL4ServerEncodedRequestAndResponseLimits(t *testing.T) {
	requestBackend := &l4FakeBackend{}
	requestRun := startL4Server(t, Options{
		Transport:       newL4BlockingTransport(),
		Backend:         requestBackend,
		MaxRequestBytes: 128,
	})
	oversized := []byte(`{"protocolVersion":"guest-agent-v1","operation":"readiness","padding":"` + strings.Repeat("x", 128) + `"}`)
	l4RequireResponseCode(t, requestRun.server.Handle(context.Background(), Request{Encoded: oversized}), guestagent.ErrorCodeOversizedRequest)
	if got := requestBackend.totalOperationCalls(); got != 0 {
		t.Fatalf("backend operation calls = %d, want 0", got)
	}

	responseBackend := &l4FakeBackend{
		execResult: ExecResult{
			Stdout: []byte(strings.Repeat("x", 1024)),
		},
	}
	responseRun := startL4Server(t, Options{
		Transport:        newL4BlockingTransport(),
		Backend:          responseBackend,
		MaxResponseBytes: MinimumMaxResponseBytes,
	})
	response := l4Handle(t, responseRun.server, guestagent.ExecRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationExec,
		Args:            []string{"tool"},
		WorkDir:         "/workspace",
		Stdout:          guestagent.StreamMetadata{MaxBytes: 2048},
		Stderr:          guestagent.StreamMetadata{MaxBytes: 2048},
	})
	l4RequireResponseCode(t, response, guestagent.ErrorCodeOversizedResponse)
	if len(response.Encoded) > int(MinimumMaxResponseBytes) {
		t.Fatalf("error envelope bytes = %d, want <= %d", len(response.Encoded), MinimumMaxResponseBytes)
	}
}

func TestL4ServerEnvironmentResolutionFailsClosed(t *testing.T) {
	const (
		maxResolvedValueBytes = 64 << 10
		maxResolvedTotalBytes = 256 << 10
	)
	request := guestagent.ExecRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationExec,
		Args:            []string{"tool"},
		Env:             []guestagent.EnvironmentEntry{{Name: "HAL_VALUE", Source: guestagent.EnvironmentSourceGenerated}},
		WorkDir:         "/workspace",
		Stdout:          guestagent.StreamMetadata{MaxBytes: 16},
		Stderr:          guestagent.StreamMetadata{MaxBytes: 16},
	}

	t.Run("default resolver rejects", func(t *testing.T) {
		backend := &l4FakeBackend{}
		run := startL4Server(t, Options{Transport: newL4BlockingTransport(), Backend: backend})
		l4RequireResponseCode(t, l4Handle(t, run.server, request), guestagent.ErrorCodeEnvironmentUnavailable)
		if backend.execCalls.Load() != 0 {
			t.Fatalf("Exec calls = %d, want 0", backend.execCalls.Load())
		}
	})

	t.Run("typed nil resolver rejects", func(t *testing.T) {
		backend := &l4FakeBackend{}
		var resolver *l4Resolver
		run := startL4Server(t, Options{
			Transport:           newL4BlockingTransport(),
			Backend:             backend,
			EnvironmentResolver: resolver,
		})
		l4RequireResponseCode(t, l4Handle(t, run.server, request), guestagent.ErrorCodeEnvironmentUnavailable)
		if backend.execCalls.Load() != 0 {
			t.Fatalf("Exec calls = %d, want 0", backend.execCalls.Load())
		}
	})

	t.Run("secret rejected before resolver", func(t *testing.T) {
		backend := &l4FakeBackend{}
		resolver := &l4Resolver{value: "must-not-be-used"}
		run := startL4Server(t, Options{
			Transport:           newL4BlockingTransport(),
			Backend:             backend,
			EnvironmentResolver: resolver,
		})
		secretRequest := request
		secretRequest.Env = []guestagent.EnvironmentEntry{{Name: "TOKEN", Source: guestagent.EnvironmentSourceSecret}}
		l4RequireResponseCode(t, l4Handle(t, run.server, secretRequest), guestagent.ErrorCodeEnvironmentUnavailable)
		if resolver.calls.Load() != 0 || backend.execCalls.Load() != 0 {
			t.Fatalf("resolver calls=%d exec calls=%d, want zero", resolver.calls.Load(), backend.execCalls.Load())
		}
	})

	t.Run("noncanonical secret source rejected before resolver", func(t *testing.T) {
		backend := &l4FakeBackend{}
		resolver := &l4Resolver{value: "must-not-be-used"}
		run := startL4Server(t, Options{
			Transport:           newL4BlockingTransport(),
			Backend:             backend,
			EnvironmentResolver: resolver,
		})
		secretRequest := request
		secretRequest.Env = []guestagent.EnvironmentEntry{{Name: "TOKEN", Source: " secret "}}
		l4RequireResponseCode(t, l4Handle(t, run.server, secretRequest), guestagent.ErrorCodeInvalidMetadata)
		if resolver.calls.Load() != 0 || backend.execCalls.Load() != 0 {
			t.Fatalf("resolver calls=%d exec calls=%d, want zero", resolver.calls.Load(), backend.execCalls.Load())
		}
	})

	t.Run("resolver failure is fixed and redacted", func(t *testing.T) {
		backend := &l4FakeBackend{}
		resolver := &l4Resolver{err: errors.New("token=ghp_secret123 /private/resolver")}
		run := startL4Server(t, Options{
			Transport:           newL4BlockingTransport(),
			Backend:             backend,
			EnvironmentResolver: resolver,
		})
		response := l4Handle(t, run.server, request)
		l4RequireResponseCode(t, response, guestagent.ErrorCodeEnvironmentUnavailable)
		lower := strings.ToLower(string(response.Encoded))
		for _, forbidden := range []string{"ghp_secret123", "/private/resolver"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("response leaked %q: %s", forbidden, response.Encoded)
			}
		}
		if backend.execCalls.Load() != 0 {
			t.Fatalf("Exec calls = %d, want 0", backend.execCalls.Load())
		}
	})

	t.Run("maximum resolved value is accepted", func(t *testing.T) {
		backend := &l4FakeBackend{}
		resolver := &l4Resolver{value: strings.Repeat("x", maxResolvedValueBytes)}
		run := startL4Server(t, Options{
			Transport:           newL4BlockingTransport(),
			Backend:             backend,
			EnvironmentResolver: resolver,
		})
		response := l4Handle(t, run.server, request)
		decoded := l4DecodeResponse[guestagent.ExecResponse](t, response)
		if err := guestagent.ValidateExecResponse(decoded); err != nil {
			t.Fatalf("ValidateExecResponse(%s) error: %v", response.Encoded, err)
		}
		if backend.execCalls.Load() != 1 {
			t.Fatalf("Exec calls = %d, want 1", backend.execCalls.Load())
		}
	})

	t.Run("oversized resolved value is rejected", func(t *testing.T) {
		backend := &l4FakeBackend{}
		resolver := &l4Resolver{value: strings.Repeat("x", maxResolvedValueBytes+1)}
		run := startL4Server(t, Options{
			Transport:           newL4BlockingTransport(),
			Backend:             backend,
			EnvironmentResolver: resolver,
		})
		l4RequireResponseCode(t, l4Handle(t, run.server, request), guestagent.ErrorCodeEnvironmentUnavailable)
		if backend.execCalls.Load() != 0 {
			t.Fatalf("Exec calls = %d, want 0", backend.execCalls.Load())
		}
	})

	t.Run("resolver success after deadline never dispatches", func(t *testing.T) {
		backend := &l4FakeBackend{}
		resolver := &l4Resolver{value: "late-value", returnAfterContext: true}
		run := startL4Server(t, Options{
			Transport:           newL4BlockingTransport(),
			Backend:             backend,
			EnvironmentResolver: resolver,
		})
		deadlineRequest := request
		deadlineRequest.Timing = &guestagent.TimingMetadata{TimeoutMillis: 1}
		l4RequireResponseCode(t, l4Handle(t, run.server, deadlineRequest), guestagent.ErrorCodeRequestTimeout)
		if resolver.calls.Load() != 1 {
			t.Fatalf("resolver calls = %d, want 1", resolver.calls.Load())
		}
		if backend.execCalls.Load() != 0 {
			t.Fatalf("Exec calls = %d, want 0", backend.execCalls.Load())
		}
	})

	t.Run("aggregate resolved environment is rejected", func(t *testing.T) {
		backend := &l4FakeBackend{}
		resolver := &l4Resolver{value: strings.Repeat("x", maxResolvedValueBytes)}
		run := startL4Server(t, Options{
			Transport:           newL4BlockingTransport(),
			Backend:             backend,
			EnvironmentResolver: resolver,
		})
		aggregateRequest := request
		aggregateRequest.Env = []guestagent.EnvironmentEntry{
			{Name: "HAL_VALUE_1", Source: guestagent.EnvironmentSourceGenerated},
			{Name: "HAL_VALUE_2", Source: guestagent.EnvironmentSourceGenerated},
			{Name: "HAL_VALUE_3", Source: guestagent.EnvironmentSourceGenerated},
			{Name: "HAL_VALUE_4", Source: guestagent.EnvironmentSourceGenerated},
		}
		if minimumBytes := 4 * (maxResolvedValueBytes + len("HAL_VALUE_1=")); minimumBytes <= maxResolvedTotalBytes {
			t.Fatalf("test aggregate bytes = %d, want above %d", minimumBytes, maxResolvedTotalBytes)
		}
		l4RequireResponseCode(t, l4Handle(t, run.server, aggregateRequest), guestagent.ErrorCodeEnvironmentUnavailable)
		if backend.execCalls.Load() != 0 {
			t.Fatalf("Exec calls = %d, want 0", backend.execCalls.Load())
		}
	})
}

func TestL4ServerBackendFailureUsesGenericErrorEnvelope(t *testing.T) {
	backend := &l4FakeBackend{execErr: errors.New("exec /private/tool token=ghp_secret123 failed")}
	run := startL4Server(t, Options{Transport: newL4BlockingTransport(), Backend: backend})
	response := l4Handle(t, run.server, guestagent.ExecRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationExec,
		Args:            []string{"tool"},
		WorkDir:         "/workspace",
		Stdout:          guestagent.StreamMetadata{MaxBytes: 16},
		Stderr:          guestagent.StreamMetadata{MaxBytes: 16},
	})
	l4RequireResponseCode(t, response, guestagent.ErrorCodeExecutionFailed)
	var object map[string]any
	if err := json.Unmarshal(response.Encoded, &object); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	for _, key := range []string{"exitCode", "stdout", "stderr"} {
		if _, ok := object[key]; ok {
			t.Fatalf("generic error response unexpectedly contains %q: %s", key, response.Encoded)
		}
	}
	for _, key := range []string{"protocolVersion", "operation", "error"} {
		if _, ok := object[key]; !ok {
			t.Fatalf("generic error response missing %q: %s", key, response.Encoded)
		}
	}
	lower := strings.ToLower(string(response.Encoded))
	for _, forbidden := range []string{"/private/tool", "ghp_secret123"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, response.Encoded)
		}
	}
}

func l4HandleJSON[T any](t *testing.T, server *Server, value any) T {
	t.Helper()
	return l4DecodeResponse[T](t, l4Handle(t, server, value))
}

func l4Handle(t *testing.T, server *Server, value any) Response {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%T) error: %v", value, err)
	}
	return server.Handle(context.Background(), Request{Encoded: encoded})
}

func l4Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
