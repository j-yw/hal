package sandboxworker

import (
	"strings"
	"testing"
)

func TestWorkerIOMaximumsArePositiveAndBounded(t *testing.T) {
	tests := []struct {
		name    string
		maximum int64
	}{
		{name: "exec stdin", maximum: MaxExecStdinBytes},
		{name: "exec stdout capture", maximum: MaxExecStdoutCaptureBytes},
		{name: "exec stderr capture", maximum: MaxExecStderrCaptureBytes},
		{name: "copy in payload", maximum: MaxCopyInPayloadBytes},
		{name: "copy out payload", maximum: MaxCopyOutPayloadBytes},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.maximum <= 0 {
				t.Fatalf("%s maximum = %d, want positive bound", tt.name, tt.maximum)
			}
			if tt.maximum > defaultMaxRequestBytes || tt.maximum > defaultMaxResponseBytes {
				t.Fatalf("%s maximum = %d, want no larger than default socket request/response caps", tt.name, tt.maximum)
			}
		})
	}
}

func TestWorkerIOValidationRejectsMissingOperationIDAndTargetMetadata(t *testing.T) {
	if err := validateWorkerIOOperationID(" "); err == nil {
		t.Fatal("validateWorkerIOOperationID() error = nil, want missing operation ID error")
	}
	if err := validateWorkerIOOperationID("op-001"); err != nil {
		t.Fatalf("validateWorkerIOOperationID() unexpected error: %v", err)
	}

	err := validateWorkerIOTarget(Target{Name: "/Users/alice/worktree token=raw-secret"})
	if err == nil {
		t.Fatal("validateWorkerIOTarget() error = nil, want missing runtime metadata error")
	}
	assertWorkerIOValidationSanitized(t, err.Error())

	if err := validateWorkerIOTarget(workerIOValidTarget()); err != nil {
		t.Fatalf("validateWorkerIOTarget() unexpected error: %v", err)
	}
}

func TestWorkerIOLimitValidationRejectsUnsafeLimits(t *testing.T) {
	tests := []struct {
		name       string
		validation workerIOLimitValidation
		want       string
	}{
		{
			name: "negative",
			validation: workerIOLimitValidation{
				Field:   "exec stdin limit",
				Value:   -1,
				Maximum: MaxExecStdinBytes,
			},
			want: "non-negative",
		},
		{
			name: "zero when required",
			validation: workerIOLimitValidation{
				Field:    "copy_in payload limit",
				Value:    0,
				Maximum:  MaxCopyInPayloadBytes,
				Required: true,
			},
			want: "required",
		},
		{
			name: "above maximum",
			validation: workerIOLimitValidation{
				Field:   "exec stdout capture limit",
				Value:   MaxExecStdoutCaptureBytes + 1,
				Maximum: MaxExecStdoutCaptureBytes,
			},
			want: "exceeds maximum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWorkerIOLimit(tt.validation)
			if err == nil {
				t.Fatal("validateWorkerIOLimit() error = nil, want validation error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateWorkerIOLimit() error = %q, want substring %q", err.Error(), tt.want)
			}
			assertWorkerIOValidationSanitized(t, err.Error())
		})
	}
}

func TestWorkerIOPayloadValidationRejectsUnboundedReads(t *testing.T) {
	tests := []struct {
		name       string
		validation workerIOPayloadValidation
		want       string
	}{
		{
			name: "negative size",
			validation: workerIOPayloadValidation{
				Field:        "exec stdin payload",
				SizeBytes:    -1,
				LimitBytes:   MaxExecStdinBytes,
				MaximumBytes: MaxExecStdinBytes,
			},
			want: "non-negative",
		},
		{
			name: "payload without explicit limit",
			validation: workerIOPayloadValidation{
				Field:        "exec stdin payload",
				SizeBytes:    1,
				LimitBytes:   0,
				MaximumBytes: MaxExecStdinBytes,
			},
			want: "required",
		},
		{
			name: "required payload without size",
			validation: workerIOPayloadValidation{
				Field:           "copy_in payload",
				SizeBytes:       0,
				LimitBytes:      MaxCopyInPayloadBytes,
				MaximumBytes:    MaxCopyInPayloadBytes,
				PayloadRequired: true,
			},
			want: "sizeBytes is required",
		},
		{
			name: "size above maximum",
			validation: workerIOPayloadValidation{
				Field:        "copy_out payload",
				SizeBytes:    MaxCopyOutPayloadBytes + 1,
				LimitBytes:   MaxCopyOutPayloadBytes,
				MaximumBytes: MaxCopyOutPayloadBytes,
			},
			want: "exceeds maximum",
		},
		{
			name: "size above caller limit",
			validation: workerIOPayloadValidation{
				Field:        "exec stderr payload",
				SizeBytes:    2,
				LimitBytes:   1,
				MaximumBytes: MaxExecStderrCaptureBytes,
			},
			want: "requested limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWorkerIOPayload(tt.validation)
			if err == nil {
				t.Fatal("validateWorkerIOPayload() error = nil, want validation error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateWorkerIOPayload() error = %q, want substring %q", err.Error(), tt.want)
			}
			assertWorkerIOValidationSanitized(t, err.Error())
		})
	}

	if err := validateWorkerIOPayload(workerIOPayloadValidation{
		Field:        "optional empty exec stdin payload",
		SizeBytes:    0,
		LimitBytes:   0,
		MaximumBytes: MaxExecStdinBytes,
	}); err != nil {
		t.Fatalf("validateWorkerIOPayload() optional empty payload error: %v", err)
	}
}

func TestWorkerIOValidationErrorsAreSanitized(t *testing.T) {
	err := validateWorkerIOPayload(workerIOPayloadValidation{
		Field:        "copy_in /Users/alice/worktree token=raw-secret password=hunter2 output",
		SizeBytes:    MaxCopyInPayloadBytes + 1,
		LimitBytes:   MaxCopyInPayloadBytes,
		MaximumBytes: MaxCopyInPayloadBytes,
	})
	if err == nil {
		t.Fatal("validateWorkerIOPayload() error = nil, want oversized payload error")
	}
	assertWorkerIOValidationSanitized(t, err.Error())
}

func workerIOValidTarget() Target {
	return Target{
		ID:   "sandbox-001",
		Name: "dev-sandbox",
		Runtime: RuntimeTarget{
			Driver:         RuntimeDriverRootlessPodman,
			RuntimeID:      "container-001",
			WorkerID:       "worker-001",
			IsolationLevel: IsolationLevelContainer,
		},
	}
}

func assertWorkerIOValidationSanitized(t *testing.T, detail string) {
	t.Helper()

	for _, unsafe := range []string{"raw-secret", "hunter2", "/Users/alice", "worktree"} {
		if strings.Contains(detail, unsafe) {
			t.Fatalf("validation detail leaked unsafe value %q in %q", unsafe, detail)
		}
	}
}
