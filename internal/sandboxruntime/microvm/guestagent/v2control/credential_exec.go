package v2control

import (
	"bytes"
	"errors"
	"path"
	"strings"
	"unicode/utf8"
)

const (
	MaxExecArguments                   = 128
	MaxExecArgumentBytes               = 8192
	MaxExecEnvironmentEntries          = 256
	MaxExecEnvironmentNameBytes        = 128
	MaxExecEnvironmentValueBytes       = 8192
	MaxExecWorkDirectoryBytes          = 4096
	MaxExecPlanBytes                   = 64 * 1024
	MaxExecPrivateBytes                = 64 * 1024
	MaxExecStreamBytes                 = 4 * 1024 * 1024
	MaxExecTimeoutMillis         int64 = 24 * 60 * 60 * 1000
	MinExecDeadlineMillis        int64 = 946684800000
	MaxExecDeadlineMillis        int64 = 4102444800000
	MaxExecHardLifetimeMillis          = int64(35 * 60 * 1000)

	emptySHA256Hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

var (
	ErrInvalidExecEnvironment                   = errors.New("guest agent v2 exec environment is invalid")
	ErrInvalidExecTiming                        = errors.New("guest agent v2 exec timing is invalid")
	ErrInvalidExecPlan                          = errors.New("guest agent v2 exec plan is invalid")
	ErrExecProxyCorrelationMismatch             = errors.New("guest agent v2 exec proxy correlation does not match")
	ErrInvalidCredentialExecCorrelation         = errors.New("guest agent v2 credential exec correlation is invalid")
	ErrInvalidCredentialExecRequest             = errors.New("guest agent v2 credential exec request is invalid")
	ErrInvalidCredentialExecRequestJSON         = errors.New("guest agent v2 credential exec request JSON is invalid")
	ErrCredentialExecCorrelationMismatch        = errors.New("guest agent v2 credential exec request correlation does not match")
	ErrInvalidCredentialExecSuccess             = errors.New("guest agent v2 credential exec success response is invalid")
	ErrInvalidCredentialExecSuccessJSON         = errors.New("guest agent v2 credential exec success response JSON is invalid")
	ErrCredentialExecSuccessCorrelationMismatch = errors.New("guest agent v2 credential exec success correlation does not match")
	ErrCredentialExecSerialization              = errors.New("guest agent v2 credential exec serialization is denied")
)

// ExecEnvironmentSource is the closed non-secret environment source catalog.
type ExecEnvironmentSource string

const (
	ExecEnvironmentLiteral   ExecEnvironmentSource = "literal"
	ExecEnvironmentInherited ExecEnvironmentSource = "inherited"
	ExecEnvironmentGenerated ExecEnvironmentSource = "generated"
)

// ExecTimingKind is the closed v1-compatible timing catalog.
type ExecTimingKind string

const (
	ExecTimingTimeoutMillis      ExecTimingKind = "timeout_millis"
	ExecTimingDeadlineUnixMillis ExecTimingKind = "deadline_unix_millis"
)

// ExecEnvironment is one opaque, non-secret plan environment entry.
type ExecEnvironment struct{ state execEnvironmentState }

type execEnvironmentState struct {
	name   string
	source ExecEnvironmentSource
	value  string
}

// ExecTiming is one opaque exact timing union member.
type ExecTiming struct{ state execTimingState }

type execTimingState struct {
	kind  ExecTimingKind
	value int64
}

// ExecPlan owns the complete bounded credential-aware command plan. It never
// contains stdin bytes or a credential value.
type ExecPlan struct{ state *execPlanState }

type execPlanState struct {
	args           []string
	environment    []ExecEnvironment
	workDirectory  string
	stdinMaxBytes  uint32
	stdoutMaxBytes uint32
	stderrMaxBytes uint32
	timing         ExecTiming
}

// CredentialExecCorrelation is the opaque caller-supplied prepared-state and
// hard-expiry authority used to validate one request without reading a clock.
// It stores no private payload bytes.
type CredentialExecCorrelation struct {
	state *credentialExecCorrelationState
}

type credentialExecCorrelationState struct {
	sessionIdentity             GuestCredentialSessionIdentity
	revision                    uint64
	execBindingID               string
	hasHTTPBinding              bool
	expectedProxyBaseURL        string
	privateRecordCount          uint32
	privateAggregateBytes       uint64
	privateAggregateSHA256      string
	validatedAtUnixMillis       int64
	jobHardExpiryUnixMillis     int64
	sessionHardExpiryUnixMillis int64
}

// CredentialExecRequest owns one canonical session-correlated exec request.
type CredentialExecRequest struct{ state *credentialExecRequestState }

type credentialExecRequestState struct {
	protocolVersion        string
	operation              Operation
	requestID              RequestID
	identityDigest         IdentityDigest
	identity               JobIdentity
	revision               uint64
	execBindingID          string
	plan                   ExecPlan
	privateRecordCount     uint32
	privateAggregateBytes  uint64
	privateAggregateSHA256 string
	correlation            CredentialExecCorrelation
}

// CredentialExecSuccessResponse owns one canonical success envelope bound to
// the originating request and its stream maxima.
type CredentialExecSuccessResponse struct{ state *credentialExecSuccessState }

type credentialExecSuccessState struct {
	protocolVersion       string
	operation             Operation
	requestID             RequestID
	identityDigest        IdentityDigest
	ok                    bool
	revision              uint64
	exitCode              int32
	stdinBytes            uint64
	stdinSHA256           string
	stdoutBytes           uint64
	stdoutSHA256          string
	stdoutTruncated       bool
	stderrBytes           uint64
	stderrSHA256          string
	stderrTruncated       bool
	execTransactionSHA256 string
	origin                CredentialExecRequest
}

// NewExecEnvironment constructs one exact non-secret environment entry.
func NewExecEnvironment(name string, source ExecEnvironmentSource, value string) (ExecEnvironment, error) {
	environment := ExecEnvironment{state: execEnvironmentState{name: name, source: source, value: value}}
	if ValidateExecEnvironment(environment) != nil {
		return ExecEnvironment{}, ErrInvalidExecEnvironment
	}
	return environment, nil
}

// ValidateExecEnvironment validates the entry catalog and fixed scalar bounds.
func ValidateExecEnvironment(environment ExecEnvironment) error {
	state := environment.state
	if !validExecEnvironmentSource(state.source) || !utf8.ValidString(state.value) ||
		len(state.value) > MaxExecEnvironmentValueBytes || strings.IndexByte(state.value, 0) >= 0 ||
		protectedExecEnvironment(state.name) {
		return ErrInvalidExecEnvironment
	}
	if proxyExecEnvironment(state.name) {
		if state.source != ExecEnvironmentGenerated {
			return ErrInvalidExecEnvironment
		}
		return nil
	}
	if !ordinaryExecEnvironmentName(state.name) {
		return ErrInvalidExecEnvironment
	}
	return nil
}

// NewExecTiming constructs one exact timing union member.
func NewExecTiming(kind ExecTimingKind, value int64) (ExecTiming, error) {
	timing := ExecTiming{state: execTimingState{kind: kind, value: value}}
	if ValidateExecTiming(timing) != nil {
		return ExecTiming{}, ErrInvalidExecTiming
	}
	return timing, nil
}

// ValidateExecTiming applies the frozen L4 bounds without reading a clock.
func ValidateExecTiming(timing ExecTiming) error {
	switch timing.state.kind {
	case ExecTimingTimeoutMillis:
		if timing.state.value < 1 || timing.state.value > MaxExecTimeoutMillis {
			return ErrInvalidExecTiming
		}
	case ExecTimingDeadlineUnixMillis:
		if timing.state.value < MinExecDeadlineMillis || timing.state.value > MaxExecDeadlineMillis {
			return ErrInvalidExecTiming
		}
	default:
		return ErrInvalidExecTiming
	}
	return nil
}

// NewExecPlan defensively owns and validates one complete plan.
func NewExecPlan(args []string, environment []ExecEnvironment, workDirectory string, stdinMaxBytes, stdoutMaxBytes, stderrMaxBytes uint32, timing ExecTiming) (ExecPlan, error) {
	plan := ExecPlan{state: &execPlanState{
		args: append([]string(nil), args...), environment: cloneExecEnvironment(environment),
		workDirectory: workDirectory, stdinMaxBytes: stdinMaxBytes,
		stdoutMaxBytes: stdoutMaxBytes, stderrMaxBytes: stderrMaxBytes, timing: timing,
	}}
	if ValidateExecPlan(plan) != nil {
		return ExecPlan{}, ErrInvalidExecPlan
	}
	return plan, nil
}

// ValidateExecPlan validates catalogs, uniqueness, quartet shape, v1 path and
// timing bounds, stream bounds, and the 64-KiB helper-plan aggregate.
func ValidateExecPlan(plan ExecPlan) error {
	if plan.state == nil || len(plan.state.args) < 1 || len(plan.state.args) > MaxExecArguments ||
		len(plan.state.environment) > MaxExecEnvironmentEntries || !canonicalExecWorkDirectory(plan.state.workDirectory) ||
		ValidateExecTiming(plan.state.timing) != nil {
		return ErrInvalidExecPlan
	}
	for index, argument := range plan.state.args {
		if len(argument) > MaxExecArgumentBytes || !utf8.ValidString(argument) || containsExecControl(argument) ||
			index == 0 && strings.TrimSpace(argument) == "" {
			return ErrInvalidExecPlan
		}
	}
	proxyCount := 0
	proxyValue := ""
	for index, entry := range plan.state.environment {
		if ValidateExecEnvironment(entry) != nil {
			return ErrInvalidExecPlan
		}
		for prior := 0; prior < index; prior++ {
			if plan.state.environment[prior].state.name == entry.state.name {
				return ErrInvalidExecPlan
			}
		}
		if proxyExecEnvironment(entry.state.name) {
			if proxyCount == 0 {
				proxyValue = entry.state.value
			} else if entry.state.value != proxyValue {
				return ErrInvalidExecPlan
			}
			proxyCount++
		}
	}
	if proxyCount != 0 && (proxyCount != 4 || proxyValue == "") {
		return ErrInvalidExecPlan
	}
	for _, maximum := range []uint32{plan.state.stdinMaxBytes, plan.state.stdoutMaxBytes, plan.state.stderrMaxBytes} {
		if maximum < 1 || maximum > MaxExecStreamBytes {
			return ErrInvalidExecPlan
		}
	}
	if execPlanBinaryLength(plan) > MaxExecPlanBytes {
		return ErrInvalidExecPlan
	}
	return nil
}

// ValidateExecPlanProxyBaseURL performs exact caller-owned correlation with an
// already-proved L7 proxy URL. It intentionally does not parse or derive it.
func ValidateExecPlanProxyBaseURL(plan ExecPlan, expectedProxyBaseURL string) error {
	if ValidateExecPlan(plan) != nil || expectedProxyBaseURL == "" || !utf8.ValidString(expectedProxyBaseURL) ||
		len(expectedProxyBaseURL) > MaxExecEnvironmentValueBytes || strings.IndexByte(expectedProxyBaseURL, 0) >= 0 {
		return ErrExecProxyCorrelationMismatch
	}
	count := 0
	for _, entry := range plan.state.environment {
		if proxyExecEnvironment(entry.state.name) {
			if entry.state.source != ExecEnvironmentGenerated || entry.state.value != expectedProxyBaseURL {
				return ErrExecProxyCorrelationMismatch
			}
			count++
		}
	}
	if count != 4 {
		return ErrExecProxyCorrelationMismatch
	}
	return nil
}

// NewCredentialExecCorrelation constructs the explicit prepared-manifest,
// authenticated-session, private-record, proxy, and hard-expiry authority.
func NewCredentialExecCorrelation(sessionIdentity GuestCredentialSessionIdentity, revision uint64, execBindingID string, hasHTTPBinding bool, expectedProxyBaseURL string, privateRecordCount uint32, privateAggregateBytes uint64, privateAggregateSHA256 string, validatedAtUnixMillis, jobHardExpiryUnixMillis, sessionHardExpiryUnixMillis int64) (CredentialExecCorrelation, error) {
	correlation := CredentialExecCorrelation{state: &credentialExecCorrelationState{
		sessionIdentity: cloneGuestCredentialSessionIdentity(sessionIdentity), revision: revision,
		execBindingID: execBindingID, hasHTTPBinding: hasHTTPBinding,
		expectedProxyBaseURL: expectedProxyBaseURL, privateRecordCount: privateRecordCount,
		privateAggregateBytes: privateAggregateBytes, privateAggregateSHA256: privateAggregateSHA256,
		validatedAtUnixMillis: validatedAtUnixMillis, jobHardExpiryUnixMillis: jobHardExpiryUnixMillis,
		sessionHardExpiryUnixMillis: sessionHardExpiryUnixMillis,
	}}
	if validateCredentialExecCorrelation(correlation) != nil {
		return CredentialExecCorrelation{}, ErrInvalidCredentialExecCorrelation
	}
	return correlation, nil
}

// NewCredentialExecRequest derives body identity and envelope digest from the
// authenticated GuestCredentialSessionIdentity in correlation.
func NewCredentialExecRequest(requestID RequestID, correlation CredentialExecCorrelation, plan ExecPlan) (CredentialExecRequest, error) {
	if validateCredentialExecCorrelation(correlation) != nil {
		return CredentialExecRequest{}, ErrInvalidCredentialExecRequest
	}
	digest, err := GuestCredentialSessionIdentityDigest(correlation.state.sessionIdentity)
	if err != nil {
		return CredentialExecRequest{}, ErrInvalidCredentialExecRequest
	}
	request := CredentialExecRequest{state: &credentialExecRequestState{
		protocolVersion: ProtocolVersion, operation: OperationExec, requestID: requestID,
		identityDigest: NewIdentityDigest(digest), identity: correlation.state.sessionIdentity.JobIdentity(),
		revision: correlation.state.revision, execBindingID: correlation.state.execBindingID,
		plan: cloneExecPlan(plan), privateRecordCount: correlation.state.privateRecordCount,
		privateAggregateBytes:  correlation.state.privateAggregateBytes,
		privateAggregateSHA256: correlation.state.privateAggregateSHA256,
		correlation:            cloneCredentialExecCorrelation(correlation),
	}}
	if ValidateCredentialExecRequest(request) != nil {
		return CredentialExecRequest{}, ErrInvalidCredentialExecRequest
	}
	return request, nil
}

// ValidateCredentialExecRequest validates both wire state and its retained
// explicit prepared-state authority.
func ValidateCredentialExecRequest(request CredentialExecRequest) error {
	if validateCredentialExecRequestBase(request) != nil ||
		ValidateCredentialExecRequestForCorrelation(request, request.state.correlation) != nil {
		return ErrInvalidCredentialExecRequest
	}
	return nil
}

// ValidateCredentialExecRequestForCorrelation performs exact prepared-state,
// proxy, private digest, session identity, revision, binding, and expiry checks.
func ValidateCredentialExecRequestForCorrelation(request CredentialExecRequest, correlation CredentialExecCorrelation) error {
	if validateCredentialExecRequestBase(request) != nil || validateCredentialExecCorrelation(correlation) != nil {
		return ErrCredentialExecCorrelationMismatch
	}
	digest, err := GuestCredentialSessionIdentityDigest(correlation.state.sessionIdentity)
	if err != nil || request.state.identityDigest != NewIdentityDigest(digest) ||
		!sameExecJobIdentity(request.state.identity, correlation.state.sessionIdentity.JobIdentity()) ||
		request.state.revision != correlation.state.revision || request.state.execBindingID != correlation.state.execBindingID ||
		request.state.privateRecordCount != correlation.state.privateRecordCount ||
		request.state.privateAggregateBytes != correlation.state.privateAggregateBytes ||
		request.state.privateAggregateSHA256 != correlation.state.privateAggregateSHA256 ||
		!validExecTimingCorrelation(request.state.plan.state.timing, correlation.state) {
		return ErrCredentialExecCorrelationMismatch
	}
	if correlation.state.hasHTTPBinding {
		if ValidateExecPlanProxyBaseURL(request.state.plan, correlation.state.expectedProxyBaseURL) != nil {
			return ErrCredentialExecCorrelationMismatch
		}
		return nil
	}
	for _, entry := range request.state.plan.state.environment {
		if proxyExecEnvironment(entry.state.name) {
			return ErrCredentialExecCorrelationMismatch
		}
	}
	return nil
}

// NewCredentialExecSuccessResponse constructs a bounded success bound to the
// exact originating request.
func NewCredentialExecSuccessResponse(request CredentialExecRequest, exitCode int32, stdinBytes uint64, stdinSHA256 string, stdoutBytes uint64, stdoutSHA256 string, stdoutTruncated bool, stderrBytes uint64, stderrSHA256 string, stderrTruncated bool, execTransactionSHA256 string) (CredentialExecSuccessResponse, error) {
	if ValidateCredentialExecRequest(request) != nil {
		return CredentialExecSuccessResponse{}, ErrInvalidCredentialExecSuccess
	}
	response := CredentialExecSuccessResponse{state: &credentialExecSuccessState{
		protocolVersion: request.state.protocolVersion, operation: request.state.operation,
		requestID: request.state.requestID, identityDigest: request.state.identityDigest, ok: true,
		revision: request.state.revision, exitCode: exitCode,
		stdinBytes: stdinBytes, stdinSHA256: stdinSHA256,
		stdoutBytes: stdoutBytes, stdoutSHA256: stdoutSHA256, stdoutTruncated: stdoutTruncated,
		stderrBytes: stderrBytes, stderrSHA256: stderrSHA256, stderrTruncated: stderrTruncated,
		execTransactionSHA256: execTransactionSHA256, origin: cloneCredentialExecRequest(request),
	}}
	if ValidateCredentialExecSuccessResponse(response) != nil {
		return CredentialExecSuccessResponse{}, ErrInvalidCredentialExecSuccess
	}
	return response, nil
}

// ValidateCredentialExecSuccessResponse validates the result and retained
// originating request, including stream bounds and truncation consistency.
func ValidateCredentialExecSuccessResponse(response CredentialExecSuccessResponse) error {
	if response.state == nil || ValidateCredentialExecRequest(response.state.origin) != nil ||
		validateCredentialExecSuccessBase(response) != nil ||
		!credentialExecSuccessCorrelates(response, response.state.origin) ||
		!validCredentialExecSuccessStreams(response.state, response.state.origin.state.plan) {
		return ErrInvalidCredentialExecSuccess
	}
	return nil
}

func validateCredentialExecRequestBase(request CredentialExecRequest) error {
	if request.state == nil || request.state.protocolVersion != ProtocolVersion || request.state.operation != OperationExec ||
		request.state.revision == 0 || !validExecSafeToken(request.state.execBindingID) ||
		ValidateJobIdentity(request.state.identity) != nil || ValidateExecPlan(request.state.plan) != nil {
		return ErrInvalidCredentialExecRequest
	}
	if _, err := EncodeRequestID(request.state.requestID); err != nil {
		return ErrInvalidCredentialExecRequest
	}
	if !validExecPrivateShape(request.state.privateRecordCount, request.state.privateAggregateBytes, request.state.privateAggregateSHA256) {
		return ErrInvalidCredentialExecRequest
	}
	return nil
}

func validateCredentialExecCorrelation(correlation CredentialExecCorrelation) error {
	if correlation.state == nil || ValidateGuestCredentialSessionIdentity(correlation.state.sessionIdentity) != nil ||
		correlation.state.revision == 0 || !validExecSafeToken(correlation.state.execBindingID) ||
		!validExecPrivateShape(correlation.state.privateRecordCount, correlation.state.privateAggregateBytes, correlation.state.privateAggregateSHA256) ||
		correlation.state.validatedAtUnixMillis < MinExecDeadlineMillis ||
		correlation.state.validatedAtUnixMillis > MaxExecDeadlineMillis {
		return ErrInvalidCredentialExecCorrelation
	}
	httpCount := 0
	for _, binding := range correlation.state.sessionIdentity.JobIdentity().Bindings {
		if binding.Mode == DeliveryMode("http_proxy") {
			httpCount++
		}
	}
	if correlation.state.hasHTTPBinding != (httpCount == 1) || httpCount > 1 ||
		!validExecHardExpiry(correlation.state.validatedAtUnixMillis, correlation.state.jobHardExpiryUnixMillis) ||
		!validExecHardExpiry(correlation.state.validatedAtUnixMillis, correlation.state.sessionHardExpiryUnixMillis) {
		return ErrInvalidCredentialExecCorrelation
	}
	if correlation.state.hasHTTPBinding {
		if correlation.state.expectedProxyBaseURL == "" || !utf8.ValidString(correlation.state.expectedProxyBaseURL) ||
			len(correlation.state.expectedProxyBaseURL) > MaxExecEnvironmentValueBytes ||
			strings.IndexByte(correlation.state.expectedProxyBaseURL, 0) >= 0 ||
			correlation.state.privateRecordCount != 1 || correlation.state.privateAggregateBytes < 1 ||
			correlation.state.privateAggregateBytes > MaxExecPrivateBytes ||
			correlation.state.privateAggregateSHA256 == emptySHA256Hex {
			return ErrInvalidCredentialExecCorrelation
		}
		return nil
	}
	if correlation.state.expectedProxyBaseURL != "" || correlation.state.privateRecordCount != 0 ||
		correlation.state.privateAggregateBytes != 0 || correlation.state.privateAggregateSHA256 != emptySHA256Hex {
		return ErrInvalidCredentialExecCorrelation
	}
	return nil
}

func validateCredentialExecSuccessBase(response CredentialExecSuccessResponse) error {
	if response.state == nil || response.state.protocolVersion != ProtocolVersion || response.state.operation != OperationExec ||
		!response.state.ok || response.state.revision == 0 || response.state.exitCode < 0 ||
		!validLowerExecSHA256(response.state.stdinSHA256) || !validLowerExecSHA256(response.state.stdoutSHA256) ||
		!validLowerExecSHA256(response.state.stderrSHA256) || !validLowerExecSHA256(response.state.execTransactionSHA256) {
		return ErrInvalidCredentialExecSuccess
	}
	if _, err := EncodeRequestID(response.state.requestID); err != nil {
		return ErrInvalidCredentialExecSuccess
	}
	return nil
}

func credentialExecSuccessCorrelates(response CredentialExecSuccessResponse, request CredentialExecRequest) bool {
	return response.state.requestID == request.state.requestID && response.state.identityDigest == request.state.identityDigest &&
		response.state.revision == request.state.revision
}

func validCredentialExecSuccessStreams(state *credentialExecSuccessState, plan ExecPlan) bool {
	if plan.state == nil || state.stdinBytes > uint64(plan.state.stdinMaxBytes) ||
		state.stdoutBytes > uint64(plan.state.stdoutMaxBytes) || state.stderrBytes > uint64(plan.state.stderrMaxBytes) ||
		state.stdoutTruncated && state.stdoutBytes != uint64(plan.state.stdoutMaxBytes) ||
		state.stderrTruncated && state.stderrBytes != uint64(plan.state.stderrMaxBytes) {
		return false
	}
	return validExecCountDigest(state.stdinBytes, state.stdinSHA256) &&
		validExecCountDigest(state.stdoutBytes, state.stdoutSHA256) && validExecCountDigest(state.stderrBytes, state.stderrSHA256)
}

func validExecCountDigest(count uint64, digest string) bool {
	if !validLowerExecSHA256(digest) {
		return false
	}
	if count == 0 {
		return digest == emptySHA256Hex
	}
	return digest != emptySHA256Hex
}

func validExecPrivateShape(count uint32, size uint64, digest string) bool {
	if !validLowerExecSHA256(digest) {
		return false
	}
	if count == 0 {
		return size == 0 && digest == emptySHA256Hex
	}
	return count == 1 && size >= 1 && size <= MaxExecPrivateBytes && digest != emptySHA256Hex
}

func validExecTimingCorrelation(timing ExecTiming, correlation *credentialExecCorrelationState) bool {
	if correlation == nil || ValidateExecTiming(timing) != nil {
		return false
	}
	hardExpiry := correlation.jobHardExpiryUnixMillis
	if correlation.sessionHardExpiryUnixMillis < hardExpiry {
		hardExpiry = correlation.sessionHardExpiryUnixMillis
	}
	switch timing.state.kind {
	case ExecTimingTimeoutMillis:
		return timing.state.value <= hardExpiry-correlation.validatedAtUnixMillis
	case ExecTimingDeadlineUnixMillis:
		return timing.state.value > correlation.validatedAtUnixMillis && timing.state.value <= hardExpiry
	default:
		return false
	}
}

func validExecHardExpiry(now, expiry int64) bool {
	return expiry > now && expiry >= MinExecDeadlineMillis && expiry <= MaxExecDeadlineMillis &&
		expiry-now <= MaxExecHardLifetimeMillis
}

func validExecEnvironmentSource(source ExecEnvironmentSource) bool {
	return source == ExecEnvironmentLiteral || source == ExecEnvironmentInherited || source == ExecEnvironmentGenerated
}

func ordinaryExecEnvironmentName(name string) bool {
	if len(name) < 1 || len(name) > MaxExecEnvironmentNameBytes ||
		!((name[0] >= 'A' && name[0] <= 'Z') || name[0] == '_') {
		return false
	}
	for index := 1; index < len(name); index++ {
		character := name[index]
		if !((character >= 'A' && character <= 'Z') || character == '_' || (character >= '0' && character <= '9')) {
			return false
		}
	}
	return true
}

func protectedExecEnvironment(name string) bool {
	return name == "AZURE_OPENAI_BASE_URL" || name == "AZURE_OPENAI_API_KEY" || name == "AZURE_OPENAI_API_VERSION"
}

func proxyExecEnvironment(name string) bool {
	return name == "HTTP_PROXY" || name == "HTTPS_PROXY" || name == "http_proxy" || name == "https_proxy"
}

func canonicalExecWorkDirectory(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > MaxExecWorkDirectoryBytes ||
		!utf8.ValidString(value) || containsExecControl(value) || !strings.HasPrefix(value, "/") ||
		strings.Contains(value, "\\") || strings.Contains(value, "://") || strings.Contains(value, "//") ||
		path.Clean(value) != value {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return false
		}
	}
	return true
}

func containsExecControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func validExecSafeToken(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !execSafeTokenByte(character) {
			return false
		}
	}
	return true
}

func execSafeTokenByte(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-'
}

func validLowerExecSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for index := range value {
		if value[index] < '0' || value[index] > '9' {
			if value[index] < 'a' || value[index] > 'f' {
				return false
			}
		}
	}
	return true
}

func execPlanBinaryLength(plan ExecPlan) int {
	length := 2 + 2 + 3 + 12 + 1 + 8
	for _, argument := range plan.state.args {
		length += 2 + len(argument)
	}
	for _, entry := range plan.state.environment {
		length += 2 + len(entry.state.name) + 1 + 2 + len(entry.state.value)
	}
	length += 2 + len(plan.state.workDirectory)
	return length
}

func sameExecJobIdentity(left, right JobIdentity) bool {
	leftWire, leftErr := MarshalJobIdentity(left)
	rightWire, rightErr := MarshalJobIdentity(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftWire, rightWire)
}

func cloneGuestCredentialSessionIdentity(identity GuestCredentialSessionIdentity) GuestCredentialSessionIdentity {
	if identity.state == nil {
		return GuestCredentialSessionIdentity{}
	}
	return GuestCredentialSessionIdentity{state: &guestCredentialSessionIdentityState{
		sessionID: identity.state.sessionID, jobIdentity: cloneJobIdentity(identity.state.jobIdentity),
	}}
}

func cloneExecEnvironment(environment []ExecEnvironment) []ExecEnvironment {
	return append([]ExecEnvironment(nil), environment...)
}

func cloneExecPlan(plan ExecPlan) ExecPlan {
	if plan.state == nil {
		return ExecPlan{}
	}
	state := *plan.state
	state.args = append([]string(nil), plan.state.args...)
	state.environment = cloneExecEnvironment(plan.state.environment)
	return ExecPlan{state: &state}
}

func cloneCredentialExecCorrelation(correlation CredentialExecCorrelation) CredentialExecCorrelation {
	if correlation.state == nil {
		return CredentialExecCorrelation{}
	}
	state := *correlation.state
	state.sessionIdentity = cloneGuestCredentialSessionIdentity(correlation.state.sessionIdentity)
	return CredentialExecCorrelation{state: &state}
}

func cloneCredentialExecRequest(request CredentialExecRequest) CredentialExecRequest {
	if request.state == nil {
		return CredentialExecRequest{}
	}
	state := *request.state
	state.identity = cloneJobIdentity(request.state.identity)
	state.plan = cloneExecPlan(request.state.plan)
	state.correlation = cloneCredentialExecCorrelation(request.state.correlation)
	return CredentialExecRequest{state: &state}
}
