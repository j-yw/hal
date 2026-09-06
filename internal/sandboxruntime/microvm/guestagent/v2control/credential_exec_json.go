package v2control

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

const (
	maxCredentialExecJSONBytes        = 2 * 1024 * 1024
	maxCredentialExecJSONDepth        = 6
	maxCredentialExecJSONTokens       = 4096
	maxCredentialExecJSONObjectFields = 64
	maxCredentialExecJSONStringBytes  = MaxExecEnvironmentValueBytes
)

type credentialExecRequestJSON struct {
	ProtocolVersion string                    `json:"protocolVersion"`
	Operation       string                    `json:"operation"`
	RequestID       string                    `json:"requestId"`
	IdentityDigest  string                    `json:"identityDigest"`
	Body            credentialExecRequestBody `json:"body"`
}

type credentialExecRequestBody struct {
	Identity               JobIdentity  `json:"identity"`
	Revision               uint64       `json:"revision"`
	ExecBindingID          string       `json:"execBindingId"`
	Plan                   execPlanJSON `json:"plan"`
	PrivateRecordCount     uint32       `json:"privateRecordCount"`
	PrivateAggregateBytes  uint64       `json:"privateAggregateBytes"`
	PrivateAggregateSHA256 string       `json:"privateAggregateSha256"`
}

type execPlanJSON struct {
	Args           []string              `json:"args"`
	Environment    []execEnvironmentJSON `json:"env"`
	WorkDirectory  string                `json:"workDir"`
	StdinMaxBytes  uint32                `json:"stdinMaxBytes"`
	StdoutMaxBytes uint32                `json:"stdoutMaxBytes"`
	StderrMaxBytes uint32                `json:"stderrMaxBytes"`
	Timing         execTimingJSON        `json:"timing"`
}

type execEnvironmentJSON struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Value  string `json:"value"`
}

type execTimingJSON struct {
	Kind  string `json:"kind"`
	Value int64  `json:"value"`
}

type credentialExecSuccessJSON struct {
	ProtocolVersion string                    `json:"protocolVersion"`
	Operation       string                    `json:"operation"`
	RequestID       string                    `json:"requestId"`
	IdentityDigest  string                    `json:"identityDigest"`
	OK              bool                      `json:"ok"`
	Body            credentialExecSuccessBody `json:"body"`
}

type credentialExecSuccessBody struct {
	Revision              uint64 `json:"revision"`
	ExitCode              int32  `json:"exitCode"`
	StdinBytes            uint64 `json:"stdinBytes"`
	StdinSHA256           string `json:"stdinSha256"`
	StdoutBytes           uint64 `json:"stdoutBytes"`
	StdoutSHA256          string `json:"stdoutSha256"`
	StdoutTruncated       bool   `json:"stdoutTruncated"`
	StderrBytes           uint64 `json:"stderrBytes"`
	StderrSHA256          string `json:"stderrSha256"`
	StderrTruncated       bool   `json:"stderrTruncated"`
	ExecTransactionSHA256 string `json:"execTransactionSha256"`
}

// EncodeCredentialExecRequest returns the sole canonical compact encoding.
func EncodeCredentialExecRequest(request CredentialExecRequest) ([]byte, error) {
	if ValidateCredentialExecRequest(request) != nil {
		return nil, ErrInvalidCredentialExecRequest
	}
	return encodeCredentialExecRequestState(request)
}

func encodeCredentialExecRequestState(request CredentialExecRequest) ([]byte, error) {
	if validateCredentialExecRequestBase(request) != nil {
		return nil, ErrInvalidCredentialExecRequest
	}
	requestID, err := EncodeRequestID(request.state.requestID)
	if err != nil {
		return nil, ErrInvalidCredentialExecRequest
	}
	wire, err := json.Marshal(credentialExecRequestJSON{
		ProtocolVersion: request.state.protocolVersion, Operation: string(request.state.operation),
		RequestID: requestID, IdentityDigest: EncodeIdentityDigest(request.state.identityDigest),
		Body: credentialExecRequestBody{
			Identity: cloneJobIdentity(request.state.identity), Revision: request.state.revision,
			ExecBindingID: request.state.execBindingID, Plan: execPlanToJSON(request.state.plan),
			PrivateRecordCount:     request.state.privateRecordCount,
			PrivateAggregateBytes:  request.state.privateAggregateBytes,
			PrivateAggregateSHA256: request.state.privateAggregateSHA256,
		},
	})
	if err != nil {
		return nil, ErrInvalidCredentialExecRequest
	}
	return wire, nil
}

// DecodeCredentialExecRequest accepts only canonical JSON and requires the
// explicit authenticated prepared-state correlation before returning a value.
func DecodeCredentialExecRequest(correlation CredentialExecCorrelation, wire []byte) (CredentialExecRequest, error) {
	if validateCredentialExecCorrelation(correlation) != nil || !validCredentialExecJSONInput(wire) {
		return CredentialExecRequest{}, ErrInvalidCredentialExecRequestJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var decoded credentialExecRequestJSON
	if err := decoder.Decode(&decoded); err != nil || requireCredentialExecJSONEOF(decoder) != nil ||
		decoded.Body.Plan.Args == nil || decoded.Body.Plan.Environment == nil {
		return CredentialExecRequest{}, ErrInvalidCredentialExecRequestJSON
	}
	requestID, err := ParseRequestID(decoded.RequestID)
	if err != nil {
		return CredentialExecRequest{}, ErrInvalidCredentialExecRequestJSON
	}
	identityDigest, err := ParseIdentityDigest(decoded.IdentityDigest)
	if err != nil {
		return CredentialExecRequest{}, ErrInvalidCredentialExecRequestJSON
	}
	plan, err := execPlanFromJSON(decoded.Body.Plan)
	if err != nil {
		return CredentialExecRequest{}, ErrInvalidCredentialExecRequestJSON
	}
	request := CredentialExecRequest{state: &credentialExecRequestState{
		protocolVersion: decoded.ProtocolVersion, operation: Operation(decoded.Operation), requestID: requestID,
		identityDigest: identityDigest, identity: cloneJobIdentity(decoded.Body.Identity), revision: decoded.Body.Revision,
		execBindingID: decoded.Body.ExecBindingID, plan: plan,
		privateRecordCount: decoded.Body.PrivateRecordCount, privateAggregateBytes: decoded.Body.PrivateAggregateBytes,
		privateAggregateSHA256: decoded.Body.PrivateAggregateSHA256,
		correlation:            cloneCredentialExecCorrelation(correlation),
	}}
	if validateCredentialExecRequestBase(request) != nil {
		return CredentialExecRequest{}, ErrInvalidCredentialExecRequestJSON
	}
	canonical, err := encodeCredentialExecRequestState(request)
	if err != nil || !bytes.Equal(canonical, wire) {
		return CredentialExecRequest{}, ErrInvalidCredentialExecRequestJSON
	}
	if ValidateCredentialExecRequestForCorrelation(request, correlation) != nil {
		return CredentialExecRequest{}, ErrCredentialExecCorrelationMismatch
	}
	return request, nil
}

// EncodeCredentialExecSuccessResponse returns the sole canonical compact
// success encoding.
func EncodeCredentialExecSuccessResponse(response CredentialExecSuccessResponse) ([]byte, error) {
	if ValidateCredentialExecSuccessResponse(response) != nil {
		return nil, ErrInvalidCredentialExecSuccess
	}
	return encodeCredentialExecSuccessState(response)
}

func encodeCredentialExecSuccessState(response CredentialExecSuccessResponse) ([]byte, error) {
	if validateCredentialExecSuccessBase(response) != nil {
		return nil, ErrInvalidCredentialExecSuccess
	}
	requestID, err := EncodeRequestID(response.state.requestID)
	if err != nil {
		return nil, ErrInvalidCredentialExecSuccess
	}
	wire, err := json.Marshal(credentialExecSuccessJSON{
		ProtocolVersion: response.state.protocolVersion, Operation: string(response.state.operation),
		RequestID: requestID, IdentityDigest: EncodeIdentityDigest(response.state.identityDigest), OK: response.state.ok,
		Body: credentialExecSuccessBody{
			Revision: response.state.revision, ExitCode: response.state.exitCode,
			StdinBytes: response.state.stdinBytes, StdinSHA256: response.state.stdinSHA256,
			StdoutBytes: response.state.stdoutBytes, StdoutSHA256: response.state.stdoutSHA256,
			StdoutTruncated: response.state.stdoutTruncated,
			StderrBytes:     response.state.stderrBytes, StderrSHA256: response.state.stderrSHA256,
			StderrTruncated:       response.state.stderrTruncated,
			ExecTransactionSHA256: response.state.execTransactionSHA256,
		},
	})
	if err != nil {
		return nil, ErrInvalidCredentialExecSuccess
	}
	return wire, nil
}

// DecodeCredentialExecSuccessResponse requires the exact originating request;
// no standalone success decoding surface exists.
func DecodeCredentialExecSuccessResponse(request CredentialExecRequest, wire []byte) (CredentialExecSuccessResponse, error) {
	if ValidateCredentialExecRequest(request) != nil || !validCredentialExecJSONInput(wire) {
		return CredentialExecSuccessResponse{}, ErrInvalidCredentialExecSuccessJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var decoded credentialExecSuccessJSON
	if err := decoder.Decode(&decoded); err != nil || requireCredentialExecJSONEOF(decoder) != nil {
		return CredentialExecSuccessResponse{}, ErrInvalidCredentialExecSuccessJSON
	}
	requestID, err := ParseRequestID(decoded.RequestID)
	if err != nil {
		return CredentialExecSuccessResponse{}, ErrInvalidCredentialExecSuccessJSON
	}
	identityDigest, err := ParseIdentityDigest(decoded.IdentityDigest)
	if err != nil {
		return CredentialExecSuccessResponse{}, ErrInvalidCredentialExecSuccessJSON
	}
	response := CredentialExecSuccessResponse{state: &credentialExecSuccessState{
		protocolVersion: decoded.ProtocolVersion, operation: Operation(decoded.Operation),
		requestID: requestID, identityDigest: identityDigest, ok: decoded.OK,
		revision: decoded.Body.Revision, exitCode: decoded.Body.ExitCode,
		stdinBytes: decoded.Body.StdinBytes, stdinSHA256: decoded.Body.StdinSHA256,
		stdoutBytes: decoded.Body.StdoutBytes, stdoutSHA256: decoded.Body.StdoutSHA256,
		stdoutTruncated: decoded.Body.StdoutTruncated,
		stderrBytes:     decoded.Body.StderrBytes, stderrSHA256: decoded.Body.StderrSHA256,
		stderrTruncated:       decoded.Body.StderrTruncated,
		execTransactionSHA256: decoded.Body.ExecTransactionSHA256,
		origin:                cloneCredentialExecRequest(request),
	}}
	if validateCredentialExecSuccessBase(response) != nil ||
		!validCredentialExecSuccessStreams(response.state, request.state.plan) {
		return CredentialExecSuccessResponse{}, ErrInvalidCredentialExecSuccessJSON
	}
	canonical, err := encodeCredentialExecSuccessState(response)
	if err != nil || !bytes.Equal(canonical, wire) {
		return CredentialExecSuccessResponse{}, ErrInvalidCredentialExecSuccessJSON
	}
	if !credentialExecSuccessCorrelates(response, request) {
		return CredentialExecSuccessResponse{}, ErrCredentialExecSuccessCorrelationMismatch
	}
	return response, nil
}

func execPlanToJSON(plan ExecPlan) execPlanJSON {
	environment := make([]execEnvironmentJSON, len(plan.state.environment))
	for index, entry := range plan.state.environment {
		environment[index] = execEnvironmentJSON{Name: entry.state.name, Source: string(entry.state.source), Value: entry.state.value}
	}
	return execPlanJSON{
		Args: append([]string(nil), plan.state.args...), Environment: environment,
		WorkDirectory: plan.state.workDirectory, StdinMaxBytes: plan.state.stdinMaxBytes,
		StdoutMaxBytes: plan.state.stdoutMaxBytes, StderrMaxBytes: plan.state.stderrMaxBytes,
		Timing: execTimingJSON{Kind: string(plan.state.timing.state.kind), Value: plan.state.timing.state.value},
	}
}

func execPlanFromJSON(decoded execPlanJSON) (ExecPlan, error) {
	environment := make([]ExecEnvironment, len(decoded.Environment))
	for index, entry := range decoded.Environment {
		value, err := NewExecEnvironment(entry.Name, ExecEnvironmentSource(entry.Source), entry.Value)
		if err != nil {
			return ExecPlan{}, err
		}
		environment[index] = value
	}
	timing, err := NewExecTiming(ExecTimingKind(decoded.Timing.Kind), decoded.Timing.Value)
	if err != nil {
		return ExecPlan{}, err
	}
	return NewExecPlan(decoded.Args, environment, decoded.WorkDirectory,
		decoded.StdinMaxBytes, decoded.StdoutMaxBytes, decoded.StderrMaxBytes, timing)
}

func validCredentialExecJSONInput(wire []byte) bool {
	if len(wire) == 0 || len(wire) > maxCredentialExecJSONBytes || !utf8.Valid(wire) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.UseNumber()
	tokens := 0
	if !scanCredentialExecJSONValue(decoder, 0, &tokens) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func scanCredentialExecJSONValue(decoder *json.Decoder, depth int, tokens *int) bool {
	token, err := decoder.Token()
	*tokens++
	if err != nil || *tokens > maxCredentialExecJSONTokens {
		return false
	}
	if value, ok := token.(string); ok && len(value) > maxCredentialExecJSONStringBytes {
		return false
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return true
	}
	nestedDepth := depth + 1
	if nestedDepth > maxCredentialExecJSONDepth {
		return false
	}
	switch delimiter {
	case '{':
		var keys [maxCredentialExecJSONObjectFields]string
		keyCount := 0
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			*tokens++
			key, isString := keyToken.(string)
			if keyErr != nil || !isString || len(key) > maxCredentialExecJSONStringBytes ||
				*tokens > maxCredentialExecJSONTokens || keyCount == len(keys) {
				return false
			}
			for index := 0; index < keyCount; index++ {
				if keys[index] == key {
					return false
				}
			}
			keys[keyCount] = key
			keyCount++
			if !scanCredentialExecJSONValue(decoder, nestedDepth, tokens) {
				return false
			}
		}
		closing, closeErr := decoder.Token()
		*tokens++
		return closeErr == nil && closing == json.Delim('}') && *tokens <= maxCredentialExecJSONTokens
	case '[':
		for decoder.More() {
			if !scanCredentialExecJSONValue(decoder, nestedDepth, tokens) {
				return false
			}
		}
		closing, closeErr := decoder.Token()
		*tokens++
		return closeErr == nil && closing == json.Delim(']') && *tokens <= maxCredentialExecJSONTokens
	default:
		return false
	}
}

func requireCredentialExecJSONEOF(decoder *json.Decoder) error {
	var trailing struct{}
	if err := decoder.Decode(&trailing); err == io.EOF {
		return nil
	}
	return ErrInvalidCredentialExecRequestJSON
}
