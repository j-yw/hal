package credentialprotocol

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"runtime"
	"strings"
	"unicode/utf8"
)

const (
	MaxHelperExecArguments                   = 128
	MaxHelperExecArgumentBytes               = 8192
	MaxHelperExecEnvironmentEntries          = 256
	MaxHelperExecEnvironmentNameBytes        = 128
	MaxHelperExecEnvironmentValueBytes       = 8192
	MaxHelperExecWorkDirectoryBytes          = 4096
	MaxHelperExecPlanBytes                   = 64 * 1024
	MaxHelperExecPrivateBytes                = 64 * 1024
	MaxHelperExecStreamPayloadBytes          = 64 * 1024
	MaxHelperExecStreamAggregateBytes        = 4 * 1024 * 1024
	MaxHelperExecTimeoutMillis         int64 = 24 * 60 * 60 * 1000
	MinHelperExecDeadlineUnixMillis    int64 = 946684800000
	MaxHelperExecDeadlineUnixMillis    int64 = 4102444800000

	helperExecPrivateFixedBytes = 44
	helperExecStreamFixedBytes  = 56
	HelperExecCreditBodyBytes   = 24
)

var (
	ErrHelperExecRevision                 = errors.New("credential protocol helper exec revision is invalid")
	ErrHelperExecArgumentCount            = errors.New("credential protocol helper exec argument count is invalid")
	ErrHelperExecArgument                 = errors.New("credential protocol helper exec argument is invalid")
	ErrHelperExecEnvironmentCount         = errors.New("credential protocol helper exec environment count is invalid")
	ErrHelperExecEnvironmentName          = errors.New("credential protocol helper exec environment name is invalid")
	ErrHelperExecEnvironmentProtected     = errors.New("credential protocol helper exec protected environment name is forbidden")
	ErrHelperExecEnvironmentValue         = errors.New("credential protocol helper exec environment value is invalid")
	ErrHelperExecProxyEnvironment         = errors.New("credential protocol helper exec proxy environment is invalid")
	ErrHelperExecPreparedManifest         = errors.New("credential protocol helper exec prepared manifest correlation is invalid")
	ErrUnknownHelperExecEnvironmentSource = errors.New("credential protocol helper exec environment source is unknown")
	ErrHelperExecWorkDirectory            = errors.New("credential protocol helper exec work directory is invalid")
	ErrUnknownHelperExecStreamMode        = errors.New("credential protocol helper exec stream mode is unknown")
	ErrHelperExecStreamMaximum            = errors.New("credential protocol helper exec stream maximum is invalid")
	ErrUnknownHelperExecTimingKind        = errors.New("credential protocol helper exec timing kind is unknown")
	ErrHelperExecTimingValue              = errors.New("credential protocol helper exec timing value is invalid")
	ErrHelperExecPlanLength               = errors.New("credential protocol helper exec plan length is invalid")
	ErrHelperExecPlanTrailingData         = errors.New("credential protocol helper exec plan has trailing data")
	ErrHelperExecBodyLength               = errors.New("credential protocol helper exec body length is invalid")
	ErrHelperExecBodyTrailingData         = errors.New("credential protocol helper exec body has trailing data")
	ErrHelperExecPrivateShape             = errors.New("credential protocol helper exec private declaration is invalid")
	ErrHelperExecPrivateBodyLength        = errors.New("credential protocol helper exec-private body length is invalid")
	ErrHelperExecPrivateTrailingData      = errors.New("credential protocol helper exec-private body has trailing data")
	ErrHelperExecPrivateDigest            = errors.New("credential protocol helper exec private digest is invalid")
	ErrHelperExecPrivateDestination       = errors.New("credential protocol helper exec private destination is too small")
	ErrHelperExecPrivateWiped             = errors.New("credential protocol helper exec private bytes are wiped")
	ErrUnknownHelperExecStreamKind        = errors.New("credential protocol helper exec stream kind is unknown")
	ErrHelperExecStreamFlags              = errors.New("credential protocol helper exec stream flags are invalid")
	ErrHelperExecStreamReserved           = errors.New("credential protocol helper exec stream reserved bytes are invalid")
	ErrHelperExecStreamPayloadLength      = errors.New("credential protocol helper exec stream payload length is invalid")
	ErrHelperExecStreamPayloadDigest      = errors.New("credential protocol helper exec stream payload digest is invalid")
	ErrHelperExecStreamBodyLength         = errors.New("credential protocol helper exec-stream body length is invalid")
	ErrHelperExecStreamTrailingData       = errors.New("credential protocol helper exec-stream body has trailing data")
	ErrHelperExecStreamDestination        = errors.New("credential protocol helper exec stream destination is too small")
	ErrHelperExecStreamWiped              = errors.New("credential protocol helper exec stream bytes are wiped")
	ErrHelperExecCreditBodyLength         = errors.New("credential protocol helper exec-credit body length is invalid")
	ErrHelperExecCreditTrailingData       = errors.New("credential protocol helper exec-credit body has trailing data")
	ErrHelperExecCreditReserved           = errors.New("credential protocol helper exec-credit reserved bytes are invalid")
	ErrHelperExecBodySerialization        = errors.New("credential protocol helper exec body serialization is denied")
)

type HelperExecEnvironmentSource uint8

const (
	HelperExecEnvironmentLiteral   HelperExecEnvironmentSource = 1
	HelperExecEnvironmentInherited HelperExecEnvironmentSource = 2
	HelperExecEnvironmentGenerated HelperExecEnvironmentSource = 3
)

type HelperExecStreamMode uint8

const HelperExecStreamModePipe HelperExecStreamMode = 1

type HelperExecTimingKind uint8

const (
	HelperExecTimingTimeoutMillis      HelperExecTimingKind = 1
	HelperExecTimingDeadlineUnixMillis HelperExecTimingKind = 2
)

type HelperExecStreamKind uint8

const (
	HelperExecStreamStdin  HelperExecStreamKind = 1
	HelperExecStreamStdout HelperExecStreamKind = 2
	HelperExecStreamStderr HelperExecStreamKind = 3
)

type HelperExecStreamFlags uint8

const (
	HelperExecStreamFlagsNone HelperExecStreamFlags = 0
	HelperExecStreamFlagEOF   HelperExecStreamFlags = 1
)

type HelperExecEnvironment struct {
	Name   string
	Source HelperExecEnvironmentSource
	Value  string
}

type HelperExecTiming struct {
	Kind  HelperExecTimingKind
	Value int64
}

type HelperExecPlan struct {
	Arguments      []string
	Environment    []HelperExecEnvironment
	WorkDirectory  string
	StdinMode      HelperExecStreamMode
	StdoutMode     HelperExecStreamMode
	StderrMode     HelperExecStreamMode
	StdinMaxBytes  uint32
	StdoutMaxBytes uint32
	StderrMaxBytes uint32
	Timing         HelperExecTiming
}

type HelperExecBody struct {
	Revision             uint64
	ExecBindingID        string
	PrivateBindingLength uint32
	PrivateBindingSHA256 [32]byte
	Plan                 HelperExecPlan
}

type HelperExecPrivateBody struct {
	state *helperExecPrivateState
}

type helperExecPrivateState struct {
	revision             uint64
	privateBindingLength uint32
	privateBindingSHA256 [32]byte
	privateBinding       []byte
	wiped                bool
}

type HelperExecStreamBody struct {
	state *helperExecStreamState
}

type helperExecStreamState struct {
	revision      uint64
	streamKind    HelperExecStreamKind
	flags         HelperExecStreamFlags
	offset        uint64
	payloadLength uint32
	payloadSHA256 [32]byte
	payload       []byte
	wiped         bool
}

type HelperExecCreditBody struct {
	Revision   uint64
	StreamKind HelperExecStreamKind
	NextOffset uint64
}

func ValidateHelperExecEnvironmentSource(source HelperExecEnvironmentSource) error {
	switch source {
	case HelperExecEnvironmentLiteral, HelperExecEnvironmentInherited, HelperExecEnvironmentGenerated:
		return nil
	default:
		return ErrUnknownHelperExecEnvironmentSource
	}
}

func ValidateHelperExecStreamMode(mode HelperExecStreamMode) error {
	if mode != HelperExecStreamModePipe {
		return ErrUnknownHelperExecStreamMode
	}
	return nil
}

func ValidateHelperExecTimingKind(kind HelperExecTimingKind) error {
	switch kind {
	case HelperExecTimingTimeoutMillis, HelperExecTimingDeadlineUnixMillis:
		return nil
	default:
		return ErrUnknownHelperExecTimingKind
	}
}

func ValidateHelperExecStreamKind(kind HelperExecStreamKind) error {
	switch kind {
	case HelperExecStreamStdin, HelperExecStreamStdout, HelperExecStreamStderr:
		return nil
	default:
		return ErrUnknownHelperExecStreamKind
	}
}

func ValidateHelperExecPlan(plan HelperExecPlan) error {
	if len(plan.Arguments) < 1 || len(plan.Arguments) > MaxHelperExecArguments {
		return ErrHelperExecArgumentCount
	}
	for index, argument := range plan.Arguments {
		if len(argument) > MaxHelperExecArgumentBytes || !utf8.ValidString(argument) || helperExecContainsControl(argument) || index == 0 && strings.TrimSpace(argument) == "" {
			return ErrHelperExecArgument
		}
	}
	if len(plan.Environment) > MaxHelperExecEnvironmentEntries {
		return ErrHelperExecEnvironmentCount
	}
	proxyCount := 0
	proxyValue := ""
	for index, entry := range plan.Environment {
		if helperExecProtectedEnvironment(entry.Name) {
			return ErrHelperExecEnvironmentProtected
		}
		if err := ValidateHelperExecEnvironmentSource(entry.Source); err != nil {
			return err
		}
		if len(entry.Value) > MaxHelperExecEnvironmentValueBytes || strings.IndexByte(entry.Value, 0) >= 0 {
			return ErrHelperExecEnvironmentValue
		}
		for prior := 0; prior < index; prior++ {
			if plan.Environment[prior].Name == entry.Name {
				return ErrHelperExecEnvironmentName
			}
		}
		if helperExecProxyEnvironment(entry.Name) {
			if entry.Source != HelperExecEnvironmentGenerated {
				return ErrHelperExecProxyEnvironment
			}
			if proxyCount == 0 {
				proxyValue = entry.Value
			} else if entry.Value != proxyValue {
				return ErrHelperExecProxyEnvironment
			}
			proxyCount++
			continue
		}
		if !helperExecOrdinaryEnvironmentName(entry.Name) {
			return ErrHelperExecEnvironmentName
		}
	}
	if proxyCount != 0 && proxyCount != 4 {
		return ErrHelperExecProxyEnvironment
	}
	if !helperExecCanonicalWorkDirectory(plan.WorkDirectory) {
		return ErrHelperExecWorkDirectory
	}
	if err := ValidateHelperExecStreamMode(plan.StdinMode); err != nil {
		return err
	}
	if err := ValidateHelperExecStreamMode(plan.StdoutMode); err != nil {
		return err
	}
	if err := ValidateHelperExecStreamMode(plan.StderrMode); err != nil {
		return err
	}
	for _, maximum := range []uint32{plan.StdinMaxBytes, plan.StdoutMaxBytes, plan.StderrMaxBytes} {
		if maximum == 0 || maximum > MaxHelperExecStreamAggregateBytes {
			return ErrHelperExecStreamMaximum
		}
	}
	if err := ValidateHelperExecTimingKind(plan.Timing.Kind); err != nil {
		return err
	}
	switch plan.Timing.Kind {
	case HelperExecTimingTimeoutMillis:
		if plan.Timing.Value < 1 || plan.Timing.Value > MaxHelperExecTimeoutMillis {
			return ErrHelperExecTimingValue
		}
	case HelperExecTimingDeadlineUnixMillis:
		if plan.Timing.Value < MinHelperExecDeadlineUnixMillis || plan.Timing.Value > MaxHelperExecDeadlineUnixMillis {
			return ErrHelperExecTimingValue
		}
	}
	return nil
}

// ValidateHelperExecPlanProxyBaseURL correlates the syntactically canonical
// generated quartet with the exact L7 proxy base URL already authenticated by
// the caller. The pure codec deliberately does not parse or derive that live
// value, and its errors never include it.
func ValidateHelperExecPlanProxyBaseURL(plan HelperExecPlan, expectedProxyBaseURL string) error {
	if err := ValidateHelperExecPlan(plan); err != nil {
		return err
	}
	if expectedProxyBaseURL == "" || len(expectedProxyBaseURL) > MaxHelperExecEnvironmentValueBytes || strings.IndexByte(expectedProxyBaseURL, 0) >= 0 {
		return ErrHelperExecProxyEnvironment
	}
	proxyCount := 0
	for _, entry := range plan.Environment {
		if !helperExecProxyEnvironment(entry.Name) {
			continue
		}
		if entry.Source != HelperExecEnvironmentGenerated || entry.Value != expectedProxyBaseURL {
			return ErrHelperExecProxyEnvironment
		}
		proxyCount++
	}
	if proxyCount != 4 {
		return ErrHelperExecProxyEnvironment
	}
	return nil
}

// ValidateHelperExecBodyForPreparedManifest performs the caller-supplied
// state correlation that cannot be inferred from 0x15 bytes alone. The body
// must name the exact prepared binding and current positive revision. One
// prepared HTTP binding requires a nonzero private declaration and the
// generated proxy quartet fixed to expectedProxyBaseURL. A manifest without
// HTTP requires the zero-length/all-zero-digest declaration and forbids that
// quartet.
func ValidateHelperExecBodyForPreparedManifest(body HelperExecBody, bindings []HelperBindingManifestRecord, expectedExecBindingID string, expectedRevision uint64, expectedProxyBaseURL string) error {
	if err := validateHelperBindingManifest(bindings); err != nil {
		return err
	}
	if err := validateHelperExecRevision(expectedRevision); err != nil {
		return err
	}
	if err := ValidateBodyToken(expectedExecBindingID); err != nil {
		return err
	}
	if err := validateHelperExecRevision(body.Revision); err != nil {
		return err
	}
	if err := ValidateBodyToken(body.ExecBindingID); err != nil {
		return err
	}
	if body.Revision != expectedRevision || body.ExecBindingID != expectedExecBindingID {
		return ErrHelperExecPreparedManifest
	}
	if err := validateHelperExecPrivateShape(body.PrivateBindingLength, body.PrivateBindingSHA256); err != nil {
		return err
	}
	if err := ValidateHelperExecPlan(body.Plan); err != nil {
		return err
	}
	hasHTTP := false
	for _, binding := range bindings {
		if binding.Mode == DeliveryModeHTTPProxy {
			hasHTTP = true
			break
		}
	}
	if hasHTTP {
		if body.PrivateBindingLength == 0 {
			return ErrHelperExecPreparedManifest
		}
		if err := ValidateHelperExecPlanProxyBaseURL(body.Plan, expectedProxyBaseURL); err != nil {
			return err
		}
		return nil
	}
	if body.PrivateBindingLength != 0 {
		return ErrHelperExecPreparedManifest
	}
	for _, entry := range body.Plan.Environment {
		if helperExecProxyEnvironment(entry.Name) {
			return ErrHelperExecPreparedManifest
		}
	}
	return nil
}

func EncodeHelperExecPlan(plan HelperExecPlan) ([]byte, error) {
	if err := ValidateHelperExecPlan(plan); err != nil {
		return nil, err
	}
	encodedLength := helperExecPlanEncodedLength(plan)
	if encodedLength > MaxHelperExecPlanBytes {
		return nil, ErrHelperExecPlanLength
	}
	encoded := make([]byte, 0, encodedLength)
	encoded = appendHelperExecUint16(encoded, uint16(len(plan.Arguments)))
	for _, argument := range plan.Arguments {
		encoded = appendHelperExecBlob16(encoded, argument)
	}
	encoded = appendHelperExecUint16(encoded, uint16(len(plan.Environment)))
	for _, entry := range plan.Environment {
		encoded = appendHelperExecBlob16(encoded, entry.Name)
		encoded = append(encoded, byte(entry.Source))
		encoded = appendHelperExecBlob16(encoded, entry.Value)
	}
	encoded = appendHelperExecBlob16(encoded, plan.WorkDirectory)
	encoded = append(encoded, byte(plan.StdinMode), byte(plan.StdoutMode), byte(plan.StderrMode))
	encoded = appendHelperExecUint32(encoded, plan.StdinMaxBytes)
	encoded = appendHelperExecUint32(encoded, plan.StdoutMaxBytes)
	encoded = appendHelperExecUint32(encoded, plan.StderrMaxBytes)
	encoded = append(encoded, byte(plan.Timing.Kind))
	encoded = appendHelperExecUint64(encoded, uint64(plan.Timing.Value))
	return encoded, nil
}

func DecodeHelperExecPlan(encoded []byte) (HelperExecPlan, error) {
	if len(encoded) > MaxHelperExecPlanBytes {
		return HelperExecPlan{}, ErrHelperExecPlanLength
	}
	plan, consumed, err := decodeHelperExecPlanPrefix(encoded)
	if err != nil {
		return HelperExecPlan{}, err
	}
	if consumed != len(encoded) {
		return HelperExecPlan{}, ErrHelperExecPlanTrailingData
	}
	return plan, nil
}

func decodeHelperExecPlanPrefix(encoded []byte) (HelperExecPlan, int, error) {
	decoder := helperExecDecoder{encoded: encoded}
	count, err := decoder.readUint16()
	if err != nil {
		return HelperExecPlan{}, 0, err
	}
	if count < 1 || count > MaxHelperExecArguments {
		return HelperExecPlan{}, 0, ErrHelperExecArgumentCount
	}
	plan := HelperExecPlan{Arguments: make([]string, int(count))}
	for index := range plan.Arguments {
		plan.Arguments[index], err = decoder.readBlob16(MaxHelperExecArgumentBytes, ErrHelperExecArgument)
		if err != nil {
			return HelperExecPlan{}, 0, err
		}
	}
	environmentCount, err := decoder.readUint16()
	if err != nil {
		return HelperExecPlan{}, 0, err
	}
	if environmentCount > MaxHelperExecEnvironmentEntries {
		return HelperExecPlan{}, 0, ErrHelperExecEnvironmentCount
	}
	plan.Environment = make([]HelperExecEnvironment, int(environmentCount))
	for index := range plan.Environment {
		plan.Environment[index].Name, err = decoder.readBlob16(MaxHelperExecEnvironmentNameBytes, ErrHelperExecEnvironmentName)
		if err != nil {
			return HelperExecPlan{}, 0, err
		}
		source, readErr := decoder.readByte()
		if readErr != nil {
			return HelperExecPlan{}, 0, readErr
		}
		plan.Environment[index].Source = HelperExecEnvironmentSource(source)
		plan.Environment[index].Value, err = decoder.readBlob16(MaxHelperExecEnvironmentValueBytes, ErrHelperExecEnvironmentValue)
		if err != nil {
			return HelperExecPlan{}, 0, err
		}
	}
	plan.WorkDirectory, err = decoder.readBlob16(MaxHelperExecWorkDirectoryBytes, ErrHelperExecWorkDirectory)
	if err != nil {
		return HelperExecPlan{}, 0, err
	}
	modes, err := decoder.readBytes(3)
	if err != nil {
		return HelperExecPlan{}, 0, err
	}
	plan.StdinMode, plan.StdoutMode, plan.StderrMode = HelperExecStreamMode(modes[0]), HelperExecStreamMode(modes[1]), HelperExecStreamMode(modes[2])
	if plan.StdinMaxBytes, err = decoder.readUint32(); err != nil {
		return HelperExecPlan{}, 0, err
	}
	if plan.StdoutMaxBytes, err = decoder.readUint32(); err != nil {
		return HelperExecPlan{}, 0, err
	}
	if plan.StderrMaxBytes, err = decoder.readUint32(); err != nil {
		return HelperExecPlan{}, 0, err
	}
	timingKind, err := decoder.readByte()
	if err != nil {
		return HelperExecPlan{}, 0, err
	}
	plan.Timing.Kind = HelperExecTimingKind(timingKind)
	timingValue, err := decoder.readUint64()
	if err != nil {
		return HelperExecPlan{}, 0, err
	}
	plan.Timing.Value = int64(timingValue)
	if err := ValidateHelperExecPlan(plan); err != nil {
		return HelperExecPlan{}, 0, err
	}
	return plan, decoder.offset, nil
}

func EncodeHelperExecBody(body HelperExecBody) ([]byte, error) {
	if err := validateHelperExecRevision(body.Revision); err != nil {
		return nil, err
	}
	execBindingID, err := EncodeBodyToken(body.ExecBindingID)
	if err != nil {
		return nil, err
	}
	if err := validateHelperExecPrivateShape(body.PrivateBindingLength, body.PrivateBindingSHA256); err != nil {
		return nil, err
	}
	plan, err := EncodeHelperExecPlan(body.Plan)
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, 8+len(execBindingID)+4+sha256.Size+len(plan))
	if len(encoded) > MaxHelperPacketBodyBytes {
		return nil, ErrHelperExecBodyLength
	}
	binary.BigEndian.PutUint64(encoded[0:8], body.Revision)
	copy(encoded[8:], execBindingID)
	offset := 8 + len(execBindingID)
	binary.BigEndian.PutUint32(encoded[offset:offset+4], body.PrivateBindingLength)
	copy(encoded[offset+4:offset+36], body.PrivateBindingSHA256[:])
	copy(encoded[offset+36:], plan)
	return encoded, nil
}

func DecodeHelperExecBody(encoded []byte) (HelperExecBody, error) {
	if len(encoded) > MaxHelperPacketBodyBytes {
		return HelperExecBody{}, ErrHelperExecBodyLength
	}
	if len(encoded) < 8+2+1+4+sha256.Size {
		return HelperExecBody{}, ErrHelperExecBodyLength
	}
	body := HelperExecBody{Revision: binary.BigEndian.Uint64(encoded[0:8])}
	if err := validateHelperExecRevision(body.Revision); err != nil {
		return HelperExecBody{}, err
	}
	execBindingID, tokenBytes, err := DecodeBodyTokenPrefix(encoded[8:])
	if err != nil {
		if errors.Is(err, ErrBodyTokenEncoding) {
			return HelperExecBody{}, ErrHelperExecBodyLength
		}
		return HelperExecBody{}, err
	}
	body.ExecBindingID = execBindingID
	offset := 8 + tokenBytes
	if len(encoded)-offset < 4+sha256.Size {
		return HelperExecBody{}, ErrHelperExecBodyLength
	}
	body.PrivateBindingLength = binary.BigEndian.Uint32(encoded[offset : offset+4])
	copy(body.PrivateBindingSHA256[:], encoded[offset+4:offset+36])
	if err := validateHelperExecPrivateShape(body.PrivateBindingLength, body.PrivateBindingSHA256); err != nil {
		return HelperExecBody{}, err
	}
	body.Plan, tokenBytes, err = decodeHelperExecPlanPrefix(encoded[offset+36:])
	if err != nil {
		if errors.Is(err, ErrHelperExecPlanLength) {
			return HelperExecBody{}, ErrHelperExecBodyLength
		}
		return HelperExecBody{}, err
	}
	if offset+36+tokenBytes != len(encoded) {
		return HelperExecBody{}, ErrHelperExecBodyTrailingData
	}
	return body, nil
}

func NewHelperExecPrivateBody(revision uint64, privateBindingSHA256 [32]byte, privateBinding []byte) (*HelperExecPrivateBody, error) {
	if err := validateHelperExecRevision(revision); err != nil {
		return nil, err
	}
	if len(privateBinding) < 1 || len(privateBinding) > MaxHelperExecPrivateBytes {
		return nil, ErrHelperExecPrivateShape
	}
	if privateBindingSHA256 == [32]byte{} || sha256.Sum256(privateBinding) != privateBindingSHA256 {
		return nil, ErrHelperExecPrivateDigest
	}
	owned := make([]byte, len(privateBinding))
	copy(owned, privateBinding)
	return &HelperExecPrivateBody{state: &helperExecPrivateState{
		revision: revision, privateBindingLength: uint32(len(owned)), privateBindingSHA256: privateBindingSHA256, privateBinding: owned,
	}}, nil
}

func EncodeHelperExecPrivateBody(body *HelperExecPrivateBody) ([]byte, error) {
	state, err := helperExecPrivateLiveState(body)
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, helperExecPrivateFixedBytes+len(state.privateBinding))
	binary.BigEndian.PutUint64(encoded[0:8], state.revision)
	binary.BigEndian.PutUint32(encoded[8:12], state.privateBindingLength)
	copy(encoded[12:44], state.privateBindingSHA256[:])
	copy(encoded[44:], state.privateBinding)
	return encoded, nil
}

func DecodeHelperExecPrivateBody(encoded []byte) (*HelperExecPrivateBody, error) {
	if len(encoded) < helperExecPrivateFixedBytes {
		return nil, ErrHelperExecPrivateBodyLength
	}
	revision := binary.BigEndian.Uint64(encoded[0:8])
	if err := validateHelperExecRevision(revision); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(encoded[8:12])
	if length == 0 || length > MaxHelperExecPrivateBytes {
		return nil, ErrHelperExecPrivateShape
	}
	expected := helperExecPrivateFixedBytes + int(length)
	if len(encoded) < expected {
		return nil, ErrHelperExecPrivateBodyLength
	}
	if len(encoded) > expected {
		return nil, ErrHelperExecPrivateTrailingData
	}
	var digest [32]byte
	copy(digest[:], encoded[12:44])
	return NewHelperExecPrivateBody(revision, digest, encoded[44:])
}

func (body *HelperExecPrivateBody) CopyPrivateBinding(destination []byte) (int, error) {
	state, err := helperExecPrivateLiveState(body)
	if err != nil {
		return 0, err
	}
	if len(destination) < len(state.privateBinding) {
		return 0, ErrHelperExecPrivateDestination
	}
	return copy(destination, state.privateBinding), nil
}

func (body HelperExecPrivateBody) Revision() uint64 {
	if body.state == nil || body.state.wiped {
		return 0
	}
	return body.state.revision
}

func (body HelperExecPrivateBody) PrivateBindingLength() uint32 {
	if body.state == nil || body.state.wiped {
		return 0
	}
	return body.state.privateBindingLength
}

func (body HelperExecPrivateBody) PrivateBindingSHA256() [32]byte {
	if body.state == nil || body.state.wiped {
		return [32]byte{}
	}
	return body.state.privateBindingSHA256
}

func (body *HelperExecPrivateBody) Wipe() {
	if body == nil || body.state == nil || body.state.wiped {
		return
	}
	state := body.state
	if state.privateBinding != nil {
		privateBinding := state.privateBinding[:cap(state.privateBinding)]
		clear(privateBinding)
		runtime.KeepAlive(privateBinding)
	}
	state.privateBinding = nil
	state.revision = 0
	state.privateBindingLength = 0
	state.privateBindingSHA256 = [32]byte{}
	state.wiped = true
}

func NewHelperExecStreamBody(revision uint64, streamKind HelperExecStreamKind, flags HelperExecStreamFlags, offset uint64, payloadSHA256 [32]byte, payload []byte) (*HelperExecStreamBody, error) {
	if err := validateHelperExecRevision(revision); err != nil {
		return nil, err
	}
	if err := ValidateHelperExecStreamKind(streamKind); err != nil {
		return nil, err
	}
	if flags != HelperExecStreamFlagsNone && flags != HelperExecStreamFlagEOF {
		return nil, ErrHelperExecStreamFlags
	}
	if flags == HelperExecStreamFlagEOF {
		if len(payload) != 0 {
			return nil, ErrHelperExecStreamPayloadLength
		}
		if payloadSHA256 != sha256.Sum256(nil) {
			return nil, ErrHelperExecStreamPayloadDigest
		}
	} else {
		if len(payload) < 1 || len(payload) > MaxHelperExecStreamPayloadBytes {
			return nil, ErrHelperExecStreamPayloadLength
		}
		if payloadSHA256 == [32]byte{} || sha256.Sum256(payload) != payloadSHA256 {
			return nil, ErrHelperExecStreamPayloadDigest
		}
	}
	owned := make([]byte, len(payload))
	copy(owned, payload)
	return &HelperExecStreamBody{state: &helperExecStreamState{
		revision: revision, streamKind: streamKind, flags: flags, offset: offset,
		payloadLength: uint32(len(owned)), payloadSHA256: payloadSHA256, payload: owned,
	}}, nil
}

func EncodeHelperExecStreamBody(body *HelperExecStreamBody) ([]byte, error) {
	state, err := helperExecStreamLiveState(body)
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, helperExecStreamFixedBytes+len(state.payload))
	binary.BigEndian.PutUint64(encoded[0:8], state.revision)
	encoded[8] = byte(state.streamKind)
	encoded[9] = byte(state.flags)
	binary.BigEndian.PutUint64(encoded[12:20], state.offset)
	binary.BigEndian.PutUint32(encoded[20:24], state.payloadLength)
	copy(encoded[24:56], state.payloadSHA256[:])
	copy(encoded[56:], state.payload)
	return encoded, nil
}

func DecodeHelperExecStreamBody(encoded []byte) (*HelperExecStreamBody, error) {
	if len(encoded) < helperExecStreamFixedBytes {
		return nil, ErrHelperExecStreamBodyLength
	}
	if encoded[10] != 0 || encoded[11] != 0 {
		return nil, ErrHelperExecStreamReserved
	}
	revision := binary.BigEndian.Uint64(encoded[0:8])
	streamKind := HelperExecStreamKind(encoded[8])
	flags := HelperExecStreamFlags(encoded[9])
	offset := binary.BigEndian.Uint64(encoded[12:20])
	length := binary.BigEndian.Uint32(encoded[20:24])
	if length > MaxHelperExecStreamPayloadBytes {
		return nil, ErrHelperExecStreamPayloadLength
	}
	expected := helperExecStreamFixedBytes + int(length)
	if len(encoded) < expected {
		return nil, ErrHelperExecStreamBodyLength
	}
	if len(encoded) > expected {
		return nil, ErrHelperExecStreamTrailingData
	}
	var digest [32]byte
	copy(digest[:], encoded[24:56])
	return NewHelperExecStreamBody(revision, streamKind, flags, offset, digest, encoded[56:])
}

func (body *HelperExecStreamBody) CopyPayload(destination []byte) (int, error) {
	state, err := helperExecStreamLiveState(body)
	if err != nil {
		return 0, err
	}
	if len(destination) < len(state.payload) {
		return 0, ErrHelperExecStreamDestination
	}
	return copy(destination, state.payload), nil
}

func (body HelperExecStreamBody) Revision() uint64 {
	if body.state == nil || body.state.wiped {
		return 0
	}
	return body.state.revision
}
func (body HelperExecStreamBody) StreamKind() HelperExecStreamKind {
	if body.state == nil || body.state.wiped {
		return 0
	}
	return body.state.streamKind
}
func (body HelperExecStreamBody) Flags() HelperExecStreamFlags {
	if body.state == nil || body.state.wiped {
		return 0
	}
	return body.state.flags
}
func (body HelperExecStreamBody) Offset() uint64 {
	if body.state == nil || body.state.wiped {
		return 0
	}
	return body.state.offset
}
func (body HelperExecStreamBody) PayloadLength() uint32 {
	if body.state == nil || body.state.wiped {
		return 0
	}
	return body.state.payloadLength
}
func (body HelperExecStreamBody) PayloadSHA256() [32]byte {
	if body.state == nil || body.state.wiped {
		return [32]byte{}
	}
	return body.state.payloadSHA256
}

func (body *HelperExecStreamBody) Wipe() {
	if body == nil || body.state == nil || body.state.wiped {
		return
	}
	state := body.state
	if state.payload != nil {
		payload := state.payload[:cap(state.payload)]
		clear(payload)
		runtime.KeepAlive(payload)
	}
	state.payload = nil
	state.revision = 0
	state.streamKind = 0
	state.flags = 0
	state.offset = 0
	state.payloadLength = 0
	state.payloadSHA256 = [32]byte{}
	state.wiped = true
}

func EncodeHelperExecCreditBody(body HelperExecCreditBody) ([]byte, error) {
	length, err := HelperExecCreditBodyEncodedLength(body)
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, length)
	if err := EncodeHelperExecCreditBodyTo(encoded, body); err != nil {
		clear(encoded)
		return nil, err
	}
	return encoded, nil
}

// HelperExecCreditBodyEncodedLength returns the fixed canonical credit length.
func HelperExecCreditBodyEncodedLength(body HelperExecCreditBody) (uint32, error) {
	if err := validateHelperExecRevision(body.Revision); err != nil {
		return 0, err
	}
	if err := ValidateHelperExecStreamKind(body.StreamKind); err != nil {
		return 0, err
	}
	return HelperExecCreditBodyBytes, nil
}

// EncodeHelperExecCreditBodyTo writes a credit body into an exact destination.
func EncodeHelperExecCreditBodyTo(dst []byte, body HelperExecCreditBody) error {
	length, err := HelperExecCreditBodyEncodedLength(body)
	if err != nil {
		return err
	}
	if len(dst) != int(length) {
		return ErrHelperExecCreditBodyLength
	}
	binary.BigEndian.PutUint64(dst[0:8], body.Revision)
	dst[8] = byte(body.StreamKind)
	clear(dst[9:16])
	binary.BigEndian.PutUint64(dst[16:24], body.NextOffset)
	return nil
}

func DecodeHelperExecCreditBody(encoded []byte) (HelperExecCreditBody, error) {
	if len(encoded) < HelperExecCreditBodyBytes {
		return HelperExecCreditBody{}, ErrHelperExecCreditBodyLength
	}
	if len(encoded) > HelperExecCreditBodyBytes {
		return HelperExecCreditBody{}, ErrHelperExecCreditTrailingData
	}
	for _, reserved := range encoded[9:16] {
		if reserved != 0 {
			return HelperExecCreditBody{}, ErrHelperExecCreditReserved
		}
	}
	body := HelperExecCreditBody{Revision: binary.BigEndian.Uint64(encoded[0:8]), StreamKind: HelperExecStreamKind(encoded[8]), NextOffset: binary.BigEndian.Uint64(encoded[16:24])}
	if err := validateHelperExecRevision(body.Revision); err != nil {
		return HelperExecCreditBody{}, err
	}
	if err := ValidateHelperExecStreamKind(body.StreamKind); err != nil {
		return HelperExecCreditBody{}, err
	}
	return body, nil
}

func validateHelperExecRevision(revision uint64) error {
	if revision == 0 {
		return ErrHelperExecRevision
	}
	return nil
}

func validateHelperExecPrivateShape(length uint32, digest [32]byte) error {
	if length == 0 {
		if digest != [32]byte{} {
			return ErrHelperExecPrivateShape
		}
		return nil
	}
	if length > MaxHelperExecPrivateBytes || digest == [32]byte{} {
		return ErrHelperExecPrivateShape
	}
	return nil
}

func helperExecPrivateLiveState(body *HelperExecPrivateBody) (*helperExecPrivateState, error) {
	if body == nil || body.state == nil || body.state.wiped || body.state.privateBinding == nil {
		return nil, ErrHelperExecPrivateWiped
	}
	state := body.state
	if err := validateHelperExecRevision(state.revision); err != nil {
		return nil, err
	}
	if state.privateBindingLength == 0 || state.privateBindingLength > MaxHelperExecPrivateBytes || int(state.privateBindingLength) != len(state.privateBinding) || cap(state.privateBinding) != len(state.privateBinding) {
		return nil, ErrHelperExecPrivateShape
	}
	if state.privateBindingSHA256 == [32]byte{} || sha256.Sum256(state.privateBinding) != state.privateBindingSHA256 {
		return nil, ErrHelperExecPrivateDigest
	}
	return state, nil
}

func helperExecStreamLiveState(body *HelperExecStreamBody) (*helperExecStreamState, error) {
	if body == nil || body.state == nil || body.state.wiped || body.state.payload == nil {
		return nil, ErrHelperExecStreamWiped
	}
	state := body.state
	if err := validateHelperExecRevision(state.revision); err != nil {
		return nil, err
	}
	if err := ValidateHelperExecStreamKind(state.streamKind); err != nil {
		return nil, err
	}
	if state.flags != HelperExecStreamFlagsNone && state.flags != HelperExecStreamFlagEOF {
		return nil, ErrHelperExecStreamFlags
	}
	if int(state.payloadLength) != len(state.payload) || cap(state.payload) != len(state.payload) {
		return nil, ErrHelperExecStreamPayloadLength
	}
	if state.flags == HelperExecStreamFlagEOF {
		if state.payloadLength != 0 {
			return nil, ErrHelperExecStreamPayloadLength
		}
		if state.payloadSHA256 != sha256.Sum256(nil) {
			return nil, ErrHelperExecStreamPayloadDigest
		}
	} else {
		if state.payloadLength == 0 || state.payloadLength > MaxHelperExecStreamPayloadBytes {
			return nil, ErrHelperExecStreamPayloadLength
		}
		if state.payloadSHA256 == [32]byte{} || sha256.Sum256(state.payload) != state.payloadSHA256 {
			return nil, ErrHelperExecStreamPayloadDigest
		}
	}
	return state, nil
}

func helperExecContainsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func helperExecProtectedEnvironment(name string) bool {
	return name == "AZURE_OPENAI_BASE_URL" || name == "AZURE_OPENAI_API_KEY" || name == "AZURE_OPENAI_API_VERSION"
}

func helperExecProxyEnvironment(name string) bool {
	return name == "HTTP_PROXY" || name == "HTTPS_PROXY" || name == "http_proxy" || name == "https_proxy"
}

func helperExecOrdinaryEnvironmentName(name string) bool {
	if len(name) < 1 || len(name) > MaxHelperExecEnvironmentNameBytes || !(name[0] >= 'A' && name[0] <= 'Z' || name[0] == '_') {
		return false
	}
	for index := 1; index < len(name); index++ {
		value := name[index]
		if !(value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '_') {
			return false
		}
	}
	return true
}

func helperExecCanonicalWorkDirectory(value string) bool {
	if len(value) < 1 || len(value) > MaxHelperExecWorkDirectoryBytes || !utf8.ValidString(value) || helperExecContainsControl(value) || !strings.HasPrefix(value, "/") || strings.Contains(value, "\\") || strings.Contains(value, "://") || strings.Contains(value, "//") || path.Clean(value) != value {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == ".." {
			return false
		}
	}
	return true
}

func helperExecPlanEncodedLength(plan HelperExecPlan) int {
	length := 2 + 2 + 2 + len(plan.WorkDirectory) + 3 + 12 + 9
	for _, argument := range plan.Arguments {
		length += 2 + len(argument)
	}
	for _, entry := range plan.Environment {
		length += 2 + len(entry.Name) + 1 + 2 + len(entry.Value)
	}
	return length
}

func appendHelperExecBlob16(encoded []byte, value string) []byte {
	encoded = appendHelperExecUint16(encoded, uint16(len(value)))
	return append(encoded, value...)
}

func appendHelperExecUint16(encoded []byte, value uint16) []byte {
	start := len(encoded)
	encoded = append(encoded, 0, 0)
	binary.BigEndian.PutUint16(encoded[start:start+2], value)
	return encoded
}

func appendHelperExecUint32(encoded []byte, value uint32) []byte {
	start := len(encoded)
	encoded = append(encoded, make([]byte, 4)...)
	binary.BigEndian.PutUint32(encoded[start:start+4], value)
	return encoded
}

func appendHelperExecUint64(encoded []byte, value uint64) []byte {
	start := len(encoded)
	encoded = append(encoded, make([]byte, 8)...)
	binary.BigEndian.PutUint64(encoded[start:start+8], value)
	return encoded
}

type helperExecDecoder struct {
	encoded []byte
	offset  int
}

func (decoder *helperExecDecoder) readBytes(length int) ([]byte, error) {
	if length < 0 || len(decoder.encoded)-decoder.offset < length {
		return nil, ErrHelperExecPlanLength
	}
	value := decoder.encoded[decoder.offset : decoder.offset+length]
	decoder.offset += length
	return value, nil
}

func (decoder *helperExecDecoder) readByte() (byte, error) {
	value, err := decoder.readBytes(1)
	if err != nil {
		return 0, err
	}
	return value[0], nil
}
func (decoder *helperExecDecoder) readUint16() (uint16, error) {
	value, err := decoder.readBytes(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(value), nil
}
func (decoder *helperExecDecoder) readUint32() (uint32, error) {
	value, err := decoder.readBytes(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(value), nil
}
func (decoder *helperExecDecoder) readUint64() (uint64, error) {
	value, err := decoder.readBytes(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(value), nil
}

func (decoder *helperExecDecoder) readBlob16(maximum int, fieldError error) (string, error) {
	length, err := decoder.readUint16()
	if err != nil {
		return "", err
	}
	if int(length) > maximum {
		return "", fieldError
	}
	value, err := decoder.readBytes(int(length))
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func helperExecFormat(state fmt.State, name string) { _, _ = state.Write([]byte(name)) }

func (HelperExecEnvironment) String() string   { return "HelperExecEnvironment" }
func (HelperExecEnvironment) GoString() string { return "HelperExecEnvironment" }
func (HelperExecEnvironment) Format(state fmt.State, _ rune) {
	helperExecFormat(state, "HelperExecEnvironment")
}
func (HelperExecTiming) String() string                 { return "HelperExecTiming" }
func (HelperExecTiming) GoString() string               { return "HelperExecTiming" }
func (HelperExecTiming) Format(state fmt.State, _ rune) { helperExecFormat(state, "HelperExecTiming") }
func (HelperExecPlan) String() string                   { return "HelperExecPlan" }
func (HelperExecPlan) GoString() string                 { return "HelperExecPlan" }
func (HelperExecPlan) Format(state fmt.State, _ rune)   { helperExecFormat(state, "HelperExecPlan") }
func (HelperExecBody) String() string                   { return "HelperExecBody" }
func (HelperExecBody) GoString() string                 { return "HelperExecBody" }
func (HelperExecBody) Format(state fmt.State, _ rune)   { helperExecFormat(state, "HelperExecBody") }
func (HelperExecPrivateBody) String() string            { return "HelperExecPrivateBody" }
func (HelperExecPrivateBody) GoString() string          { return "HelperExecPrivateBody" }
func (HelperExecPrivateBody) Format(state fmt.State, _ rune) {
	helperExecFormat(state, "HelperExecPrivateBody")
}
func (HelperExecStreamBody) String() string   { return "HelperExecStreamBody" }
func (HelperExecStreamBody) GoString() string { return "HelperExecStreamBody" }
func (HelperExecStreamBody) Format(state fmt.State, _ rune) {
	helperExecFormat(state, "HelperExecStreamBody")
}
func (HelperExecCreditBody) String() string   { return "HelperExecCreditBody" }
func (HelperExecCreditBody) GoString() string { return "HelperExecCreditBody" }
func (HelperExecCreditBody) Format(state fmt.State, _ rune) {
	helperExecFormat(state, "HelperExecCreditBody")
}

func (HelperExecEnvironment) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperExecBodySerialization
}
func (HelperExecEnvironment) MarshalText() ([]byte, error) {
	return nil, ErrHelperExecBodySerialization
}
func (HelperExecEnvironment) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperExecBodySerialization
}
func (*HelperExecEnvironment) UnmarshalJSON([]byte) error   { return ErrHelperExecBodySerialization }
func (*HelperExecEnvironment) UnmarshalText([]byte) error   { return ErrHelperExecBodySerialization }
func (*HelperExecEnvironment) UnmarshalBinary([]byte) error { return ErrHelperExecBodySerialization }
func (HelperExecTiming) MarshalJSON() ([]byte, error)       { return nil, ErrHelperExecBodySerialization }
func (HelperExecTiming) MarshalText() ([]byte, error)       { return nil, ErrHelperExecBodySerialization }
func (HelperExecTiming) MarshalBinary() ([]byte, error)     { return nil, ErrHelperExecBodySerialization }
func (*HelperExecTiming) UnmarshalJSON([]byte) error        { return ErrHelperExecBodySerialization }
func (*HelperExecTiming) UnmarshalText([]byte) error        { return ErrHelperExecBodySerialization }
func (*HelperExecTiming) UnmarshalBinary([]byte) error      { return ErrHelperExecBodySerialization }
func (HelperExecPlan) MarshalJSON() ([]byte, error)         { return nil, ErrHelperExecBodySerialization }
func (HelperExecPlan) MarshalText() ([]byte, error)         { return nil, ErrHelperExecBodySerialization }
func (HelperExecPlan) MarshalBinary() ([]byte, error)       { return nil, ErrHelperExecBodySerialization }
func (*HelperExecPlan) UnmarshalJSON([]byte) error          { return ErrHelperExecBodySerialization }
func (*HelperExecPlan) UnmarshalText([]byte) error          { return ErrHelperExecBodySerialization }
func (*HelperExecPlan) UnmarshalBinary([]byte) error        { return ErrHelperExecBodySerialization }
func (HelperExecBody) MarshalJSON() ([]byte, error)         { return nil, ErrHelperExecBodySerialization }
func (HelperExecBody) MarshalText() ([]byte, error)         { return nil, ErrHelperExecBodySerialization }
func (HelperExecBody) MarshalBinary() ([]byte, error)       { return nil, ErrHelperExecBodySerialization }
func (*HelperExecBody) UnmarshalJSON([]byte) error          { return ErrHelperExecBodySerialization }
func (*HelperExecBody) UnmarshalText([]byte) error          { return ErrHelperExecBodySerialization }
func (*HelperExecBody) UnmarshalBinary([]byte) error        { return ErrHelperExecBodySerialization }
func (HelperExecPrivateBody) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperExecBodySerialization
}
func (HelperExecPrivateBody) MarshalText() ([]byte, error) {
	return nil, ErrHelperExecBodySerialization
}
func (HelperExecPrivateBody) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperExecBodySerialization
}
func (*HelperExecPrivateBody) UnmarshalJSON([]byte) error   { return ErrHelperExecBodySerialization }
func (*HelperExecPrivateBody) UnmarshalText([]byte) error   { return ErrHelperExecBodySerialization }
func (*HelperExecPrivateBody) UnmarshalBinary([]byte) error { return ErrHelperExecBodySerialization }
func (HelperExecStreamBody) MarshalJSON() ([]byte, error)   { return nil, ErrHelperExecBodySerialization }
func (HelperExecStreamBody) MarshalText() ([]byte, error)   { return nil, ErrHelperExecBodySerialization }
func (HelperExecStreamBody) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperExecBodySerialization
}
func (*HelperExecStreamBody) UnmarshalJSON([]byte) error   { return ErrHelperExecBodySerialization }
func (*HelperExecStreamBody) UnmarshalText([]byte) error   { return ErrHelperExecBodySerialization }
func (*HelperExecStreamBody) UnmarshalBinary([]byte) error { return ErrHelperExecBodySerialization }
func (HelperExecCreditBody) MarshalJSON() ([]byte, error)  { return nil, ErrHelperExecBodySerialization }
func (HelperExecCreditBody) MarshalText() ([]byte, error)  { return nil, ErrHelperExecBodySerialization }
func (HelperExecCreditBody) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperExecBodySerialization
}
func (*HelperExecCreditBody) UnmarshalJSON([]byte) error   { return ErrHelperExecBodySerialization }
func (*HelperExecCreditBody) UnmarshalText([]byte) error   { return ErrHelperExecBodySerialization }
func (*HelperExecCreditBody) UnmarshalBinary([]byte) error { return ErrHelperExecBodySerialization }
