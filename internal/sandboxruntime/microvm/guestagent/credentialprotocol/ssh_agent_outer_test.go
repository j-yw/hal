package credentialprotocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestSSHAgentOuterFrameBounds(t *testing.T) {
	t.Parallel()

	if SSHAgentFrameHeaderBytes != 4 {
		t.Fatalf("SSHAgentFrameHeaderBytes = %d, want 4", SSHAgentFrameHeaderBytes)
	}
	if SSHAgentMinPayloadBytes != 1 {
		t.Fatalf("SSHAgentMinPayloadBytes = %d, want 1", SSHAgentMinPayloadBytes)
	}
	if SSHAgentMaxPayloadBytes != 256*1024 {
		t.Fatalf("SSHAgentMaxPayloadBytes = %d, want %d", SSHAgentMaxPayloadBytes, 256*1024)
	}
	if SSHAgentMaxFrameBytes != 262148 {
		t.Fatalf("SSHAgentMaxFrameBytes = %d, want 262148", SSHAgentMaxFrameBytes)
	}

	minimum := sshAgentOuterFrame(1, []byte{byte(SSHAgentMessageRequestIdentities)})
	metadata, err := ValidateSSHAgentOuterFrame(minimum)
	if err != nil {
		t.Fatalf("ValidateSSHAgentOuterFrame(minimum): %v", err)
	}
	if metadata.PayloadLength != 1 || metadata.MessageType != SSHAgentMessageRequestIdentities || metadata.Class != SSHAgentMessageClassClientRequest {
		t.Fatalf("minimum metadata = %#v", metadata)
	}

	maximumPayload := make([]byte, SSHAgentMaxPayloadBytes)
	maximumPayload[0] = byte(SSHAgentMessageSignRequest)
	maximum := sshAgentOuterFrame(SSHAgentMaxPayloadBytes, maximumPayload)
	metadata, err = ValidateSSHAgentOuterFrame(maximum)
	if err != nil {
		t.Fatalf("ValidateSSHAgentOuterFrame(maximum): %v", err)
	}
	if len(maximum) != SSHAgentMaxFrameBytes || metadata.PayloadLength != SSHAgentMaxPayloadBytes || metadata.MessageType != SSHAgentMessageSignRequest {
		t.Fatalf("maximum len/metadata = %d/%#v", len(maximum), metadata)
	}

	tests := []struct {
		name  string
		frame []byte
		want  error
	}{
		{name: "missing header", frame: nil, want: ErrSSHAgentFrameHeader},
		{name: "short header", frame: []byte{0, 0, 0}, want: ErrSSHAgentFrameHeader},
		{name: "zero payload", frame: []byte{0, 0, 0, 0}, want: ErrSSHAgentPayloadLength},
		{name: "payload plus one", frame: []byte{0, 4, 0, 1}, want: ErrSSHAgentPayloadLength},
		{name: "truncated minimum", frame: []byte{0, 0, 0, 1}, want: ErrSSHAgentFrameTruncated},
		{name: "truncated declared", frame: sshAgentOuterFrame(2, []byte{byte(SSHAgentMessageSignRequest)}), want: ErrSSHAgentFrameTruncated},
		{name: "trailing byte", frame: append(sshAgentOuterFrame(1, []byte{byte(SSHAgentMessageRequestIdentities)}), 0), want: ErrSSHAgentFrameTrailingData},
		{name: "concatenated frame", frame: append(sshAgentOuterFrame(1, []byte{byte(SSHAgentMessageRequestIdentities)}), sshAgentOuterFrame(1, []byte{byte(SSHAgentMessageFailure)})...), want: ErrSSHAgentFrameTrailingData},
		{name: "identities request body", frame: sshAgentOuterFrame(2, []byte{byte(SSHAgentMessageRequestIdentities), 0}), want: ErrSSHAgentMessageBody},
		{name: "failure body", frame: sshAgentOuterFrame(2, []byte{byte(SSHAgentMessageFailure), 0}), want: ErrSSHAgentMessageBody},
		{name: "unknown type", frame: sshAgentOuterFrame(1, []byte{0xff}), want: ErrSSHAgentMessageType},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			metadata, err := ValidateSSHAgentOuterFrame(test.frame)
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateSSHAgentOuterFrame() error = %v, want %v", err, test.want)
			}
			if metadata != (SSHAgentOuterFrameMetadata{}) {
				t.Fatalf("failure metadata = %#v, want zero", metadata)
			}
		})
	}
}

func TestSSHAgentFrameHeaderEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		length uint32
		want   [SSHAgentFrameHeaderBytes]byte
	}{
		{length: 1, want: [4]byte{0, 0, 0, 1}},
		{length: SSHAgentMaxPayloadBytes, want: [4]byte{0, 4, 0, 0}},
	}
	for _, test := range tests {
		header, err := EncodeSSHAgentFrameHeader(test.length)
		if err != nil {
			t.Fatalf("EncodeSSHAgentFrameHeader(%d): %v", test.length, err)
		}
		if header != test.want {
			t.Fatalf("EncodeSSHAgentFrameHeader(%d) = %v, want %v", test.length, header, test.want)
		}
	}
	for _, length := range []uint32{0, SSHAgentMaxPayloadBytes + 1, ^uint32(0)} {
		header, err := EncodeSSHAgentFrameHeader(length)
		if !errors.Is(err, ErrSSHAgentPayloadLength) {
			t.Fatalf("EncodeSSHAgentFrameHeader(%d) error = %v", length, err)
		}
		if header != ([SSHAgentFrameHeaderBytes]byte{}) {
			t.Fatalf("EncodeSSHAgentFrameHeader(%d) = %v, want zero", length, header)
		}
	}
}

func TestSSHAgentMessageTypeCatalogAndClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		messageType SSHAgentMessageType
		wire        byte
		class       SSHAgentMessageClass
		name        string
	}{
		{SSHAgentMessageFailure, 5, SSHAgentMessageClassResponse, "failure"},
		{SSHAgentMessageRequestIdentities, 11, SSHAgentMessageClassClientRequest, "request_identities"},
		{SSHAgentMessageIdentitiesAnswer, 12, SSHAgentMessageClassResponse, "identities_answer"},
		{SSHAgentMessageSignRequest, 13, SSHAgentMessageClassClientRequest, "sign_request"},
		{SSHAgentMessageSignResponse, 14, SSHAgentMessageClassResponse, "sign_response"},
	}
	for _, test := range tests {
		if byte(test.messageType) != test.wire {
			t.Errorf("%s wire value = %d, want %d", test.name, test.messageType, test.wire)
		}
		if err := ValidateSSHAgentMessageType(test.messageType); err != nil {
			t.Errorf("ValidateSSHAgentMessageType(%s): %v", test.name, err)
		}
		class, err := ClassifySSHAgentMessageType(test.messageType)
		if err != nil || class != test.class {
			t.Errorf("ClassifySSHAgentMessageType(%s) = %v, %v; want %v, nil", test.name, class, err, test.class)
		}
		if test.messageType.String() != test.name {
			t.Errorf("SSHAgentMessageType(%d).String() = %q, want %q", test.wire, test.messageType.String(), test.name)
		}
		if test.class.String() == "unknown" {
			t.Errorf("SSHAgentMessageClass %q is not canonical", test.class)
		}
		frame := sshAgentOuterFrame(1, []byte{byte(test.messageType)})
		metadata, err := ValidateSSHAgentOuterFrame(frame)
		if err != nil || metadata.MessageType != test.messageType || metadata.Class != test.class {
			t.Errorf("ValidateSSHAgentOuterFrame(%s) = %#v, %v", test.name, metadata, err)
		}
	}

	for _, value := range []SSHAgentMessageType{0, 1, 6, 10, 15, 17, 255} {
		if !errors.Is(ValidateSSHAgentMessageType(value), ErrSSHAgentMessageType) {
			t.Errorf("ValidateSSHAgentMessageType(%d) accepted", value)
		}
		class, err := ClassifySSHAgentMessageType(value)
		if !errors.Is(err, ErrSSHAgentMessageType) || class != SSHAgentMessageClassUnknown {
			t.Errorf("ClassifySSHAgentMessageType(%d) = %v, %v", value, class, err)
		}
		if value.String() != "unknown" {
			t.Errorf("SSHAgentMessageType(%d).String() = %q", value, value.String())
		}
	}
}

func TestSSHAgentAlgorithmCatalogs(t *testing.T) {
	t.Parallel()

	keys := []SSHAgentKeyAlgorithm{
		SSHAgentKeyAlgorithmED25519,
		SSHAgentKeyAlgorithmECDSANISTP256,
		SSHAgentKeyAlgorithmECDSANISTP384,
		SSHAgentKeyAlgorithmECDSANISTP521,
		SSHAgentKeyAlgorithmRSA,
	}
	for _, algorithm := range keys {
		if err := ValidateSSHAgentKeyAlgorithm(algorithm); err != nil {
			t.Errorf("ValidateSSHAgentKeyAlgorithm(%q): %v", algorithm, err)
		}
		if algorithm.String() != string(algorithm) {
			t.Errorf("SSHAgentKeyAlgorithm(%q).String() = %q", algorithm, algorithm.String())
		}
	}

	signatures := []SSHAgentSignatureAlgorithm{
		SSHAgentSignatureAlgorithmED25519,
		SSHAgentSignatureAlgorithmECDSANISTP256,
		SSHAgentSignatureAlgorithmECDSANISTP384,
		SSHAgentSignatureAlgorithmECDSANISTP521,
		SSHAgentSignatureAlgorithmRSASHA256,
		SSHAgentSignatureAlgorithmRSASHA512,
	}
	for _, algorithm := range signatures {
		if err := ValidateSSHAgentSignatureAlgorithm(algorithm); err != nil {
			t.Errorf("ValidateSSHAgentSignatureAlgorithm(%q): %v", algorithm, err)
		}
		if algorithm.String() != string(algorithm) {
			t.Errorf("SSHAgentSignatureAlgorithm(%q).String() = %q", algorithm, algorithm.String())
		}
	}

	for _, value := range []SSHAgentKeyAlgorithm{
		"", "rsa-sha2-256", "ssh-dss", "sk-ssh-ed25519@openssh.com",
		"ssh-ed25519-cert-v01@openssh.com", "unknown-key",
	} {
		if !errors.Is(ValidateSSHAgentKeyAlgorithm(value), ErrSSHAgentKeyAlgorithm) {
			t.Errorf("ValidateSSHAgentKeyAlgorithm(%q) accepted", value)
		}
		if value.String() != "unknown" {
			t.Errorf("invalid key algorithm String() = %q", value.String())
		}
	}
	for _, value := range []SSHAgentSignatureAlgorithm{
		"", "ssh-rsa", "ssh-dss", "sk-ssh-ed25519@openssh.com",
		"ssh-ed25519-cert-v01@openssh.com", "unknown-signature",
	} {
		if !errors.Is(ValidateSSHAgentSignatureAlgorithm(value), ErrSSHAgentSignatureAlgorithm) {
			t.Errorf("ValidateSSHAgentSignatureAlgorithm(%q) accepted", value)
		}
		if value.String() != "unknown" {
			t.Errorf("invalid signature algorithm String() = %q", value.String())
		}
	}
}

func TestSSHAgentSignPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		key       SSHAgentKeyAlgorithm
		flags     SSHAgentRSAFlags
		signature SSHAgentSignatureAlgorithm
	}{
		{"ed25519", SSHAgentKeyAlgorithmED25519, 0, SSHAgentSignatureAlgorithmED25519},
		{"ecdsa p256", SSHAgentKeyAlgorithmECDSANISTP256, 0, SSHAgentSignatureAlgorithmECDSANISTP256},
		{"ecdsa p384", SSHAgentKeyAlgorithmECDSANISTP384, 0, SSHAgentSignatureAlgorithmECDSANISTP384},
		{"ecdsa p521", SSHAgentKeyAlgorithmECDSANISTP521, 0, SSHAgentSignatureAlgorithmECDSANISTP521},
		{"rsa sha256", SSHAgentKeyAlgorithmRSA, SSHAgentRSAFlagSHA256, SSHAgentSignatureAlgorithmRSASHA256},
		{"rsa sha512", SSHAgentKeyAlgorithmRSA, SSHAgentRSAFlagSHA512, SSHAgentSignatureAlgorithmRSASHA512},
	}
	for _, test := range tests {
		if err := ValidateSSHAgentRequestFlags(test.key, test.flags); err != nil {
			t.Errorf("ValidateSSHAgentRequestFlags(%s): %v", test.name, err)
		}
		if err := ValidateSSHAgentSignPolicy(test.key, test.flags, test.signature); err != nil {
			t.Errorf("ValidateSSHAgentSignPolicy(%s): %v", test.name, err)
		}
	}

	if uint32(SSHAgentRSAFlagSHA256) != 2 || uint32(SSHAgentRSAFlagSHA512) != 4 {
		t.Fatalf("RSA flags = %d/%d, want 2/4", SSHAgentRSAFlagSHA256, SSHAgentRSAFlagSHA512)
	}
	invalidFlags := []struct {
		key   SSHAgentKeyAlgorithm
		flags SSHAgentRSAFlags
	}{
		{SSHAgentKeyAlgorithmRSA, 0},
		{SSHAgentKeyAlgorithmRSA, SSHAgentRSAFlagSHA256 | SSHAgentRSAFlagSHA512},
		{SSHAgentKeyAlgorithmRSA, 1},
		{SSHAgentKeyAlgorithmRSA, 8},
		{SSHAgentKeyAlgorithmED25519, SSHAgentRSAFlagSHA256},
		{SSHAgentKeyAlgorithmECDSANISTP256, SSHAgentRSAFlagSHA512},
	}
	for _, test := range invalidFlags {
		if !errors.Is(ValidateSSHAgentRequestFlags(test.key, test.flags), ErrSSHAgentFlags) {
			t.Errorf("ValidateSSHAgentRequestFlags(%q, %d) accepted", test.key, test.flags)
		}
	}

	mismatches := []struct {
		key       SSHAgentKeyAlgorithm
		flags     SSHAgentRSAFlags
		signature SSHAgentSignatureAlgorithm
	}{
		{SSHAgentKeyAlgorithmRSA, SSHAgentRSAFlagSHA256, SSHAgentSignatureAlgorithmRSASHA512},
		{SSHAgentKeyAlgorithmRSA, SSHAgentRSAFlagSHA512, SSHAgentSignatureAlgorithmRSASHA256},
		{SSHAgentKeyAlgorithmED25519, 0, SSHAgentSignatureAlgorithmECDSANISTP256},
		{SSHAgentKeyAlgorithmECDSANISTP256, 0, SSHAgentSignatureAlgorithmED25519},
	}
	for _, test := range mismatches {
		if !errors.Is(ValidateSSHAgentSignPolicy(test.key, test.flags, test.signature), ErrSSHAgentSignaturePolicy) {
			t.Errorf("ValidateSSHAgentSignPolicy(%q, %d, %q) accepted", test.key, test.flags, test.signature)
		}
	}
	if !errors.Is(ValidateSSHAgentSignPolicy("ssh-dss", 0, SSHAgentSignatureAlgorithmED25519), ErrSSHAgentKeyAlgorithm) {
		t.Error("invalid key algorithm did not retain catalog error")
	}
	if !errors.Is(ValidateSSHAgentSignPolicy(SSHAgentKeyAlgorithmED25519, 0, "ssh-rsa"), ErrSSHAgentSignatureAlgorithm) {
		t.Error("invalid signature algorithm did not retain catalog error")
	}
}

func TestSSHAgentOuterValidationDoesNotAllocateOrRetainSource(t *testing.T) {
	frame := sshAgentOuterFrame(1, []byte{byte(SSHAgentMessageRequestIdentities)})
	allocations := testing.AllocsPerRun(1000, func() {
		metadata, err := ValidateSSHAgentOuterFrame(frame)
		if err != nil || metadata.MessageType != SSHAgentMessageRequestIdentities {
			panic("unexpected validation result")
		}
	})
	if allocations != 0 {
		t.Fatalf("ValidateSSHAgentOuterFrame allocations = %v, want 0", allocations)
	}

	metadata, err := ValidateSSHAgentOuterFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	for index := range frame {
		frame[index] = 0xa5
	}
	if metadata.PayloadLength != 1 || metadata.MessageType != SSHAgentMessageRequestIdentities || metadata.Class != SSHAgentMessageClassClientRequest {
		t.Fatalf("metadata changed after source overwrite: %#v", metadata)
	}
}

func TestSSHAgentOuterErrorsAndFormattingAreSanitized(t *testing.T) {
	t.Parallel()

	secret := "ssh-agent-sensitive-canary"
	frame := sshAgentOuterFrame(1+len(secret), append([]byte{0xff}, []byte(secret)...))
	metadata, err := ValidateSSHAgentOuterFrame(frame)
	if !errors.Is(err, ErrSSHAgentMessageType) || metadata != (SSHAgentOuterFrameMetadata{}) {
		t.Fatalf("unexpected result: %#v, %v", metadata, err)
	}
	for _, rendered := range []string{err.Error(), fmt.Sprint(err), fmt.Sprintf("%v", err), fmt.Sprintf("%#v", err), fmt.Sprint(metadata), fmt.Sprintf("%#v", metadata)} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("sensitive body leaked through formatting: %q", rendered)
		}
	}
	for _, rendered := range []string{
		fmt.Sprint(SSHAgentKeyAlgorithm(secret)),
		fmt.Sprintf("%#v", SSHAgentKeyAlgorithm(secret)),
		fmt.Sprint(SSHAgentSignatureAlgorithm(secret)),
		fmt.Sprintf("%#v", SSHAgentSignatureAlgorithm(secret)),
		fmt.Sprint(SSHAgentMessageClass(secret)),
		fmt.Sprintf("%#v", SSHAgentMessageClass(secret)),
	} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("invalid catalog value leaked through formatting: %q", rendered)
		}
	}

	for _, value := range []any{SSHAgentOuterFrameMetadata{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			if field.Tag != "" {
				t.Errorf("%s.%s tag = %q, want none", typeOf, field.Name, field.Tag)
			}
			if field.Type.Kind() == reflect.String && field.Type != reflect.TypeOf(SSHAgentMessageClassUnknown) {
				t.Errorf("%s.%s has non-catalog string type %s", typeOf, field.Name, field.Type)
			}
			if field.Type.Kind() == reflect.Slice || field.Type.Kind() == reflect.Map || field.Type.Kind() == reflect.Interface {
				t.Errorf("%s.%s has body-capable type %s", typeOf, field.Name, field.Type)
			}
		}
	}
}

func TestSSHAgentOuterSourceShapeAndImports(t *testing.T) {
	t.Parallel()

	const filename = "ssh_agent_outer.go"
	file, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	approvedImports := map[string]bool{"encoding/binary": true, "errors": true}
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("unquote import: %v", err)
		}
		if !approvedImports[path] {
			t.Errorf("%s imports %q; only exact pure outer-codec imports are allowed", filename, path)
		}
	}

	forbiddenFunctions := map[string]bool{
		"EncodeSSHAgentFrame":   true,
		"EncodeSSHAgentPayload": true,
		"DecodeSSHAgentFrame":   true,
		"DecodeSSHAgentPayload": true,
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.FuncDecl:
			if forbiddenFunctions[typed.Name.Name] {
				t.Errorf("%s exposes generic body API %s", filename, typed.Name.Name)
			}
			if typed.Name.Name == "ValidateSSHAgentOuterFrame" && typed.Type.Results != nil {
				for _, result := range typed.Type.Results.List {
					if array, ok := result.Type.(*ast.ArrayType); ok && array.Len == nil {
						t.Errorf("ValidateSSHAgentOuterFrame returns a slice")
					}
					if identifier, ok := result.Type.(*ast.Ident); ok && identifier.Name == "string" {
						t.Errorf("ValidateSSHAgentOuterFrame returns a string")
					}
				}
			}
		case *ast.CallExpr:
			identifier, ok := typed.Fun.(*ast.Ident)
			if ok && (identifier.Name == "append" || identifier.Name == "copy" || identifier.Name == "make") {
				t.Errorf("%s calls body-owning builtin %s", filename, identifier.Name)
			}
		case *ast.TypeSpec:
			structure, ok := typed.Type.(*ast.StructType)
			if !ok {
				break
			}
			for _, field := range structure.Fields.List {
				if array, ok := field.Type.(*ast.ArrayType); ok && array.Len == nil {
					t.Errorf("%s struct %s owns a slice", filename, typed.Name)
				}
				if identifier, ok := field.Type.(*ast.Ident); ok && identifier.Name == "string" {
					t.Errorf("%s struct %s owns a string", filename, typed.Name)
				}
			}
		}
		return true
	})
}

func sshAgentOuterFrame(declaredLength int, payload []byte) []byte {
	frame := make([]byte, SSHAgentFrameHeaderBytes+len(payload))
	binary.BigEndian.PutUint32(frame[:SSHAgentFrameHeaderBytes], uint32(declaredLength))
	copy(frame[SSHAgentFrameHeaderBytes:], payload)
	return frame
}
