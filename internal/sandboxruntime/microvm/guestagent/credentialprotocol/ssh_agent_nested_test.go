package credentialprotocol

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSSHAgentNestedAcceptedRequestForms(t *testing.T) {
	t.Parallel()

	identities := sshAgentNestedFrame(SSHAgentMessageRequestIdentities, nil)
	if err := ValidateSSHAgentIdentitiesRequest(identities); err != nil {
		t.Fatalf("ValidateSSHAgentIdentitiesRequest(): %v", err)
	}

	key := sshAgentNestedED25519Key(bytes.Repeat([]byte{0x42}, 32))
	challenge := []byte("nested-sensitive-challenge")
	body := append(sshAgentNestedString(nil, key), sshAgentNestedString(nil, challenge)...)
	body = append(body, 0, 0, 0, 0)
	request, err := DecodeSSHAgentSignRequest(sshAgentNestedFrame(SSHAgentMessageSignRequest, body))
	if err != nil {
		t.Fatalf("DecodeSSHAgentSignRequest(): %v", err)
	}
	defer request.Wipe()
	if request.KeyAlgorithm() != SSHAgentKeyAlgorithmED25519 || request.Flags() != 0 {
		t.Fatalf("request policy = %s/%d", request.KeyAlgorithm(), request.Flags())
	}
	if got := request.PublicKeyBlob(); !bytes.Equal(got, key) {
		t.Fatalf("public key blob mismatch")
	} else {
		WipeSSHAgentBytes(got)
	}
	if got := request.Challenge(); !bytes.Equal(got, challenge) {
		t.Fatalf("challenge mismatch")
	} else {
		WipeSSHAgentBytes(got)
	}
}

func TestSSHAgentNestedBoundsAreFixed(t *testing.T) {
	t.Parallel()

	if SSHAgentMaxIdentities != 256 || SSHAgentMaxKeyBlobBytes != 16*1024 ||
		SSHAgentMaxCommentBytes != 4*1024 || SSHAgentMaxChallengeBytes != 192*1024 ||
		SSHAgentMaxSignatureBytes != 16*1024 {
		t.Fatalf("unexpected SSH-agent nested bounds")
	}

	key := sshAgentNestedED25519Key(bytes.Repeat([]byte{0x24}, 32))
	body := append(sshAgentNestedString(nil, key), sshAgentNestedString(nil, make([]byte, SSHAgentMaxChallengeBytes+1))...)
	body = append(body, 0, 0, 0, 0)
	request, err := DecodeSSHAgentSignRequest(sshAgentNestedFrame(SSHAgentMessageSignRequest, body))
	if request != nil || !errors.Is(err, ErrSSHAgentChallengeLength) {
		t.Fatalf("plus-one challenge = %#v, %v", request, err)
	}
}

func TestSSHAgentNestedKeyBlobCatalogAndCanonicalStructure(t *testing.T) {
	t.Parallel()

	ed25519 := sshAgentNestedED25519Key(bytes.Repeat([]byte{0x24}, 32))
	rsa := sshAgentNestedRSAKey([]byte{1, 0, 1}, []byte{0, 0x80, 1})
	valid := []struct {
		name      string
		algorithm SSHAgentKeyAlgorithm
		blob      []byte
	}{
		{name: "ed25519", algorithm: SSHAgentKeyAlgorithmED25519, blob: ed25519},
		{name: "rsa", algorithm: SSHAgentKeyAlgorithmRSA, blob: rsa},
	}
	for _, test := range sshAgentNestedECDSAKeys() {
		valid = append(valid, struct {
			name      string
			algorithm SSHAgentKeyAlgorithm
			blob      []byte
		}{name: test.name, algorithm: test.algorithm, blob: test.blob})
	}
	for _, test := range valid {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			identity, err := NewSSHAgentIdentity(test.blob)
			if err != nil {
				t.Fatalf("NewSSHAgentIdentity(): %v", err)
			}
			defer identity.Wipe()
			if identity.KeyAlgorithm() != test.algorithm {
				t.Fatalf("algorithm = %s, want %s", identity.KeyAlgorithm(), test.algorithm)
			}
			got := identity.PublicKeyBlob()
			defer WipeSSHAgentBytes(got)
			if !bytes.Equal(got, test.blob) {
				t.Fatal("key blob changed")
			}
		})
	}

	for _, test := range sshAgentNestedECDSAKeys() {
		pointOffset := len(test.blob) - test.pointLength
		offCurve := append([]byte(nil), test.blob...)
		for index := pointOffset + 1; index < len(offCurve); index++ {
			offCurve[index] = 0xff
		}
		if _, err := NewSSHAgentIdentity(offCurve); !errors.Is(err, ErrSSHAgentKeyBlob) {
			t.Errorf("%s off-curve point error = %v", test.name, err)
		}
		wrongPrefix := append([]byte(nil), test.blob...)
		wrongPrefix[pointOffset] = 2
		if _, err := NewSSHAgentIdentity(wrongPrefix); !errors.Is(err, ErrSSHAgentKeyBlob) {
			t.Errorf("%s compressed point error = %v", test.name, err)
		}
	}

	invalid := []struct {
		name string
		blob []byte
		want error
	}{
		{name: "empty", want: ErrSSHAgentKeyBlob},
		{name: "algorithm truncated", blob: []byte{0, 0, 0, 4, 's'}, want: ErrSSHAgentNestedTruncated},
		{name: "unknown algorithm", blob: sshAgentNestedString(nil, []byte("ssh-dss")), want: ErrSSHAgentKeyAlgorithm},
		{name: "ed25519 short", blob: sshAgentNestedED25519Key(make([]byte, 31)), want: ErrSSHAgentKeyBlob},
		{name: "ed25519 long", blob: sshAgentNestedED25519Key(make([]byte, 33)), want: ErrSSHAgentKeyBlob},
		{name: "ed25519 trailing", blob: append(ed25519, 0), want: ErrSSHAgentNestedTrailingData},
		{name: "rsa empty exponent", blob: sshAgentNestedRSAKey(nil, []byte{1}), want: ErrSSHAgentKeyBlob},
		{name: "rsa zero exponent", blob: sshAgentNestedRSAKey([]byte{0}, []byte{1}), want: ErrSSHAgentKeyBlob},
		{name: "rsa negative exponent", blob: sshAgentNestedRSAKey([]byte{0x80}, []byte{1}), want: ErrSSHAgentKeyBlob},
		{name: "rsa redundant zero", blob: sshAgentNestedRSAKey([]byte{0, 1}, []byte{1}), want: ErrSSHAgentKeyBlob},
		{name: "rsa empty modulus", blob: sshAgentNestedRSAKey([]byte{3}, nil), want: ErrSSHAgentKeyBlob},
		{name: "rsa negative modulus", blob: sshAgentNestedRSAKey([]byte{3}, []byte{0x80}), want: ErrSSHAgentKeyBlob},
	}
	for _, test := range invalid {
		if identity, err := NewSSHAgentIdentity(test.blob); !errors.Is(err, test.want) {
			identity.Wipe()
			t.Errorf("%s error = %v, want %v", test.name, err, test.want)
		}
	}
}

func TestSSHAgentNestedSignRequestStrictParsingAndPolicy(t *testing.T) {
	t.Parallel()

	ed25519 := sshAgentNestedED25519Key(bytes.Repeat([]byte{0x33}, 32))
	maxChallenge := bytes.Repeat([]byte{0x5a}, SSHAgentMaxChallengeBytes)
	for _, challenge := range [][]byte{nil, maxChallenge} {
		body := append(sshAgentNestedString(nil, ed25519), sshAgentNestedString(nil, challenge)...)
		body = appendSSHAgentUint32(body, 0)
		request, err := DecodeSSHAgentSignRequest(sshAgentNestedFrame(SSHAgentMessageSignRequest, body))
		if err != nil {
			t.Fatalf("challenge length %d: %v", len(challenge), err)
		}
		request.Wipe()
	}

	maxRSA := sshAgentNestedRSAKey([]byte{1, 0, 1}, append([]byte{1}, make([]byte, SSHAgentMaxKeyBlobBytes-23)...))
	if len(maxRSA) != SSHAgentMaxKeyBlobBytes {
		t.Fatalf("max RSA blob length = %d", len(maxRSA))
	}
	for _, flags := range []SSHAgentRSAFlags{SSHAgentRSAFlagSHA256, SSHAgentRSAFlagSHA512} {
		body := append(sshAgentNestedString(nil, maxRSA), sshAgentNestedString(nil, nil)...)
		body = appendSSHAgentUint32(body, uint32(flags))
		request, err := DecodeSSHAgentSignRequest(sshAgentNestedFrame(SSHAgentMessageSignRequest, body))
		if err != nil {
			t.Fatalf("max key flags %d: %v", flags, err)
		}
		request.Wipe()
	}

	requestBody := append(sshAgentNestedString(nil, ed25519), sshAgentNestedString(nil, []byte("challenge"))...)
	requestBody = appendSSHAgentUint32(requestBody, 0)
	validFrame := sshAgentNestedFrame(SSHAgentMessageSignRequest, requestBody)
	tests := []struct {
		name  string
		frame []byte
		want  error
	}{
		{name: "wrong request type", frame: sshAgentNestedFrame(SSHAgentMessageRequestIdentities, nil), want: ErrSSHAgentMessageDirection},
		{name: "response type", frame: sshAgentNestedFrame(SSHAgentMessageSignResponse, sshAgentNestedString(nil, nil)), want: ErrSSHAgentMessageDirection},
		{name: "forbidden operation", frame: sshAgentNestedFrame(SSHAgentMessageType(17), nil), want: ErrSSHAgentMessageType},
		{name: "outer truncation", frame: validFrame[:len(validFrame)-1], want: ErrSSHAgentFrameTruncated},
		{name: "outer trailing", frame: append(append([]byte(nil), validFrame...), 0), want: ErrSSHAgentFrameTrailingData},
		{name: "missing key length", frame: sshAgentNestedFrame(SSHAgentMessageSignRequest, nil), want: ErrSSHAgentNestedTruncated},
		{name: "key truncated", frame: sshAgentNestedFrame(SSHAgentMessageSignRequest, []byte{0, 0, 0, 1}), want: ErrSSHAgentNestedTruncated},
		{name: "missing challenge", frame: sshAgentNestedFrame(SSHAgentMessageSignRequest, sshAgentNestedString(nil, ed25519)), want: ErrSSHAgentNestedTruncated},
		{name: "missing flags", frame: sshAgentNestedFrame(SSHAgentMessageSignRequest, append(sshAgentNestedString(nil, ed25519), sshAgentNestedString(nil, nil)...)), want: ErrSSHAgentNestedTruncated},
		{name: "nested trailing", frame: sshAgentNestedFrame(SSHAgentMessageSignRequest, append(append([]byte(nil), requestBody...), 0)), want: ErrSSHAgentNestedTrailingData},
	}
	for _, test := range tests {
		request, err := DecodeSSHAgentSignRequest(test.frame)
		if request != nil || !errors.Is(err, test.want) {
			if request != nil {
				request.Wipe()
			}
			t.Errorf("%s = %#v, %v; want nil, %v", test.name, request, err, test.want)
		}
	}

	oversizedKey := make([]byte, SSHAgentMaxKeyBlobBytes+1)
	body := append(sshAgentNestedString(nil, oversizedKey), sshAgentNestedString(nil, nil)...)
	body = appendSSHAgentUint32(body, 0)
	if request, err := DecodeSSHAgentSignRequest(sshAgentNestedFrame(SSHAgentMessageSignRequest, body)); request != nil || !errors.Is(err, ErrSSHAgentKeyBlobLength) {
		t.Fatalf("oversized key = %#v, %v", request, err)
	}

	for _, flags := range []SSHAgentRSAFlags{0, 1, 6, 8} {
		body = append(sshAgentNestedString(nil, sshAgentNestedRSAKey([]byte{3}, []byte{1})), sshAgentNestedString(nil, nil)...)
		body = appendSSHAgentUint32(body, uint32(flags))
		if request, err := DecodeSSHAgentSignRequest(sshAgentNestedFrame(SSHAgentMessageSignRequest, body)); request != nil || !errors.Is(err, ErrSSHAgentFlags) {
			t.Errorf("RSA flags %d = %#v, %v", flags, request, err)
		}
	}
}

func TestSSHAgentNestedIdentitiesDecodeEncodeOrderAndComments(t *testing.T) {
	t.Parallel()

	first := sshAgentNestedED25519Key(bytes.Repeat([]byte{1}, 32))
	second := sshAgentNestedRSAKey([]byte{3}, []byte{1})
	body := appendSSHAgentUint32(nil, 2)
	body = appendSSHAgentString(body, first)
	body = appendSSHAgentString(body, []byte("discard-sensitive-first-comment"))
	body = appendSSHAgentString(body, second)
	body = appendSSHAgentString(body, []byte("discard-sensitive-second-comment"))
	identities, err := DecodeSSHAgentIdentitiesAnswer(sshAgentNestedFrame(SSHAgentMessageIdentitiesAnswer, body))
	if err != nil {
		t.Fatalf("DecodeSSHAgentIdentitiesAnswer(): %v", err)
	}
	defer WipeSSHAgentIdentities(identities)
	if len(identities) != 2 {
		t.Fatalf("identity count = %d", len(identities))
	}
	for index, want := range [][]byte{first, second} {
		got := identities[index].PublicKeyBlob()
		if !bytes.Equal(got, want) {
			t.Errorf("identity %d order changed", index)
		}
		WipeSSHAgentBytes(got)
	}

	encoded, err := EncodeSSHAgentIdentitiesAnswer(identities)
	if err != nil {
		t.Fatalf("EncodeSSHAgentIdentitiesAnswer(): %v", err)
	}
	defer WipeSSHAgentBytes(encoded)
	wantBody := appendSSHAgentUint32(nil, 2)
	wantBody = appendSSHAgentString(wantBody, first)
	wantBody = appendSSHAgentString(wantBody, nil)
	wantBody = appendSSHAgentString(wantBody, second)
	wantBody = appendSSHAgentString(wantBody, nil)
	wantFrame := sshAgentNestedFrame(SSHAgentMessageIdentitiesAnswer, wantBody)
	if !bytes.Equal(encoded, wantFrame) {
		t.Fatalf("encoded answer did not preserve order and empty comments")
	}

	empty, err := DecodeSSHAgentIdentitiesAnswer(sshAgentNestedFrame(SSHAgentMessageIdentitiesAnswer, []byte{0, 0, 0, 0}))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty identities = %#v, %v", empty, err)
	}
}

func TestSSHAgentNestedIdentityCountCommentAndFrameBounds(t *testing.T) {
	t.Parallel()

	key := sshAgentNestedED25519Key(bytes.Repeat([]byte{7}, 32))
	body := appendSSHAgentUint32(nil, SSHAgentMaxIdentities)
	for index := 0; index < SSHAgentMaxIdentities; index++ {
		body = appendSSHAgentString(body, key)
		body = appendSSHAgentString(body, nil)
	}
	identities, err := DecodeSSHAgentIdentitiesAnswer(sshAgentNestedFrame(SSHAgentMessageIdentitiesAnswer, body))
	if err != nil || len(identities) != SSHAgentMaxIdentities {
		t.Fatalf("max identities = %d, %v", len(identities), err)
	}
	WipeSSHAgentIdentities(identities)

	tooMany := sshAgentNestedFrame(SSHAgentMessageIdentitiesAnswer, appendSSHAgentUint32(nil, SSHAgentMaxIdentities+1))
	if identities, err := DecodeSSHAgentIdentitiesAnswer(tooMany); identities != nil || !errors.Is(err, ErrSSHAgentIdentityCount) {
		t.Fatalf("too many identities = %#v, %v", identities, err)
	}

	for _, commentLength := range []int{SSHAgentMaxCommentBytes, SSHAgentMaxCommentBytes + 1} {
		body = appendSSHAgentUint32(nil, 1)
		body = appendSSHAgentString(body, key)
		body = appendSSHAgentString(body, make([]byte, commentLength))
		identities, err := DecodeSSHAgentIdentitiesAnswer(sshAgentNestedFrame(SSHAgentMessageIdentitiesAnswer, body))
		if commentLength == SSHAgentMaxCommentBytes {
			if err != nil || len(identities) != 1 {
				t.Fatalf("max comment = %#v, %v", identities, err)
			}
			WipeSSHAgentIdentities(identities)
		} else if identities != nil || !errors.Is(err, ErrSSHAgentCommentLength) {
			t.Fatalf("plus-one comment = %#v, %v", identities, err)
		}
	}

	identity, err := NewSSHAgentIdentity(key)
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Wipe()
	tooLargeForFrame := make([]SSHAgentIdentity, SSHAgentMaxIdentities)
	largeRSA := sshAgentNestedRSAKey([]byte{3}, append([]byte{1}, make([]byte, 1020)...))
	for index := range tooLargeForFrame {
		tooLargeForFrame[index], err = NewSSHAgentIdentity(largeRSA)
		if err != nil {
			t.Fatal(err)
		}
	}
	defer WipeSSHAgentIdentities(tooLargeForFrame)
	if frame, err := EncodeSSHAgentIdentitiesAnswer(tooLargeForFrame); frame != nil || !errors.Is(err, ErrSSHAgentPayloadLength) {
		t.Fatalf("total frame bound = %d, %v", len(frame), err)
	}

	identity.Wipe()
	if frame, err := EncodeSSHAgentIdentitiesAnswer([]SSHAgentIdentity{identity}); frame != nil || !errors.Is(err, ErrSSHAgentKeyBlob) {
		t.Fatalf("wiped identity = %d, %v", len(frame), err)
	}
}

func TestSSHAgentNestedIdentitiesAnswerRejectsTruncationTrailingAndDirection(t *testing.T) {
	t.Parallel()

	key := sshAgentNestedED25519Key(make([]byte, 32))
	validBody := appendSSHAgentUint32(nil, 1)
	validBody = appendSSHAgentString(validBody, key)
	validBody = appendSSHAgentString(validBody, nil)
	validFrame := sshAgentNestedFrame(SSHAgentMessageIdentitiesAnswer, validBody)
	tests := []struct {
		name  string
		frame []byte
		want  error
	}{
		{name: "request direction", frame: sshAgentNestedFrame(SSHAgentMessageRequestIdentities, nil), want: ErrSSHAgentMessageDirection},
		{name: "sign response direction", frame: sshAgentNestedFrame(SSHAgentMessageSignResponse, sshAgentNestedString(nil, nil)), want: ErrSSHAgentMessageDirection},
		{name: "missing count", frame: sshAgentNestedFrame(SSHAgentMessageIdentitiesAnswer, nil), want: ErrSSHAgentNestedTruncated},
		{name: "missing key", frame: sshAgentNestedFrame(SSHAgentMessageIdentitiesAnswer, appendSSHAgentUint32(nil, 1)), want: ErrSSHAgentNestedTruncated},
		{name: "truncated key", frame: sshAgentNestedFrame(SSHAgentMessageIdentitiesAnswer, append(appendSSHAgentUint32(nil, 1), 0, 0, 0, 1)), want: ErrSSHAgentNestedTruncated},
		{name: "missing comment", frame: sshAgentNestedFrame(SSHAgentMessageIdentitiesAnswer, append(appendSSHAgentUint32(nil, 1), sshAgentNestedString(nil, key)...)), want: ErrSSHAgentNestedTruncated},
		{name: "truncated comment", frame: sshAgentNestedFrame(SSHAgentMessageIdentitiesAnswer, append(append(appendSSHAgentUint32(nil, 1), sshAgentNestedString(nil, key)...), 0, 0, 0, 1)), want: ErrSSHAgentNestedTruncated},
		{name: "nested trailing", frame: sshAgentNestedFrame(SSHAgentMessageIdentitiesAnswer, append(append([]byte(nil), validBody...), 0)), want: ErrSSHAgentNestedTrailingData},
		{name: "outer truncated", frame: validFrame[:len(validFrame)-1], want: ErrSSHAgentFrameTruncated},
		{name: "outer trailing", frame: append(append([]byte(nil), validFrame...), 0), want: ErrSSHAgentFrameTrailingData},
	}
	for _, test := range tests {
		identities, err := DecodeSSHAgentIdentitiesAnswer(test.frame)
		if identities != nil || !errors.Is(err, test.want) {
			WipeSSHAgentIdentities(identities)
			t.Errorf("%s = %#v, %v; want nil, %v", test.name, identities, err, test.want)
		}
	}

	oversizedKey := make([]byte, SSHAgentMaxKeyBlobBytes+1)
	body := appendSSHAgentUint32(nil, 1)
	body = appendSSHAgentString(body, oversizedKey)
	body = appendSSHAgentString(body, nil)
	if identities, err := DecodeSSHAgentIdentitiesAnswer(sshAgentNestedFrame(SSHAgentMessageIdentitiesAnswer, body)); identities != nil || !errors.Is(err, ErrSSHAgentKeyBlobLength) {
		WipeSSHAgentIdentities(identities)
		t.Fatalf("plus-one key = %#v, %v", identities, err)
	}
}

func TestSSHAgentNestedSignResponseCanonicalPolicyAndBounds(t *testing.T) {
	t.Parallel()

	ecdsaValue := appendSSHAgentString(nil, []byte{1})
	ecdsaValue = appendSSHAgentString(ecdsaValue, []byte{2})
	tests := []struct {
		algorithm SSHAgentSignatureAlgorithm
		value     []byte
	}{
		{SSHAgentSignatureAlgorithmED25519, bytes.Repeat([]byte{1}, 64)},
		{SSHAgentSignatureAlgorithmECDSANISTP256, ecdsaValue},
		{SSHAgentSignatureAlgorithmECDSANISTP384, ecdsaValue},
		{SSHAgentSignatureAlgorithmECDSANISTP521, ecdsaValue},
		{SSHAgentSignatureAlgorithmRSASHA256, []byte{1}},
		{SSHAgentSignatureAlgorithmRSASHA512, []byte{2}},
	}
	for _, test := range tests {
		signature, err := NewSSHAgentSignature(test.algorithm, test.value)
		if err != nil {
			t.Fatalf("NewSSHAgentSignature(%s): %v", test.algorithm, err)
		}
		frame, err := EncodeSSHAgentSignResponse(signature)
		if err != nil {
			signature.Wipe()
			t.Fatalf("EncodeSSHAgentSignResponse(%s): %v", test.algorithm, err)
		}
		decoded, err := DecodeSSHAgentSignResponse(frame)
		WipeSSHAgentBytes(frame)
		if err != nil {
			signature.Wipe()
			t.Fatalf("DecodeSSHAgentSignResponse(%s): %v", test.algorithm, err)
		}
		if decoded.Algorithm() != test.algorithm {
			t.Errorf("decoded algorithm = %s, want %s", decoded.Algorithm(), test.algorithm)
		}
		got := decoded.Signature()
		if !bytes.Equal(got, test.value) {
			t.Errorf("decoded %s signature changed", test.algorithm)
		}
		WipeSSHAgentBytes(got)
		decoded.Wipe()
		signature.Wipe()
	}

	rsaValueLength := SSHAgentMaxSignatureBytes - sshAgentNestedStringSize(len(SSHAgentSignatureAlgorithmRSASHA256)) - 4
	maxSignature, err := NewSSHAgentSignature(SSHAgentSignatureAlgorithmRSASHA256, bytes.Repeat([]byte{1}, rsaValueLength))
	if err != nil {
		t.Fatalf("max signature: %v", err)
	}
	frame, err := EncodeSSHAgentSignResponse(maxSignature)
	if err != nil {
		t.Fatalf("max signature encode: %v", err)
	}
	if metadata, err := ValidateSSHAgentOuterFrame(frame); err != nil || metadata.PayloadLength != 1+4+SSHAgentMaxSignatureBytes {
		t.Fatalf("max signature outer = %#v, %v", metadata, err)
	}
	WipeSSHAgentBytes(frame)
	maxSignature.Wipe()
	if signature, err := NewSSHAgentSignature(SSHAgentSignatureAlgorithmRSASHA256, bytes.Repeat([]byte{1}, rsaValueLength+1)); !errors.Is(err, ErrSSHAgentSignatureLength) {
		signature.Wipe()
		t.Fatalf("plus-one signature error = %v", err)
	}

	invalidECDSA := []byte{}
	invalidECDSA = appendSSHAgentString(invalidECDSA, nil)
	invalidECDSA = appendSSHAgentString(invalidECDSA, []byte{1})
	if signature, err := NewSSHAgentSignature(SSHAgentSignatureAlgorithmECDSANISTP256, invalidECDSA); !errors.Is(err, ErrSSHAgentSignatureBlob) {
		signature.Wipe()
		t.Fatalf("zero ECDSA mpint error = %v", err)
	}

	zero := SSHAgentSignature{}
	if frame, err := EncodeSSHAgentSignResponse(zero); frame != nil || !errors.Is(err, ErrSSHAgentSignatureAlgorithm) {
		t.Fatalf("zero signature = %d, %v", len(frame), err)
	}
	valid, err := NewSSHAgentSignature(SSHAgentSignatureAlgorithmED25519, make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	valid.Wipe()
	if frame, err := EncodeSSHAgentSignResponse(valid); frame != nil || !errors.Is(err, ErrSSHAgentSignatureAlgorithm) {
		t.Fatalf("wiped signature = %d, %v", len(frame), err)
	}
}

func TestSSHAgentNestedSignatureResponseRejectsTruncationTrailingAndDirection(t *testing.T) {
	t.Parallel()

	signatureBlob := sshAgentNestedSignatureBlob(SSHAgentSignatureAlgorithmED25519, make([]byte, 64))
	validBody := sshAgentNestedString(nil, signatureBlob)
	validFrame := sshAgentNestedFrame(SSHAgentMessageSignResponse, validBody)
	tests := []struct {
		name  string
		frame []byte
		want  error
	}{
		{name: "request direction", frame: sshAgentNestedFrame(SSHAgentMessageSignRequest, nil), want: ErrSSHAgentMessageDirection},
		{name: "failure direction", frame: EncodeSSHAgentFailure(), want: ErrSSHAgentMessageDirection},
		{name: "outer truncated", frame: validFrame[:len(validFrame)-1], want: ErrSSHAgentFrameTruncated},
		{name: "outer trailing", frame: append(append([]byte(nil), validFrame...), 0), want: ErrSSHAgentFrameTrailingData},
		{name: "missing signature string", frame: sshAgentNestedFrame(SSHAgentMessageSignResponse, nil), want: ErrSSHAgentNestedTruncated},
		{name: "truncated signature string", frame: sshAgentNestedFrame(SSHAgentMessageSignResponse, []byte{0, 0, 0, 1}), want: ErrSSHAgentNestedTruncated},
		{name: "response trailing", frame: sshAgentNestedFrame(SSHAgentMessageSignResponse, append(append([]byte(nil), validBody...), 0)), want: ErrSSHAgentNestedTrailingData},
		{name: "signature blob trailing", frame: sshAgentNestedFrame(SSHAgentMessageSignResponse, sshAgentNestedString(nil, append(signatureBlob, 0))), want: ErrSSHAgentNestedTrailingData},
	}
	for _, test := range tests {
		signature, err := DecodeSSHAgentSignResponse(test.frame)
		if signature != nil || !errors.Is(err, test.want) {
			if signature != nil {
				signature.Wipe()
			}
			t.Errorf("%s = %#v, %v; want nil, %v", test.name, signature, err, test.want)
		}
	}
}

func TestSSHAgentNestedExactSignaturePolicy(t *testing.T) {
	t.Parallel()

	requestFor := func(key []byte, flags SSHAgentRSAFlags) *SSHAgentSignRequest {
		body := append(sshAgentNestedString(nil, key), sshAgentNestedString(nil, nil)...)
		body = appendSSHAgentUint32(body, uint32(flags))
		request, err := DecodeSSHAgentSignRequest(sshAgentNestedFrame(SSHAgentMessageSignRequest, body))
		if err != nil {
			t.Fatalf("DecodeSSHAgentSignRequest(): %v", err)
		}
		return request
	}
	edRequest := requestFor(sshAgentNestedED25519Key(make([]byte, 32)), 0)
	defer edRequest.Wipe()
	edSignature, _ := NewSSHAgentSignature(SSHAgentSignatureAlgorithmED25519, make([]byte, 64))
	defer edSignature.Wipe()
	if err := ValidateSSHAgentSignatureForRequest(edRequest, edSignature); err != nil {
		t.Fatalf("ed25519 policy: %v", err)
	}

	rsaRequest := requestFor(sshAgentNestedRSAKey([]byte{3}, []byte{1}), SSHAgentRSAFlagSHA256)
	defer rsaRequest.Wipe()
	rsa256, _ := NewSSHAgentSignature(SSHAgentSignatureAlgorithmRSASHA256, []byte{1})
	defer rsa256.Wipe()
	rsa512, _ := NewSSHAgentSignature(SSHAgentSignatureAlgorithmRSASHA512, []byte{1})
	defer rsa512.Wipe()
	if err := ValidateSSHAgentSignatureForRequest(rsaRequest, rsa256); err != nil {
		t.Fatalf("RSA SHA-256 policy: %v", err)
	}
	if err := ValidateSSHAgentSignatureForRequest(rsaRequest, rsa512); !errors.Is(err, ErrSSHAgentSignaturePolicy) {
		t.Fatalf("RSA mismatch error = %v", err)
	}
	if err := ValidateSSHAgentSignatureForRequest(nil, rsa256); !errors.Is(err, ErrSSHAgentSignaturePolicy) {
		t.Fatalf("nil request error = %v", err)
	}
	rsaRequest.Wipe()
	if err := ValidateSSHAgentSignatureForRequest(rsaRequest, rsa256); !errors.Is(err, ErrSSHAgentKeyAlgorithm) {
		t.Fatalf("wiped request error = %v", err)
	}
}

func TestSSHAgentNestedFailureAndIdentitiesRequestExactFrames(t *testing.T) {
	t.Parallel()

	request := sshAgentNestedFrame(SSHAgentMessageRequestIdentities, nil)
	if err := ValidateSSHAgentIdentitiesRequest(request); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		frame []byte
		want  error
	}{
		{sshAgentNestedFrame(SSHAgentMessageSignRequest, nil), ErrSSHAgentMessageDirection},
		{sshAgentNestedFrame(SSHAgentMessageIdentitiesAnswer, []byte{0, 0, 0, 0}), ErrSSHAgentMessageDirection},
		{append(append([]byte(nil), request...), 0), ErrSSHAgentFrameTrailingData},
		{request[:len(request)-1], ErrSSHAgentFrameTruncated},
	} {
		if err := ValidateSSHAgentIdentitiesRequest(test.frame); !errors.Is(err, test.want) {
			t.Errorf("ValidateSSHAgentIdentitiesRequest() = %v, want %v", err, test.want)
		}
	}
	failure := EncodeSSHAgentFailure()
	if !bytes.Equal(failure, []byte{0, 0, 0, 1, 5}) {
		t.Fatalf("failure frame = %v", failure)
	}
	metadata, err := ValidateSSHAgentOuterFrame(failure)
	if err != nil || metadata.MessageType != SSHAgentMessageFailure {
		t.Fatalf("failure metadata = %#v, %v", metadata, err)
	}
}

func TestSSHAgentNestedForbiddenOperations(t *testing.T) {
	t.Parallel()

	forbidden := []SSHAgentMessageType{
		1, 3, // protocol-v1 request/challenge
		6, 7, 8, 9, 10, // protocol-v1 responses and mutation operations
		15, 16, 17, 18, 19, // add/remove/remove-all
		20, 21, // smartcard add/remove
		22, 23, // lock/unlock
		24, 25, 26, // constrained mutation operations
		27, 28, // extension request/failure
		255,
	}
	for _, messageType := range forbidden {
		frame := sshAgentNestedFrame(messageType, nil)
		if err := ValidateSSHAgentIdentitiesRequest(frame); !errors.Is(err, ErrSSHAgentMessageType) {
			t.Errorf("forbidden type %d error = %v", messageType, err)
		}
		if request, err := DecodeSSHAgentSignRequest(frame); request != nil || !errors.Is(err, ErrSSHAgentMessageType) {
			if request != nil {
				request.Wipe()
			}
			t.Errorf("forbidden sign type %d = %#v, %v", messageType, request, err)
		}
	}
}

func TestSSHAgentNestedFingerprintVectorsAndOpacity(t *testing.T) {
	t.Parallel()

	key := sshAgentNestedED25519Key([]byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	})
	digest := sha256.Sum256(key)
	canonical := "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
	const fixedVector = "SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA"
	if canonical != fixedVector {
		t.Fatalf("independent fingerprint vector = %q, want %q", canonical, fixedVector)
	}
	derived, err := DeriveSSHAgentKeyFingerprint(key)
	if err != nil {
		t.Fatal(err)
	}
	defer derived.Wipe()
	parsed, err := ParseSSHAgentKeyFingerprint(canonical)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Wipe()
	if !derived.Equal(parsed) || !parsed.Equal(derived) {
		t.Fatal("derived fingerprint does not match canonical vector")
	}
	otherKey := append([]byte(nil), key...)
	otherKey[len(otherKey)-1] ^= 1
	other, err := DeriveSSHAgentKeyFingerprint(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Wipe()
	if derived.Equal(other) || derived.Equal(SSHAgentKeyFingerprint{}) {
		t.Fatal("fingerprint equality accepted a distinct or invalid value")
	}

	bad := []string{
		"", strings.ToLower(canonical[:7]) + canonical[7:], canonical + "=",
		"SHA256:" + base64.RawURLEncoding.EncodeToString(digest[:]),
		"SHA256:" + strings.Repeat("A", 42),
		"SHA256:" + strings.Repeat("A", 44),
		"SHA256:" + strings.Repeat("/", 43),
	}
	for _, value := range bad {
		if fingerprint, err := ParseSSHAgentKeyFingerprint(value); !errors.Is(err, ErrSSHAgentFingerprint) {
			fingerprint.Wipe()
			t.Errorf("ParseSSHAgentKeyFingerprint(%q) error = %v", value, err)
		}
	}
	for _, rendered := range []string{
		fmt.Sprint(derived), fmt.Sprintf("%#v", derived), fmt.Sprintf("%x", derived), fmt.Sprintf("%q", derived),
	} {
		if strings.Contains(rendered, canonical) || strings.Contains(rendered, canonical[7:]) {
			t.Fatalf("fingerprint leaked through formatting: %q", rendered)
		}
	}
}

func TestSSHAgentNestedOwnershipWipeAndSerializationDenial(t *testing.T) {
	key := sshAgentNestedED25519Key(bytes.Repeat([]byte{0x71}, 32))
	challenge := []byte("wipe-sensitive-challenge")
	body := append(sshAgentNestedString(nil, key), sshAgentNestedString(nil, challenge)...)
	body = appendSSHAgentUint32(body, 0)
	frame := sshAgentNestedFrame(SSHAgentMessageSignRequest, body)
	request, err := DecodeSSHAgentSignRequest(frame)
	if err != nil {
		t.Fatal(err)
	}
	for index := range frame {
		frame[index] ^= 0xff
	}
	keyCopy := request.PublicKeyBlob()
	challengeCopy := request.Challenge()
	keyCopy[0] ^= 0xff
	challengeCopy[0] ^= 0xff
	if bytes.Equal(keyCopy, request.keyBlob) || bytes.Equal(challengeCopy, request.challenge) {
		t.Fatal("accessor returned an aliased buffer")
	}
	WipeSSHAgentBytes(keyCopy)
	WipeSSHAgentBytes(challengeCopy)
	requestKeyBacking := request.keyBlob
	requestChallengeBacking := request.challenge
	request.Wipe()
	request.Wipe()
	if request.keyBlob != nil || request.challenge != nil || request.keyAlgorithm != "" || request.flags != 0 ||
		!allSSHAgentBytesZero(requestKeyBacking) || !allSSHAgentBytesZero(requestChallengeBacking) {
		t.Fatal("request wipe did not destroy and clear owned buffers")
	}

	identity, err := NewSSHAgentIdentity(key)
	if err != nil {
		t.Fatal(err)
	}
	identityBacking := identity.keyBlob
	identity.Wipe()
	if identity.keyBlob != nil || identity.keyAlgorithm != "" || !allSSHAgentBytesZero(identityBacking) {
		t.Fatal("identity wipe did not destroy and clear owned buffer")
	}

	signature, err := NewSSHAgentSignature(SSHAgentSignatureAlgorithmED25519, bytes.Repeat([]byte{0x62}, 64))
	if err != nil {
		t.Fatal(err)
	}
	signatureBacking := signature.signature
	signature.Wipe()
	if signature.signature != nil || signature.algorithm != "" || !allSSHAgentBytesZero(signatureBacking) {
		t.Fatal("signature wipe did not destroy and clear owned buffer")
	}

	values := []any{
		request,
		SSHAgentIdentity{},
		SSHAgentSignature{},
		SSHAgentKeyFingerprint{},
	}
	for _, value := range values {
		payload, err := json.Marshal(value)
		if payload != nil || !errors.Is(err, ErrSSHAgentNestedSerialization) {
			t.Errorf("json.Marshal(%T) = %q, %v", value, payload, err)
		}
	}

	nonzeroIdentity, _ := NewSSHAgentIdentity(key)
	defer nonzeroIdentity.Wipe()
	before := nonzeroIdentity.PublicKeyBlob()
	if err := nonzeroIdentity.UnmarshalJSON([]byte(`{"key":"sensitive"}`)); !errors.Is(err, ErrSSHAgentNestedSerialization) {
		t.Fatalf("UnmarshalJSON() = %v", err)
	}
	if err := nonzeroIdentity.UnmarshalText([]byte("sensitive")); !errors.Is(err, ErrSSHAgentNestedSerialization) {
		t.Fatalf("UnmarshalText() = %v", err)
	}
	after := nonzeroIdentity.PublicKeyBlob()
	if !bytes.Equal(before, after) {
		t.Fatal("denied unmarshal mutated identity")
	}
	WipeSSHAgentBytes(before)
	WipeSSHAgentBytes(after)

	canary := "wipe-sensitive-challenge"
	for _, rendered := range []string{
		fmt.Sprint(request), fmt.Sprintf("%#v", request), fmt.Sprintf("%x", request), fmt.Sprintf("%q", request),
	} {
		if strings.Contains(rendered, canary) {
			t.Fatalf("request leaked through formatting: %q", rendered)
		}
	}
}

func TestSSHAgentNestedDeniedUnmarshalDoesNotMutateOwnedValues(t *testing.T) {
	key := sshAgentNestedED25519Key(bytes.Repeat([]byte{0x31}, 32))
	body := append(sshAgentNestedString(nil, key), sshAgentNestedString(nil, []byte("unmarshal-sensitive-challenge"))...)
	body = appendSSHAgentUint32(body, 0)
	request, err := DecodeSSHAgentSignRequest(sshAgentNestedFrame(SSHAgentMessageSignRequest, body))
	if err != nil {
		t.Fatal(err)
	}
	defer request.Wipe()
	signature, err := NewSSHAgentSignature(SSHAgentSignatureAlgorithmED25519, bytes.Repeat([]byte{0x41}, 64))
	if err != nil {
		t.Fatal(err)
	}
	defer signature.Wipe()
	identity, err := NewSSHAgentIdentity(key)
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Wipe()
	fingerprint, err := DeriveSSHAgentKeyFingerprint(key)
	if err != nil {
		t.Fatal(err)
	}
	defer fingerprint.Wipe()

	requestKeyBefore := request.PublicKeyBlob()
	requestChallengeBefore := request.Challenge()
	signatureBefore := signature.Signature()
	identityBefore := identity.PublicKeyBlob()
	fingerprintBefore := fingerprint
	defer WipeSSHAgentBytes(requestKeyBefore)
	defer WipeSSHAgentBytes(requestChallengeBefore)
	defer WipeSSHAgentBytes(signatureBefore)
	defer WipeSSHAgentBytes(identityBefore)

	for _, denied := range []func() error{
		func() error { return request.UnmarshalJSON([]byte(`{"challenge":"changed"}`)) },
		func() error { return request.UnmarshalText([]byte("changed")) },
		func() error { return request.UnmarshalBinary([]byte("changed")) },
		func() error { return identity.UnmarshalJSON([]byte(`{"key":"changed"}`)) },
		func() error { return identity.UnmarshalText([]byte("changed")) },
		func() error { return identity.UnmarshalBinary([]byte("changed")) },
		func() error { return signature.UnmarshalJSON([]byte(`{"signature":"changed"}`)) },
		func() error { return signature.UnmarshalText([]byte("changed")) },
		func() error { return signature.UnmarshalBinary([]byte("changed")) },
		func() error { return fingerprint.UnmarshalJSON([]byte(`{"digest":"changed"}`)) },
		func() error { return fingerprint.UnmarshalText([]byte("changed")) },
		func() error { return fingerprint.UnmarshalBinary([]byte("changed")) },
	} {
		if err := denied(); !errors.Is(err, ErrSSHAgentNestedSerialization) {
			t.Errorf("denied unmarshal error = %v", err)
		}
	}
	requestKeyAfter := request.PublicKeyBlob()
	requestChallengeAfter := request.Challenge()
	signatureAfter := signature.Signature()
	identityAfter := identity.PublicKeyBlob()
	defer WipeSSHAgentBytes(requestKeyAfter)
	defer WipeSSHAgentBytes(requestChallengeAfter)
	defer WipeSSHAgentBytes(signatureAfter)
	defer WipeSSHAgentBytes(identityAfter)
	if !bytes.Equal(requestKeyBefore, requestKeyAfter) || !bytes.Equal(requestChallengeBefore, requestChallengeAfter) ||
		!bytes.Equal(signatureBefore, signatureAfter) || !bytes.Equal(identityBefore, identityAfter) ||
		!fingerprint.Equal(fingerprintBefore) {
		t.Fatal("denied unmarshal mutated an owned value")
	}
	fingerprintBefore.Wipe()
}

func TestSSHAgentNestedErrorsAndFormattingAreOpaque(t *testing.T) {
	canary := "nested-sensitive-canary"
	public := make([]byte, 32)
	copy(public, canary)
	key := sshAgentNestedED25519Key(public)
	body := append(sshAgentNestedString(nil, key), sshAgentNestedString(nil, []byte(canary))...)
	body = appendSSHAgentUint32(body, 0)
	request, err := DecodeSSHAgentSignRequest(sshAgentNestedFrame(SSHAgentMessageSignRequest, body))
	if err != nil {
		t.Fatal(err)
	}
	defer request.Wipe()
	identity, err := NewSSHAgentIdentity(key)
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Wipe()
	signatureBytes := make([]byte, 64)
	copy(signatureBytes, canary)
	signature, err := NewSSHAgentSignature(SSHAgentSignatureAlgorithmED25519, signatureBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer signature.Wipe()
	fingerprint, err := DeriveSSHAgentKeyFingerprint(key)
	if err != nil {
		t.Fatal(err)
	}
	defer fingerprint.Wipe()

	for _, value := range []any{request, identity, signature, fingerprint} {
		for _, rendered := range []string{
			fmt.Sprint(value), fmt.Sprintf("%v", value), fmt.Sprintf("%#v", value),
			fmt.Sprintf("%s", value), fmt.Sprintf("%q", value), fmt.Sprintf("%x", value),
		} {
			if strings.Contains(rendered, canary) {
				t.Fatalf("%T leaked through formatting: %q", value, rendered)
			}
		}
		jsonMarshaler := value.(interface{ MarshalJSON() ([]byte, error) })
		if payload, err := jsonMarshaler.MarshalJSON(); payload != nil || !errors.Is(err, ErrSSHAgentNestedSerialization) {
			t.Errorf("%T MarshalJSON = %q, %v", value, payload, err)
		}
		textMarshaler := value.(interface{ MarshalText() ([]byte, error) })
		if payload, err := textMarshaler.MarshalText(); payload != nil || !errors.Is(err, ErrSSHAgentNestedSerialization) {
			t.Errorf("%T MarshalText = %q, %v", value, payload, err)
		}
		binaryMarshaler := value.(interface{ MarshalBinary() ([]byte, error) })
		if payload, err := binaryMarshaler.MarshalBinary(); payload != nil || !errors.Is(err, ErrSSHAgentNestedSerialization) {
			t.Errorf("%T MarshalBinary = %q, %v", value, payload, err)
		}
	}

	invalid := sshAgentNestedFrame(SSHAgentMessageType(17), []byte(canary))
	if err := ValidateSSHAgentIdentitiesRequest(invalid); !errors.Is(err, ErrSSHAgentMessageType) {
		t.Fatalf("invalid message error = %v", err)
	} else {
		for _, rendered := range []string{err.Error(), fmt.Sprint(err), fmt.Sprintf("%#v", err)} {
			if strings.Contains(rendered, canary) {
				t.Fatalf("error leaked body: %q", rendered)
			}
		}
	}
}

func TestSSHAgentNestedProductionBoundary(t *testing.T) {
	t.Parallel()

	matches, err := filepath.Glob("ssh_agent_nested*.go")
	if err != nil {
		t.Fatal(err)
	}
	production := make([]string, 0, len(matches))
	for _, path := range matches {
		if !strings.HasSuffix(path, "_test.go") {
			production = append(production, filepath.Clean(path))
		}
	}
	if len(production) != 1 || production[0] != "ssh_agent_nested.go" {
		t.Fatalf("nested codec production scope = %v; review and extend the exact-file guard before adding files", production)
	}

	source, err := os.ReadFile(production[0])
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), production[0], source, 0)
	if err != nil {
		t.Fatal(err)
	}
	allowedImports := map[string]bool{
		"crypto/elliptic": true,
		"crypto/sha256":   true,
		"crypto/subtle":   true,
		"encoding/base64": true,
		"encoding/binary": true,
		"errors":          true,
		"fmt":             true,
		"runtime":         true,
	}
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if imported.Name != nil || !allowedImports[path] {
			t.Errorf("ssh_agent_nested.go imports %q; nested codec permits only its reviewed pure standard-library set", path)
		}
	}
	if len(file.Imports) != len(allowedImports) {
		t.Errorf("ssh_agent_nested.go import count = %d, want exact reviewed set of %d", len(file.Imports), len(allowedImports))
	}

	allowedByteSliceFields := map[string]bool{
		"SSHAgentSignRequest.keyBlob":   true,
		"SSHAgentSignRequest.challenge": true,
		"SSHAgentIdentity.keyBlob":      true,
		"SSHAgentSignature.signature":   true,
		"sshAgentNestedReader.data":     true,
	}
	forbiddenDeclarations := map[string]bool{
		"SSHAgentPayload":       true,
		"SSHAgentRawMessage":    true,
		"EncodeSSHAgentMessage": true,
		"DecodeSSHAgentMessage": true,
	}
	forbiddenLiveIdentifiers := map[string]bool{
		"Dial":           true,
		"DialContext":    true,
		"Listen":         true,
		"ListenUnix":     true,
		"SCM_RIGHTS":     true,
		"Socket":         true,
		"Socketpair":     true,
		"Command":        true,
		"CommandContext": true,
	}
	for _, declaration := range file.Decls {
		switch typed := declaration.(type) {
		case *ast.FuncDecl:
			if forbiddenDeclarations[typed.Name.Name] {
				t.Errorf("ssh_agent_nested.go declares generic raw API %s", typed.Name.Name)
			}
		case *ast.GenDecl:
			if typed.Tok != token.TYPE {
				continue
			}
			for _, specification := range typed.Specs {
				typeSpec := specification.(*ast.TypeSpec)
				if forbiddenDeclarations[typeSpec.Name.Name] {
					t.Errorf("ssh_agent_nested.go declares generic raw owner %s", typeSpec.Name.Name)
				}
				structure, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, field := range structure.Fields.List {
					if _, ok := field.Type.(*ast.MapType); ok {
						t.Errorf("%s has generic map owner", typeSpec.Name.Name)
					}
					if _, ok := field.Type.(*ast.InterfaceType); ok {
						t.Errorf("%s has generic interface owner", typeSpec.Name.Name)
					}
					for _, name := range field.Names {
						if name.IsExported() {
							switch field.Type.(type) {
							case *ast.ArrayType:
								t.Errorf("%s.%s exports a slice/array owner", typeSpec.Name.Name, name.Name)
							case *ast.Ident:
								if field.Type.(*ast.Ident).Name == "string" {
									t.Errorf("%s.%s exports a string owner", typeSpec.Name.Name, name.Name)
								}
							}
						}
						array, ok := field.Type.(*ast.ArrayType)
						if ok && array.Len == nil {
							key := typeSpec.Name.Name + "." + name.Name
							if !allowedByteSliceFields[key] {
								t.Errorf("%s adds an unreviewed slice owner", key)
							}
						}
					}
				}
			}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.MapType:
			t.Error("ssh_agent_nested.go contains a generic map type")
		case *ast.InterfaceType:
			t.Error("ssh_agent_nested.go contains a generic interface type")
		case *ast.SelectorExpr:
			if forbiddenLiveIdentifiers[typed.Sel.Name] {
				t.Errorf("ssh_agent_nested.go contains forbidden live behavior %s", typed.Sel.Name)
			}
		case *ast.Ident:
			if forbiddenLiveIdentifiers[typed.Name] {
				t.Errorf("ssh_agent_nested.go contains forbidden live identifier %s", typed.Name)
			}
		}
		return true
	})
}

func sshAgentNestedECDSAKeys() []struct {
	name        string
	algorithm   SSHAgentKeyAlgorithm
	blob        []byte
	pointLength int
} {
	tests := []struct {
		name      string
		algorithm SSHAgentKeyAlgorithm
		curveName string
		curve     elliptic.Curve
	}{
		{name: "ecdsa p256", algorithm: SSHAgentKeyAlgorithmECDSANISTP256, curveName: "nistp256", curve: elliptic.P256()},
		{name: "ecdsa p384", algorithm: SSHAgentKeyAlgorithmECDSANISTP384, curveName: "nistp384", curve: elliptic.P384()},
		{name: "ecdsa p521", algorithm: SSHAgentKeyAlgorithmECDSANISTP521, curveName: "nistp521", curve: elliptic.P521()},
	}
	result := make([]struct {
		name        string
		algorithm   SSHAgentKeyAlgorithm
		blob        []byte
		pointLength int
	}, 0, len(tests))
	for _, test := range tests {
		x, y := test.curve.ScalarBaseMult([]byte{1})
		// Test fixtures encode the ECDSA public key in the SSH-required SEC1 form.
		//nolint:staticcheck // crypto/ecdh cannot represent the ECDSA fixture contract.
		point := elliptic.Marshal(test.curve, x, y)
		blob := sshAgentNestedString(nil, []byte(test.algorithm))
		blob = sshAgentNestedString(blob, []byte(test.curveName))
		blob = sshAgentNestedString(blob, point)
		result = append(result, struct {
			name        string
			algorithm   SSHAgentKeyAlgorithm
			blob        []byte
			pointLength int
		}{name: test.name, algorithm: test.algorithm, blob: blob, pointLength: len(point)})
	}
	return result
}

func sshAgentNestedRSAKey(exponent, modulus []byte) []byte {
	blob := sshAgentNestedString(nil, []byte(SSHAgentKeyAlgorithmRSA))
	blob = sshAgentNestedString(blob, exponent)
	return sshAgentNestedString(blob, modulus)
}

func sshAgentNestedSignatureBlob(algorithm SSHAgentSignatureAlgorithm, signature []byte) []byte {
	blob := sshAgentNestedString(nil, []byte(algorithm))
	return sshAgentNestedString(blob, signature)
}

func allSSHAgentBytesZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

func sshAgentNestedED25519Key(public []byte) []byte {
	return sshAgentNestedString(sshAgentNestedString(nil, []byte(SSHAgentKeyAlgorithmED25519)), public)
}

func sshAgentNestedString(dst, value []byte) []byte {
	length := uint32(len(value))
	dst = append(dst, byte(length>>24), byte(length>>16), byte(length>>8), byte(length))
	return append(dst, value...)
}

func sshAgentNestedFrame(messageType SSHAgentMessageType, body []byte) []byte {
	payloadLength := uint32(1 + len(body))
	frame := []byte{byte(payloadLength >> 24), byte(payloadLength >> 16), byte(payloadLength >> 8), byte(payloadLength), byte(messageType)}
	return append(frame, body...)
}
