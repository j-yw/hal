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

func TestHelperPrepareBodiesExactVectorsHashAndRoundTrip(t *testing.T) {
	t.Parallel()

	fileBytes := []byte("private-file")
	fileDigest := sha256.Sum256(fileBytes)
	bindings := []HelperBindingManifestRecord{
		{BindingID: "http", Mode: DeliveryModeHTTPProxy},
		{BindingID: "file", Mode: DeliveryModeFileTmpfs, TargetPath: "credentials/token", DeclaredFileBytes: uint32(len(fileBytes)), FileSHA256: fileDigest},
		{BindingID: "ssh", Mode: DeliveryModeSSHAgent},
	}
	begin := HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: -2, Bindings: bindings}
	wantBegin := mustHexBytes(t,
		"0000000000000001fffffffffffffffe0003"+
			"00046874747001000000000000"+strings.Repeat("00", 32)+
			"000466696c6502001163726564656e7469616c732f746f6b656e0000000c"+hex.EncodeToString(fileDigest[:])+
			"000373736803000000000000"+strings.Repeat("00", 32))
	encodedBegin, err := EncodeHelperPrepareBeginBody(begin)
	if err != nil {
		t.Fatalf("EncodeHelperPrepareBeginBody: %v", err)
	}
	if !bytes.Equal(encodedBegin, wantBegin) {
		t.Fatalf("prepare_begin = %x\nwant          = %x", encodedBegin, wantBegin)
	}
	decodedBegin, err := DecodeHelperPrepareBeginBody(encodedBegin)
	if err != nil {
		t.Fatalf("DecodeHelperPrepareBeginBody: %v", err)
	}
	if !reflect.DeepEqual(decodedBegin, begin) {
		t.Fatalf("prepare_begin round trip = %#v, want %#v", decodedBegin, begin)
	}

	wantManifest := sha256.Sum256(append(
		append([]byte{0, byte(len("hal/l8/guest-helper/manifest/v1"))}, "hal/l8/guest-helper/manifest/v1"...),
		wantBegin[16:]...,
	))
	manifest, err := ComputeHelperManifestSHA256(bindings)
	if err != nil {
		t.Fatalf("ComputeHelperManifestSHA256: %v", err)
	}
	if manifest != wantManifest {
		t.Fatalf("manifest digest = %x, want %x", manifest, wantManifest)
	}

	fileBody, err := NewHelperPrepareFileBody(1, 1, fileDigest, fileBytes)
	if err != nil {
		t.Fatalf("NewHelperPrepareFileBody: %v", err)
	}
	defer fileBody.Wipe()
	wantFile := make([]byte, 46+len(fileBytes))
	binary.BigEndian.PutUint64(wantFile[0:8], 1)
	binary.BigEndian.PutUint16(wantFile[8:10], 1)
	binary.BigEndian.PutUint32(wantFile[10:14], uint32(len(fileBytes)))
	copy(wantFile[14:46], fileDigest[:])
	copy(wantFile[46:], fileBytes)
	encodedFile, err := EncodeHelperPrepareFileBody(fileBody)
	if err != nil {
		t.Fatalf("EncodeHelperPrepareFileBody: %v", err)
	}
	if !bytes.Equal(encodedFile, wantFile) {
		t.Fatalf("prepare_file = %x, want %x", encodedFile, wantFile)
	}
	decodedFile, err := DecodeHelperPrepareFileBody(encodedFile)
	if err != nil {
		t.Fatalf("DecodeHelperPrepareFileBody: %v", err)
	}
	defer decodedFile.Wipe()
	if decodedFile.Revision() != 1 || decodedFile.BindingIndex() != 1 || decodedFile.FileLength() != uint32(len(fileBytes)) || decodedFile.FileSHA256() != fileDigest {
		t.Fatalf("prepare_file metadata = %#v", decodedFile)
	}
	gotPrivate := make([]byte, len(fileBytes))
	if n, err := decodedFile.CopyPrivateBytes(gotPrivate); err != nil || n != len(fileBytes) || !bytes.Equal(gotPrivate, fileBytes) {
		t.Fatalf("CopyPrivateBytes = %q, %d, %v", gotPrivate, n, err)
	}

	commit := HelperPrepareCommitBody{Revision: 1, ManifestSHA256: manifest}
	wantCommit := append([]byte{0, 0, 0, 0, 0, 0, 0, 1}, manifest[:]...)
	encodedCommit, err := EncodeHelperPrepareCommitBody(commit)
	if err != nil {
		t.Fatalf("EncodeHelperPrepareCommitBody: %v", err)
	}
	if !bytes.Equal(encodedCommit, wantCommit) {
		t.Fatalf("prepare_commit = %x, want %x", encodedCommit, wantCommit)
	}
	decodedCommit, err := DecodeHelperPrepareCommitBody(encodedCommit)
	if err != nil || decodedCommit != commit {
		t.Fatalf("prepare_commit round trip = %#v, %v", decodedCommit, err)
	}
}

func TestHelperPrepareManifestPreservesIntentionalOrder(t *testing.T) {
	t.Parallel()
	first := []HelperBindingManifestRecord{
		{BindingID: "zulu", Mode: DeliveryModeSSHAgent},
		{BindingID: "alpha", Mode: DeliveryModeHTTPProxy},
	}
	second := []HelperBindingManifestRecord{first[1], first[0]}
	firstWire, err := EncodeHelperPrepareBeginBody(HelperPrepareBeginBody{Revision: 1, Bindings: first})
	if err != nil {
		t.Fatal(err)
	}
	secondWire, err := EncodeHelperPrepareBeginBody(HelperPrepareBeginBody{Revision: 1, Bindings: second})
	if err != nil {
		t.Fatal(err)
	}
	firstHash, err := ComputeHelperManifestSHA256(first)
	if err != nil {
		t.Fatal(err)
	}
	secondHash, err := ComputeHelperManifestSHA256(second)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstWire, secondWire) || firstHash == secondHash {
		t.Fatal("manifest order did not affect canonical encoding and digest")
	}
	decoded, err := DecodeHelperPrepareBeginBody(firstWire)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Bindings[0].BindingID != "zulu" || decoded.Bindings[1].BindingID != "alpha" {
		t.Fatalf("decoder reordered manifest: %#v", decoded.Bindings)
	}
}

func TestHelperPrepareBeginBoundsModeRulesAndOwnership(t *testing.T) {
	t.Parallel()
	fileBytes := []byte("x")
	digest := sha256.Sum256(fileBytes)
	validFile := HelperBindingManifestRecord{BindingID: "file", Mode: DeliveryModeFileTmpfs, TargetPath: "a/b", DeclaredFileBytes: 1, FileSHA256: digest}
	valid := HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: -1, Bindings: []HelperBindingManifestRecord{validFile}}
	wire, err := EncodeHelperPrepareBeginBody(valid)
	if err != nil {
		t.Fatal(err)
	}
	valid.Bindings[0].BindingID = "mutated"
	decoded, err := DecodeHelperPrepareBeginBody(wire)
	if err != nil {
		t.Fatal(err)
	}
	for index := range wire {
		wire[index] = 0xff
	}
	if decoded.Bindings[0].BindingID != "file" || decoded.Bindings[0].TargetPath != "a/b" || decoded.ExpiryUnixNano != -1 {
		t.Fatalf("decoded prepare_begin aliases input: %#v", decoded)
	}

	maximum := make([]HelperBindingManifestRecord, MaxHelperBindings)
	for index := range maximum {
		maximum[index] = HelperBindingManifestRecord{
			BindingID: fmt.Sprintf("binding-%02d", index), Mode: DeliveryModeFileTmpfs,
			TargetPath: fmt.Sprintf("file-%02d", index), DeclaredFileBytes: MaxHelperFileBytes, FileSHA256: digest,
		}
	}
	if _, err := EncodeHelperPrepareBeginBody(HelperPrepareBeginBody{Revision: 1, Bindings: maximum}); err != nil {
		t.Fatalf("maximum bindings rejected: %v", err)
	}
	maximumToken := "A" + strings.Repeat("z", MaxBodyTokenBytes-1)
	components := make([]string, 17)
	for index := range components {
		components[index] = strings.Repeat("p", 240)
	}
	maximumPath := strings.Join(components, "/")
	if len(maximumPath) != MaxRelativePathBytes {
		t.Fatalf("maximum path fixture length = %d", len(maximumPath))
	}
	if _, err := EncodeHelperPrepareBeginBody(HelperPrepareBeginBody{Revision: 1, Bindings: []HelperBindingManifestRecord{{BindingID: maximumToken, Mode: DeliveryModeFileTmpfs, TargetPath: maximumPath, DeclaredFileBytes: MaxHelperFileBytes, FileSHA256: digest}}}); err != nil {
		t.Fatalf("maximum token/path/file record rejected: %v", err)
	}

	zeroDigest := [32]byte{}
	invalid := []struct {
		name string
		body HelperPrepareBeginBody
		want error
	}{
		{name: "zero revision", body: HelperPrepareBeginBody{Bindings: []HelperBindingManifestRecord{{BindingID: "ssh", Mode: DeliveryModeSSHAgent}}}, want: ErrHelperPrepareRevision},
		{name: "later revision", body: HelperPrepareBeginBody{Revision: 2, Bindings: []HelperBindingManifestRecord{{BindingID: "ssh", Mode: DeliveryModeSSHAgent}}}, want: ErrHelperPrepareRevision},
		{name: "zero bindings", body: HelperPrepareBeginBody{Revision: 1}, want: ErrHelperPrepareBindingCount},
		{name: "plus one bindings", body: HelperPrepareBeginBody{Revision: 1, Bindings: append(maximum, maximum[0])}, want: ErrHelperPrepareBindingCount},
		{name: "duplicate IDs", body: HelperPrepareBeginBody{Revision: 1, Bindings: []HelperBindingManifestRecord{{BindingID: "same", Mode: DeliveryModeSSHAgent}, {BindingID: "same", Mode: DeliveryModeFileTmpfs, TargetPath: "file", DeclaredFileBytes: 1, FileSHA256: digest}}}, want: ErrHelperPrepareBindingDuplicate},
		{name: "two HTTP", body: HelperPrepareBeginBody{Revision: 1, Bindings: []HelperBindingManifestRecord{{BindingID: "one", Mode: DeliveryModeHTTPProxy}, {BindingID: "two", Mode: DeliveryModeHTTPProxy}}}, want: ErrHelperPrepareHTTPBindingCount},
		{name: "HTTP target", body: HelperPrepareBeginBody{Revision: 1, Bindings: []HelperBindingManifestRecord{{BindingID: "http", Mode: DeliveryModeHTTPProxy, TargetPath: "file"}}}, want: ErrHelperPrepareBindingModeFields},
		{name: "HTTP length", body: HelperPrepareBeginBody{Revision: 1, Bindings: []HelperBindingManifestRecord{{BindingID: "http", Mode: DeliveryModeHTTPProxy, DeclaredFileBytes: 1}}}, want: ErrHelperPrepareBindingModeFields},
		{name: "HTTP digest", body: HelperPrepareBeginBody{Revision: 1, Bindings: []HelperBindingManifestRecord{{BindingID: "http", Mode: DeliveryModeHTTPProxy, FileSHA256: digest}}}, want: ErrHelperPrepareBindingModeFields},
		{name: "SSH fields", body: HelperPrepareBeginBody{Revision: 1, Bindings: []HelperBindingManifestRecord{{BindingID: "ssh", Mode: DeliveryModeSSHAgent, TargetPath: "file", DeclaredFileBytes: 1, FileSHA256: digest}}}, want: ErrHelperPrepareBindingModeFields},
		{name: "file no path", body: HelperPrepareBeginBody{Revision: 1, Bindings: []HelperBindingManifestRecord{{BindingID: "file", Mode: DeliveryModeFileTmpfs, DeclaredFileBytes: 1, FileSHA256: digest}}}, want: ErrHelperPrepareBindingModeFields},
		{name: "file zero length", body: HelperPrepareBeginBody{Revision: 1, Bindings: []HelperBindingManifestRecord{{BindingID: "file", Mode: DeliveryModeFileTmpfs, TargetPath: "file", FileSHA256: digest}}}, want: ErrHelperPrepareFileLength},
		{name: "file plus one", body: HelperPrepareBeginBody{Revision: 1, Bindings: []HelperBindingManifestRecord{{BindingID: "file", Mode: DeliveryModeFileTmpfs, TargetPath: "file", DeclaredFileBytes: MaxHelperFileBytes + 1, FileSHA256: digest}}}, want: ErrHelperPrepareFileLength},
		{name: "file zero digest", body: HelperPrepareBeginBody{Revision: 1, Bindings: []HelperBindingManifestRecord{{BindingID: "file", Mode: DeliveryModeFileTmpfs, TargetPath: "file", DeclaredFileBytes: 1, FileSHA256: zeroDigest}}}, want: ErrHelperPrepareFileDigest},
		{name: "unknown mode", body: HelperPrepareBeginBody{Revision: 1, Bindings: []HelperBindingManifestRecord{{BindingID: "binding", Mode: DeliveryMode(4)}}}, want: ErrUnknownDeliveryMode},
		{name: "invalid token", body: HelperPrepareBeginBody{Revision: 1, Bindings: []HelperBindingManifestRecord{{BindingID: "private/path", Mode: DeliveryModeSSHAgent}}}, want: ErrInvalidBodyToken},
		{name: "token plus one", body: HelperPrepareBeginBody{Revision: 1, Bindings: []HelperBindingManifestRecord{{BindingID: strings.Repeat("a", MaxBodyTokenBytes+1), Mode: DeliveryModeSSHAgent}}}, want: ErrInvalidBodyToken},
		{name: "invalid path", body: HelperPrepareBeginBody{Revision: 1, Bindings: []HelperBindingManifestRecord{{BindingID: "file", Mode: DeliveryModeFileTmpfs, TargetPath: "../private", DeclaredFileBytes: 1, FileSHA256: digest}}}, want: ErrInvalidRelativePath},
		{name: "path plus one", body: HelperPrepareBeginBody{Revision: 1, Bindings: []HelperBindingManifestRecord{{BindingID: "file", Mode: DeliveryModeFileTmpfs, TargetPath: maximumPath + "/x", DeclaredFileBytes: 1, FileSHA256: digest}}}, want: ErrInvalidRelativePath},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, err := EncodeHelperPrepareBeginBody(test.body); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestHelperPrepareFileBoundsDigestOwnershipAndWipe(t *testing.T) {
	t.Parallel()
	private := bytes.Repeat([]byte{0x5a}, MaxHelperFileBytes)
	digest := sha256.Sum256(private)
	body, err := NewHelperPrepareFileBody(1, MaxHelperBindings-1, digest, private)
	if err != nil {
		t.Fatalf("maximum file rejected: %v", err)
	}
	if cap(body.state.privateBytes) != len(body.state.privateBytes) || len(body.state.privateBytes) != MaxHelperFileBytes {
		t.Fatalf("private allocation len/cap = %d/%d", len(body.state.privateBytes), cap(body.state.privateBytes))
	}
	private[0] = 0
	destination := make([]byte, MaxHelperFileBytes)
	if n, err := body.CopyPrivateBytes(destination); err != nil || n != MaxHelperFileBytes || destination[0] != 0x5a {
		t.Fatalf("constructor retained caller alias: n=%d err=%v first=%x", n, err, destination[0])
	}
	small := bytes.Repeat([]byte{0xa5}, MaxHelperFileBytes-1)
	if n, err := body.CopyPrivateBytes(small); !errors.Is(err, ErrHelperPreparePrivateDestination) || n != 0 {
		t.Fatalf("short destination = %d, %v", n, err)
	}
	if !bytes.Equal(small, bytes.Repeat([]byte{0xa5}, MaxHelperFileBytes-1)) {
		t.Fatal("short destination was partially mutated")
	}
	owned := body.state.privateBytes
	alias := *body
	alias.Wipe()
	if body.state.privateBytes != nil || !body.state.wiped || !bytes.Equal(owned[:cap(owned)], make([]byte, cap(owned))) {
		t.Fatal("Wipe did not overwrite full capacity and reset ownership")
	}
	if body.Revision() != 0 || body.BindingIndex() != 0 || body.FileLength() != 0 || body.FileSHA256() != [32]byte{} ||
		body.state.revision != 0 || body.state.bindingIndex != 0 || body.state.fileLength != 0 || body.state.fileSHA256 != [32]byte{} {
		t.Fatal("Wipe did not zero safe metadata across aliases")
	}
	if n, err := body.CopyPrivateBytes(destination); !errors.Is(err, ErrHelperPreparePrivateWiped) || n != 0 {
		t.Fatalf("copy after wipe = %d, %v", n, err)
	}
	if _, err := EncodeHelperPrepareFileBody(body); !errors.Is(err, ErrHelperPreparePrivateWiped) {
		t.Fatalf("encode after wipe = %v", err)
	}
	body.Wipe()

	for _, test := range []struct {
		name     string
		revision uint64
		index    uint16
		digest   [32]byte
		private  []byte
		want     error
	}{
		{name: "zero revision", index: 0, digest: sha256.Sum256([]byte("x")), private: []byte("x"), want: ErrHelperPrepareRevision},
		{name: "later revision", revision: 2, digest: sha256.Sum256([]byte("x")), private: []byte("x"), want: ErrHelperPrepareRevision},
		{name: "index plus one", revision: 1, index: MaxHelperBindings, digest: sha256.Sum256([]byte("x")), private: []byte("x"), want: ErrHelperPrepareBindingIndex},
		{name: "empty", revision: 1, digest: sha256.Sum256(nil), want: ErrHelperPrepareFileLength},
		{name: "plus one", revision: 1, digest: sha256.Sum256(bytes.Repeat([]byte("x"), MaxHelperFileBytes+1)), private: bytes.Repeat([]byte("x"), MaxHelperFileBytes+1), want: ErrHelperPrepareFileLength},
		{name: "zero digest", revision: 1, private: []byte("x"), want: ErrHelperPrepareFileDigest},
		{name: "digest mismatch", revision: 1, digest: sha256.Sum256([]byte("y")), private: []byte("x"), want: ErrHelperPrepareFileDigest},
	} {
		t.Run(test.name, func(t *testing.T) {
			if body, err := NewHelperPrepareFileBody(test.revision, test.index, test.digest, test.private); !errors.Is(err, test.want) {
				if body != nil {
					body.Wipe()
				}
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestHelperPrepareDecodersRejectTruncationTrailingAndMalformedFields(t *testing.T) {
	t.Parallel()
	digest := sha256.Sum256([]byte("x"))
	begin := HelperPrepareBeginBody{Revision: 1, Bindings: []HelperBindingManifestRecord{{BindingID: "file", Mode: DeliveryModeFileTmpfs, TargetPath: "file", DeclaredFileBytes: 1, FileSHA256: digest}}}
	beginWire, err := EncodeHelperPrepareBeginBody(begin)
	if err != nil {
		t.Fatal(err)
	}
	for length := 0; length < len(beginWire); length++ {
		if _, err := DecodeHelperPrepareBeginBody(beginWire[:length]); err == nil {
			t.Fatalf("prepare_begin truncation %d accepted", length)
		}
	}
	if _, err := DecodeHelperPrepareBeginBody(append(append([]byte(nil), beginWire...), 0)); !errors.Is(err, ErrHelperPrepareBeginTrailingData) {
		t.Fatalf("prepare_begin trailing error = %v", err)
	}
	badCount := append([]byte(nil), beginWire...)
	binary.BigEndian.PutUint16(badCount[16:18], 0)
	if _, err := DecodeHelperPrepareBeginBody(badCount); !errors.Is(err, ErrHelperPrepareBindingCount) {
		t.Fatalf("zero binding count error = %v", err)
	}

	file, err := NewHelperPrepareFileBody(1, 0, digest, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Wipe()
	fileWire, err := EncodeHelperPrepareFileBody(file)
	if err != nil {
		t.Fatal(err)
	}
	for length := 0; length < len(fileWire); length++ {
		if decoded, err := DecodeHelperPrepareFileBody(fileWire[:length]); err == nil {
			decoded.Wipe()
			t.Fatalf("prepare_file truncation %d accepted", length)
		}
	}
	if decoded, err := DecodeHelperPrepareFileBody(append(append([]byte(nil), fileWire...), 0)); !errors.Is(err, ErrHelperPrepareFileTrailingData) {
		if decoded != nil {
			decoded.Wipe()
		}
		t.Fatalf("prepare_file trailing error = %v", err)
	}
	badDigest := append([]byte(nil), fileWire...)
	badDigest[14] ^= 0xff
	if decoded, err := DecodeHelperPrepareFileBody(badDigest); !errors.Is(err, ErrHelperPrepareFileDigest) {
		if decoded != nil {
			decoded.Wipe()
		}
		t.Fatalf("prepare_file digest error = %v", err)
	}

	zeroCommit := make([]byte, 40)
	binary.BigEndian.PutUint64(zeroCommit[:8], 1)
	decodedCommit, err := DecodeHelperPrepareCommitBody(zeroCommit)
	if err != nil || decodedCommit.ManifestSHA256 != [32]byte{} {
		t.Fatalf("zero manifest digest representation = %#v, %v", decodedCommit, err)
	}
	for length := 0; length < len(zeroCommit); length++ {
		if _, err := DecodeHelperPrepareCommitBody(zeroCommit[:length]); !errors.Is(err, ErrHelperPrepareCommitBodyLength) {
			t.Fatalf("commit truncation %d error = %v", length, err)
		}
	}
	if _, err := DecodeHelperPrepareCommitBody(append(zeroCommit, 0)); !errors.Is(err, ErrHelperPrepareCommitTrailingData) {
		t.Fatalf("commit trailing error = %v", err)
	}
	if encoded, err := EncodeHelperPrepareCommitBody(HelperPrepareCommitBody{Revision: 1}); err != nil || !bytes.Equal(encoded, zeroCommit) {
		t.Fatalf("zero commit encoding = %x, %v", encoded, err)
	}
}

func TestHelperPrepareBodiesDenySerializationAndFormatOpaque(t *testing.T) {
	t.Parallel()
	digest := sha256.Sum256([]byte("private-marker"))
	record := HelperBindingManifestRecord{BindingID: "binding-marker", Mode: DeliveryModeFileTmpfs, TargetPath: "private/marker", DeclaredFileBytes: 14, FileSHA256: digest}
	begin := HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: -9, Bindings: []HelperBindingManifestRecord{record}}
	commit := HelperPrepareCommitBody{Revision: 1, ManifestSHA256: digest}
	file, err := NewHelperPrepareFileBody(1, 0, digest, []byte("private-marker"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Wipe()

	values := []struct {
		value any
		name  string
	}{
		{record, "HelperBindingManifestRecord"},
		{begin, "HelperPrepareBeginBody"},
		{commit, "HelperPrepareCommitBody"},
		{file, "HelperPrepareFileBody"},
		{*file, "HelperPrepareFileBody"},
	}
	for _, test := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
			got := fmt.Sprintf(verb, test.value)
			if got != test.name || strings.Contains(got, "marker") {
				t.Errorf("fmt.Sprintf(%q, %s) = %q", verb, test.name, got)
			}
		}
		if _, err := json.Marshal(test.value); !errors.Is(err, ErrHelperPrepareBodySerialization) {
			t.Errorf("json.Marshal(%s) error = %v", test.name, err)
		}
		if marshaler, ok := test.value.(encoding.TextMarshaler); !ok {
			t.Errorf("%s lacks text serialization denial", test.name)
		} else if _, err := marshaler.MarshalText(); !errors.Is(err, ErrHelperPrepareBodySerialization) {
			t.Errorf("MarshalText(%s) error = %v", test.name, err)
		}
		if marshaler, ok := test.value.(encoding.BinaryMarshaler); !ok {
			t.Errorf("%s lacks binary serialization denial", test.name)
		} else if _, err := marshaler.MarshalBinary(); !errors.Is(err, ErrHelperPrepareBodySerialization) {
			t.Errorf("MarshalBinary(%s) error = %v", test.name, err)
		}
	}

	for _, pointer := range []any{&HelperBindingManifestRecord{}, &HelperPrepareBeginBody{}, &HelperPrepareCommitBody{}} {
		if err := json.Unmarshal([]byte(`{"Revision":9,"Bindings":[{"BindingID":"marker"}]}`), pointer); !errors.Is(err, ErrHelperPrepareBodySerialization) {
			t.Errorf("json.Unmarshal(%T) error = %v", pointer, err)
		}
		if err := pointer.(encoding.TextUnmarshaler).UnmarshalText([]byte("private-marker")); !errors.Is(err, ErrHelperPrepareBodySerialization) {
			t.Errorf("UnmarshalText(%T) error = %v", pointer, err)
		}
		if err := pointer.(encoding.BinaryUnmarshaler).UnmarshalBinary([]byte("private-marker")); !errors.Is(err, ErrHelperPrepareBodySerialization) {
			t.Errorf("UnmarshalBinary(%T) error = %v", pointer, err)
		}
		if !reflect.ValueOf(pointer).Elem().IsZero() {
			t.Errorf("generic decoders mutated %T", pointer)
		}
	}
	before := make([]byte, file.FileLength())
	_, _ = file.CopyPrivateBytes(before)
	if err := json.Unmarshal([]byte(`{"Revision":9}`), file); !errors.Is(err, ErrHelperPrepareBodySerialization) {
		t.Fatalf("json.Unmarshal(private owner) error = %v", err)
	}
	if err := file.UnmarshalText([]byte("private-marker")); !errors.Is(err, ErrHelperPrepareBodySerialization) {
		t.Fatalf("UnmarshalText(private owner) error = %v", err)
	}
	if err := file.UnmarshalBinary([]byte("private-marker")); !errors.Is(err, ErrHelperPrepareBodySerialization) {
		t.Fatalf("UnmarshalBinary(private owner) error = %v", err)
	}
	after := make([]byte, file.FileLength())
	_, _ = file.CopyPrivateBytes(after)
	if !bytes.Equal(after, before) {
		t.Fatal("denied generic decode mutated private owner")
	}
}

func TestHelperPreparePublicTypesHaveExactFieldsAndNoTags(t *testing.T) {
	t.Parallel()
	assertFields := func(value any, names ...string) {
		t.Helper()
		typeOf := reflect.TypeOf(value)
		if typeOf.NumField() < len(names) {
			t.Fatalf("%s fields = %d, want at least %d", typeOf, typeOf.NumField(), len(names))
		}
		for index, name := range names {
			field := typeOf.Field(index)
			if field.Name != name || field.Tag != "" {
				t.Errorf("%s field %d = %s tag %q, want %s no tag", typeOf, index, field.Name, field.Tag, name)
			}
		}
	}
	assertFields(HelperBindingManifestRecord{}, "BindingID", "Mode", "TargetPath", "DeclaredFileBytes", "FileSHA256")
	assertFields(HelperPrepareBeginBody{}, "Revision", "ExpiryUnixNano", "Bindings")
	assertFields(HelperPrepareCommitBody{}, "Revision", "ManifestSHA256")
	fileType := reflect.TypeOf(HelperPrepareFileBody{})
	if fileType.NumField() != 1 || fileType.Field(0).Name != "state" || fileType.Field(0).IsExported() || fileType.Field(0).Tag != "" {
		t.Fatalf("HelperPrepareFileBody fields expose owner state: %#v", fileType.Field(0))
	}
}

func TestHelperPrepareErrorsDoNotEchoRejectedInput(t *testing.T) {
	t.Parallel()
	seed := "credential-value-never-echoed/private/path"
	checks := []error{
		func() error {
			_, err := EncodeHelperPrepareBeginBody(HelperPrepareBeginBody{Revision: 1, Bindings: []HelperBindingManifestRecord{{BindingID: seed, Mode: DeliveryModeSSHAgent}}})
			return err
		}(),
		func() error {
			_, err := EncodeHelperPrepareBeginBody(HelperPrepareBeginBody{Revision: 1, Bindings: []HelperBindingManifestRecord{{BindingID: "file", Mode: DeliveryModeFileTmpfs, TargetPath: "../" + seed, DeclaredFileBytes: 1, FileSHA256: sha256.Sum256([]byte("x"))}}})
			return err
		}(),
		func() error { _, err := NewHelperPrepareFileBody(1, 0, sha256.Sum256([]byte(seed)), nil); return err }(),
	}
	for _, err := range checks {
		if err == nil || strings.Contains(err.Error(), seed) || strings.Contains(err.Error(), "private/path") {
			t.Fatalf("unsafe/static error = %v", err)
		}
	}
}

func mustHexBytes(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
