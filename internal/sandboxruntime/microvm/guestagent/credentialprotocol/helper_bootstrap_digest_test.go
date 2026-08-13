package credentialprotocol

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

func TestComputeCanonicalHelperBootstrapSHA256ExactVectorAndMutationMatrix(t *testing.T) {
	t.Parallel()

	body := canonicalHelperBootstrapDigestBody()
	header := canonicalHelperBootstrapDigestHeader(uint32(len(body)))
	digest, err := ComputeCanonicalHelperBootstrapSHA256(header, body)
	if err != nil {
		t.Fatalf("ComputeCanonicalHelperBootstrapSHA256() error = %v", err)
	}
	const wantHex = "8e3b5225e1c65dff41ce543c5cd69be9e981361819160dcfbd0447ce2166cba0"
	if got := hex.EncodeToString(digest[:]); got != wantHex {
		t.Fatalf("digest = %s, want %s", got, wantHex)
	}

	headerWire, err := EncodeHelperPacketHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	input := make([]byte, 2, 2+len("hal/l8/guest-helper/bootstrap/v1")+len(headerWire)+len(body))
	binary.BigEndian.PutUint16(input, uint16(len("hal/l8/guest-helper/bootstrap/v1")))
	input = append(input, "hal/l8/guest-helper/bootstrap/v1"...)
	input = append(input, headerWire[:]...)
	input = append(input, body...)
	if independent := sha256.Sum256(input); independent != digest {
		t.Fatalf("digest = %x, independent = %x", digest, independent)
	}

	bodyMutation := append([]byte(nil), body...)
	bodyMutation[len(bodyMutation)-1] ^= 1
	mutatedBodyDigest, err := ComputeCanonicalHelperBootstrapSHA256(header, bodyMutation)
	if err != nil || mutatedBodyDigest == digest {
		t.Fatalf("body mutation digest = %x, %v; want distinct success", mutatedBodyDigest, err)
	}
	headerMutation := header
	headerMutation.BootNonce[0] ^= 1
	mutatedHeaderDigest, err := ComputeCanonicalHelperBootstrapSHA256(headerMutation, body)
	if err != nil || mutatedHeaderDigest == digest {
		t.Fatalf("header mutation digest = %x, %v; want distinct success", mutatedHeaderDigest, err)
	}

	retainedProbe := append([]byte(nil), body...)
	stableDigest, err := ComputeCanonicalHelperBootstrapSHA256(header, retainedProbe)
	if err != nil {
		t.Fatal(err)
	}
	for index := range retainedProbe {
		retainedProbe[index] ^= byte(index + 1)
	}
	if stableDigest != digest {
		t.Fatalf("digest changed after caller body mutation: %x != %x", stableDigest, digest)
	}

	oversizedBody := make([]byte, MaxHelperPacketBodyBytes+1)
	invalid := []struct {
		name   string
		header HelperPacketHeader
		body   []byte
	}{
		{name: "unknown type", header: canonicalBootstrapDigestWithType(header, 0x06), body: body},
		{name: "wrong type", header: canonicalBootstrapDigestWithType(header, PacketTypeBootstrapAck), body: body},
		{name: "sequence", header: canonicalBootstrapDigestWithSequence(header, 1), body: body},
		{name: "request ID", header: canonicalBootstrapDigestWithRequestID(header), body: body},
		{name: "identity digest", header: canonicalBootstrapDigestWithIdentity(header), body: body},
		{name: "missing nonce", header: canonicalBootstrapDigestWithNonce(header, [32]byte{}), body: body},
		{name: "zero body", header: canonicalBootstrapDigestWithBodyLength(header, 0), body: nil},
		{name: "declared short", header: canonicalBootstrapDigestWithBodyLength(header, uint32(len(body)-1)), body: body},
		{name: "declared long", header: canonicalBootstrapDigestWithBodyLength(header, uint32(len(body)+1)), body: body},
		{name: "oversized", header: canonicalBootstrapDigestWithBodyLength(header, uint32(len(oversizedBody))), body: oversizedBody},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := ComputeCanonicalHelperBootstrapSHA256(test.header, test.body)
			if got != ([32]byte{}) || !errors.Is(err, ErrHelperBootstrapCanonicalDigest) {
				t.Fatalf("ComputeCanonicalHelperBootstrapSHA256() = %x, %v; want zero and %v", got, err, ErrHelperBootstrapCanonicalDigest)
			}
			if err.Error() != ErrHelperBootstrapCanonicalDigest.Error() {
				t.Fatalf("error = %q, want stable sanitized %q", err, ErrHelperBootstrapCanonicalDigest)
			}
		})
	}
}

func canonicalHelperBootstrapDigestBody() []byte {
	body := make([]byte, 12)
	binary.BigEndian.PutUint32(body[0:4], 0x01020304)
	binary.BigEndian.PutUint32(body[4:8], 998)
	binary.BigEndian.PutUint32(body[8:12], 998)
	body = binary.BigEndian.AppendUint16(body, uint16(len("boot-generation-1")))
	body = append(body, "boot-generation-1"...)
	body = binary.BigEndian.AppendUint16(body, uint16(len("helper-generation-1")))
	return append(body, "helper-generation-1"...)
}

func canonicalHelperBootstrapDigestHeader(bodyLength uint32) HelperPacketHeader {
	return HelperPacketHeader{
		Type:       PacketTypeBootstrap,
		BodyLength: bodyLength,
		BootNonce:  canonicalHelperBootstrapDigestFilled32(0x44),
	}
}

func canonicalHelperBootstrapDigestFilled32(value byte) [32]byte {
	var result [32]byte
	for index := range result {
		result[index] = value
	}
	return result
}

func canonicalBootstrapDigestWithType(header HelperPacketHeader, packetType PacketType) HelperPacketHeader {
	header.Type = packetType
	return header
}

func canonicalBootstrapDigestWithSequence(header HelperPacketHeader, sequence uint64) HelperPacketHeader {
	header.Sequence = sequence
	return header
}

func canonicalBootstrapDigestWithRequestID(header HelperPacketHeader) HelperPacketHeader {
	header.RequestID[0] = 1
	return header
}

func canonicalBootstrapDigestWithIdentity(header HelperPacketHeader) HelperPacketHeader {
	header.GuestCredentialIdentityDigest[0] = 1
	return header
}

func canonicalBootstrapDigestWithNonce(header HelperPacketHeader, nonce [32]byte) HelperPacketHeader {
	header.BootNonce = nonce
	return header
}

func canonicalBootstrapDigestWithBodyLength(header HelperPacketHeader, bodyLength uint32) HelperPacketHeader {
	header.BodyLength = bodyLength
	return header
}
