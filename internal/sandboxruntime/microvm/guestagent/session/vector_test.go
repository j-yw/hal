package session

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

const (
	vectorGuestPrivateHex       = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	vectorControllerPrivateHex  = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	vectorControllerSeedHex     = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	vectorGuestHelloHex         = "000000d9484c384801010000000101008520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000003000004010014636f6e74726f6c6c65722d6b65792d67656e2d31000972756e74696d652d31000d72756e74696d652d67656e2d31000d70726f636573732d67656e2d31000b76736f636b2d67656e2d31000a626f6f742d67656e2d31000b696d6167652d67656e2d315756b67946a36d1e78ce0b3ae6f1131ead840b828d41b334de1594a7c8a00687"
	vectorControllerAuthHex     = "0000006c484c38480102000000010100de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4ff40a8509d1881897bfd0838d2008290d71287a45ab92a811450e71a74b26243766c6e1a62de2a1a13064cbd8c8f512cd9be8dd49ed840c4fe765468eb5d27600"
	vectorGuestFinishedHex      = "484c3846010100000000000000000000000000308bb2532307629fb19302a9e5ee11490e8c9f2265f030bcc46a13391dc9759efbfb955227d8d3bf927f66b3e947f3dd2608bc81ba3070ab22d1aef360e6579366d5e79ee66d83dcf5234495deaf608cae"
	vectorControllerFinishedHex = "484c3846010200000000000000000000000000308bb2532307629fb19302a9e5ee11490e8c9f2265f030bcc46a13391dc9759efbdacd029fbeabc81d3644fc6c194f5ade5082bcf21140d99a286ea0ca7d730267bfe2fb9806023953216d89368c00ec23"
	vectorApplicationHex        = "484c3846011000000000000000000001000000308bb2532307629fb19302a9e5ee11490e8c9f2265f030bcc46a13391dc9759efb5a7ea7228a09f92f035b0bd61133da82428eb55e9a5c2d54004927c84edecc39cf4512c772cbf1ad10e9a6c317411a34"
)

var vectorNow = time.Date(2026, 8, 5, 1, 2, 3, 0, time.UTC)

func TestSuiteOneExactVector(t *testing.T) {
	guestHandshake, helloWire, err := NewGuestHandshake(GuestHandshakeConfig{
		Identity:                  vectorIdentity(),
		PinnedControllerPublicKey: vectorControllerPublicKey(t),
		Dependencies: Dependencies{
			Random: bytes.NewReader(mustHex(t, vectorGuestPrivateHex)),
			Now:    func() time.Time { return vectorNow },
		},
	})
	if err != nil {
		t.Fatalf("NewGuestHandshake() error: %v", err)
	}
	assertHex(t, "GuestHello", helloWire, vectorGuestHelloHex)

	controllerHandshake, err := NewControllerHandshake(ControllerHandshakeConfig{
		ExpectedIdentity: vectorIdentity(),
		SigningKey:       vectorControllerPrivateKey(t),
		Dependencies: Dependencies{
			Random: bytes.NewReader(mustHex(t, vectorControllerPrivateHex)),
			Now:    func() time.Time { return vectorNow },
		},
	})
	if err != nil {
		t.Fatalf("NewControllerHandshake() error: %v", err)
	}
	controllerState, authWire, err := controllerHandshake.AcceptGuestHello(helloWire)
	if err != nil {
		t.Fatalf("AcceptGuestHello() error: %v", err)
	}
	assertHex(t, "ControllerAuth", authWire, vectorControllerAuthHex)

	guestState, err := guestHandshake.AcceptControllerAuth(authWire)
	if err != nil {
		t.Fatalf("AcceptControllerAuth() error: %v", err)
	}
	trace := independentlyDeriveVector(t, helloWire, authWire)
	assertHex(t, "shared secret", trace.sharedSecret, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
	assertHex(t, "transcript hash", trace.transcriptHash, "5ca9d78096d266d650caef23a7619548039feffcd6ef4d4636d8e330c3c9591a")
	assertHex(t, "session ID", guestState.material.sessionID[:], "8bb2532307629fb19302a9e5ee11490e8c9f2265f030bcc46a13391dc9759efb")
	assertHex(t, "PRK", trace.prk, "ba5a837774445109cd4be8509cbc19261278240efe08f5882e8f32c2b926c2a4")
	assertHex(t, "controller-to-guest key", guestState.material.controllerToGuest.key[:], "1dc71db6479a93a9fa784b8aa4e6fa94997fb7d9dbbc7ac549087bc06e04c9b1")
	assertHex(t, "guest-to-controller key", guestState.material.guestToController.key[:], "2a0ca1e4bf700414c0af68a90d46086a3dc075a314f4a3d0349f1066f775e52f")
	assertHex(t, "controller-to-guest nonce prefix", guestState.material.controllerToGuest.noncePrefix[:], "525309e4")
	assertHex(t, "guest-to-controller nonce prefix", guestState.material.guestToController.noncePrefix[:], "3737cc07")
	assertHex(t, "controller-to-guest Finished key", guestState.material.controllerToGuest.finishedKey[:], "6296f230589ee300af728605d996be1d5deb7724c6f0a1fbbb59e34b2325df07")
	assertHex(t, "guest-to-controller Finished key", guestState.material.guestToController.finishedKey[:], "538a2ed25a05b640e8aa35b1e7ca989d428949e8198030232866d139ad762e6f")
	assertHex(t, "guest verify", guestState.localFinished[:], "7869fb8ddfac62aaa8a8a59febda424eb1d31834e2ba89d433ba69ef17c763f2")
	assertHex(t, "controller verify", guestState.peerFinished[:], "4489107525a59d2174bfed691601ce21f6389420f3151cdc26c65f23f9c797dd")

	guestFinished, err := guestState.SealFinished()
	if err != nil {
		t.Fatalf("guest SealFinished() error: %v", err)
	}
	assertHex(t, "guest Finished", guestFinished, vectorGuestFinishedHex)
	if err := controllerState.OpenFinished(guestFinished); err != nil {
		t.Fatalf("controller OpenFinished() error: %v", err)
	}
	controllerFinished, err := controllerState.SealFinished()
	if err != nil {
		t.Fatalf("controller SealFinished() error: %v", err)
	}
	assertHex(t, "controller Finished", controllerFinished, vectorControllerFinishedHex)
	if err := guestState.OpenFinished(controllerFinished); err != nil {
		t.Fatalf("guest OpenFinished() error: %v", err)
	}

	plaintext := make([]byte, 32)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	applicationWire, err := controllerState.SealApplication(FrameTypeControlRequest, plaintext)
	if err != nil {
		t.Fatalf("SealApplication() error: %v", err)
	}
	assertHex(t, "sequence-1 application", applicationWire, vectorApplicationHex)
	got, err := guestState.OpenApplication(applicationWire, nil)
	if err != nil {
		t.Fatalf("OpenApplication() error: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("OpenApplication() = %x, want %x", got, plaintext)
	}
}

type vectorTrace struct {
	sharedSecret   []byte
	transcriptHash []byte
	prk            []byte
}

func independentlyDeriveVector(t *testing.T, helloWire, authWire []byte) vectorTrace {
	t.Helper()
	privateKey, err := ecdh.X25519().NewPrivateKey(mustHex(t, vectorGuestPrivateHex))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ecdh.X25519().NewPublicKey(mustHex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
	if err != nil {
		t.Fatal(err)
	}
	sharedSecret, err := privateKey.ECDH(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	guestInner := helloWire[4:]
	controllerUnsigned := authWire[4 : len(authWire)-ed25519.SignatureSize]
	transcript := testOpaque16(nil, transcriptLabel)
	transcript = testUint32(transcript, uint32(len(guestInner)))
	transcript = append(transcript, guestInner...)
	transcript = testUint32(transcript, uint32(len(controllerUnsigned)))
	transcript = append(transcript, controllerUnsigned...)
	transcriptHash := sha256.Sum256(transcript)
	mac := hmac.New(sha256.New, transcriptHash[:])
	mac.Write(sharedSecret)
	return vectorTrace{sharedSecret: sharedSecret, transcriptHash: transcriptHash[:], prk: mac.Sum(nil)}
}

func testOpaque16(destination []byte, value string) []byte {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)))
	destination = append(destination, length[:]...)
	return append(destination, value...)
}

func testUint32(destination []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return append(destination, encoded[:]...)
}

func vectorIdentity() Identity {
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	var image [32]byte
	copy(image[:], mustDecodeHex("5756b67946a36d1e78ce0b3ae6f1131ead840b828d41b334de1594a7c8a00687"))
	return Identity{
		Channel:                      ChannelControl,
		GuestBootNonce:               nonce,
		GuestCID:                     GuestCID,
		GuestPort:                    ControlPort,
		ControllerKeyGeneration:      "controller-key-gen-1",
		RuntimeID:                    "runtime-1",
		RuntimeGeneration:            "runtime-gen-1",
		FirecrackerProcessGeneration: "process-gen-1",
		VsockGeneration:              "vsock-gen-1",
		BootGeneration:               "boot-gen-1",
		ImageGeneration:              "image-gen-1",
		ImageSHA256:                  image,
	}
}

func vectorControllerPrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	return ed25519.NewKeyFromSeed(mustHex(t, vectorControllerSeedHex))
}

func vectorControllerPublicKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	key := vectorControllerPrivateKey(t).Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), key...)
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString(%q): %v", value, err)
	}
	return decoded
}

func mustDecodeHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}

func assertHex(t *testing.T, name string, got []byte, wantHex string) {
	t.Helper()
	want := mustHex(t, wantHex)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s = %x, want %x", name, got, want)
	}
}
