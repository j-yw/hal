//go:build l8_verified_native_artifact

package rolebootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestL8D7NativeGeneratedArtifactIdentitiesAreStableAndMatchHashedInputs(t *testing.T) {
	first, err := EmbeddedGeneratedArtifact()
	if err != nil {
		t.Fatalf("EmbeddedGeneratedArtifact() error = %v", err)
	}
	second, err := EmbeddedGeneratedArtifact()
	if err != nil {
		t.Fatalf("second EmbeddedGeneratedArtifact() error = %v", err)
	}
	if first != second {
		t.Fatal("generated native artifact identities are unstable")
	}
	if first.ContractVersion() != ContractVersion {
		t.Fatalf("contract version = %q, want %q", first.ContractVersion(), ContractVersion)
	}
	policy := first.PolicySHA256()
	source := first.NativeSourceSHA256()
	callsite := first.NativeCallsiteSHA256()
	install := first.NativeInstallTableSHA256()
	if policy == ([32]byte{}) || source == ([32]byte{}) || callsite == ([32]byte{}) || install == ([32]byte{}) {
		t.Fatal("generated native artifact identities include a zero digest")
	}

	root := repositoryRoot(t)
	issuedPolicy, err := os.ReadFile(filepath.Join(root, "tools/microvm/l8/policy/verified-syscall-policy.hl8q.sha256"))
	if err != nil {
		t.Fatalf("read issued policy identity: %v", err)
	}
	if hex.EncodeToString(policy[:])+"\n" != string(issuedPolicy) {
		t.Fatal("generated policy digest does not match the already-issued HL8Q identity")
	}

	sourceBytes, err := os.ReadFile(filepath.Join(root, "tools/microvm/l8/role-bootstrap/hal-guest-role-bootstrap.S"))
	if err != nil {
		t.Fatalf("read native source: %v", err)
	}
	if source != framedDigest("hal/l8/native-role-bootstrap-source/linux-amd64/v1", encodeSourcePreimage("tools/microvm/l8/role-bootstrap/hal-guest-role-bootstrap.S", sourceBytes)) {
		t.Fatal("generated native source digest does not match hashed source bytes")
	}

	callsiteBytes, err := os.ReadFile(filepath.Join(root, "tools/microvm/l8/role-bootstrap/callsites.v1"))
	if err != nil {
		t.Fatalf("read native callsite inventory: %v", err)
	}
	if callsite != framedDigest("hal/l8/native-role-bootstrap-callsites/linux-amd64/v1", callsiteBytes) {
		t.Fatal("generated native callsite digest does not match hashed inventory bytes")
	}

	if install != nativeInstallTableDigest() {
		t.Fatal("generated native install-table digest does not match the hashed D4 binding table")
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	current, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			t.Fatal("repository root not found")
		}
		current = parent
	}
}

func encodeSourcePreimage(path string, encoded []byte) []byte {
	preimage := new(bytes.Buffer)
	_ = binary.Write(preimage, binary.BigEndian, uint16(len(path)))
	preimage.WriteString(path)
	_ = binary.Write(preimage, binary.BigEndian, uint64(len(encoded)))
	preimage.Write(encoded)
	return preimage.Bytes()
}

func nativeInstallTableDigest() [32]byte {
	bindings := [5][3]byte{
		{1, 1, 1},
		{2, 3, 1},
		{3, 5, 1},
		{4, 7, 1},
		{5, 9, 1},
	}
	preimage := make([]byte, 4+len(bindings)*4)
	binary.BigEndian.PutUint16(preimage[:2], uint16(len(bindings)))
	for index, binding := range bindings {
		offset := 4 + index*4
		preimage[offset] = binding[0]
		preimage[offset+1] = binding[1]
		preimage[offset+2] = binding[2]
	}
	return framedDigest("hal/l8/d4-native-install-table/linux-amd64/v1", preimage)
}

func framedDigest(domain string, preimage []byte) [32]byte {
	encoded := make([]byte, 2, 2+len(domain)+len(preimage))
	binary.BigEndian.PutUint16(encoded[:2], uint16(len(domain)))
	encoded = append(encoded, domain...)
	encoded = append(encoded, preimage...)
	return sha256.Sum256(encoded)
}
