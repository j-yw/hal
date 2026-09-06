package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type generatedEvidence struct {
	encoded []byte
	sha256  [32]byte
	source  []byte
}

var errEvidenceInputsUnavailable = errors.New("HL8E issuance disabled: final D4/D6 linked binary identity and call graph are unavailable")

func (evidence generatedEvidence) files() map[string][]byte {
	return map[string][]byte{
		filepath.Join(policyDir, "verified-pinned-callsites.hl8e"):             evidence.encoded,
		filepath.Join(policyDir, "verified-pinned-callsites.hl8e.sha256"):      digestLine(evidence.sha256),
		filepath.Join(guestDir, "pinned_callsite_evidence_expected_d7_gen.go"): evidence.source,
	}
}

func generateEvidence(root, binaryPath string, outputs generatedOutputs) (generatedEvidence, error) {
	return generateEvidenceFromInputs(root, evidenceInputs{binaryPath: binaryPath}, outputs)
}

func validatePinnedRuntimeSource(root string, callsite callsiteInput, runtimeLock map[string]string) error {
	command := exec.Command("go", "env", "GOROOT")
	command.Dir = root
	command.Env = append(os.Environ(), "GOTOOLCHAIN=go1.25.7")
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("locate pinned Go 1.25.7 source: %w", err)
	}
	if callsite.SourceUnit != runtimeLock["runtime_source_path"] {
		return errors.New("pinned callsite source path does not match runtime lock")
	}
	return validateLockedAbsoluteFile(filepath.Join(strings.TrimSpace(string(output)), filepath.FromSlash(callsite.SourceUnit)), callsite.SourceUnitSHA256)
}

func validateLockedAbsoluteFile(path, digestText string) error {
	encoded, err := readBounded(path, 8<<20)
	if err != nil {
		return err
	}
	want, err := parseDigest(digestText)
	if err != nil {
		return err
	}
	if sha256.Sum256(encoded) != want {
		return fmt.Errorf("locked source %s digest mismatch", filepath.Base(path))
	}
	return nil
}
