package main

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"fmt"
	"go/format"
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

func (evidence generatedEvidence) files() map[string][]byte {
	return map[string][]byte{
		filepath.Join(policyDir, "verified-pinned-callsites.hl8e"):             evidence.encoded,
		filepath.Join(policyDir, "verified-pinned-callsites.hl8e.sha256"):      digestLine(evidence.sha256),
		filepath.Join(guestDir, "pinned_callsite_evidence_expected_d7_gen.go"): evidence.source,
	}
}

func generateEvidence(root, binaryPath string, outputs generatedOutputs) (generatedEvidence, error) {
	rolesBytes, err := readBounded(filepath.Join(root, policyDir, "roles-v1.yaml"), 1<<20)
	if err != nil {
		return generatedEvidence{}, err
	}
	roles, err := decodeRoles(rolesBytes)
	if err != nil {
		return generatedEvidence{}, err
	}
	runtimeLock, err := readExactLock(filepath.Join(root, policyDir, "runtime-go1.25.7.lock"), exactRuntimeLockValues(), "runtime-go1.25.7.lock")
	if err != nil {
		return generatedEvidence{}, err
	}
	toolchainSHA256, err := parseDigest(runtimeLock["toolchain_archive_sha256"])
	if err != nil {
		return generatedEvidence{}, err
	}
	if err := validatePinnedRuntimeSource(root, roles.PinnedCallsite, runtimeLock); err != nil {
		return generatedEvidence{}, err
	}

	pinnedRole, err := solePinnedRole(roles)
	if err != nil {
		return generatedEvidence{}, err
	}
	binaryBytes, err := readBounded(binaryPath, 128<<20)
	if err != nil {
		return generatedEvidence{}, fmt.Errorf("read final guest role binary: %w", err)
	}
	if !bytes.Contains(binaryBytes, outputs.artifact) {
		return generatedEvidence{}, errors.New("final guest role binary does not embed the exact D7 HL8Q artifact")
	}
	build, err := buildinfo.ReadFile(binaryPath)
	if err != nil {
		return generatedEvidence{}, fmt.Errorf("read final guest role build info: %w", err)
	}
	if build.GoVersion != "go1.25.7" {
		return generatedEvidence{}, fmt.Errorf("final guest role binary Go version = %s, want go1.25.7", build.GoVersion)
	}

	file, err := elf.Open(binaryPath)
	if err != nil {
		return generatedEvidence{}, fmt.Errorf("open final guest role ELF: %w", err)
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || file.Machine != elf.EM_X86_64 {
		return generatedEvidence{}, errors.New("final guest role binary is not Linux amd64 ELF")
	}
	textSection := file.Section(".text")
	if textSection == nil || textSection.Size == 0 {
		return generatedEvidence{}, errors.New("final guest role binary has no executable text")
	}
	textBytes, err := textSection.Data()
	if err != nil {
		return generatedEvidence{}, fmt.Errorf("read final guest role executable text: %w", err)
	}
	symbol, err := findExactSymbol(file, roles.PinnedCallsite.Symbol)
	if err != nil {
		return generatedEvidence{}, err
	}
	instruction := mustDecodeHex(roles.PinnedCallsite.InstructionHex)
	instructionAddress := symbol.Value + roles.PinnedCallsite.InstructionOffsetInSymbol
	if instructionAddress < symbol.Value || instructionAddress < textSection.Addr {
		return generatedEvidence{}, errors.New("pinned instruction address underflow")
	}
	instructionOffset := instructionAddress - textSection.Addr
	end := instructionOffset + uint64(len(instruction))
	if end < instructionOffset || end > uint64(len(textBytes)) || roles.PinnedCallsite.InstructionOffsetInSymbol+uint64(len(instruction)) > symbol.Size {
		return generatedEvidence{}, errors.New("pinned instruction is outside its exact symbol or executable text")
	}
	if !bytes.Equal(textBytes[instructionOffset:end], instruction) {
		return generatedEvidence{}, errors.New("pinned instruction bytes do not match the source-locked template")
	}

	requirementRow, err := encodePinnedRequirement(roles.PinnedCallsite, toolchainSHA256, true)
	if err != nil {
		return generatedEvidence{}, err
	}
	callsiteSHA256 := framedSHA256("hal/l8/pinned-callsite/linux-amd64/v1", requirementRow)
	binding := new(bytes.Buffer)
	binding.WriteByte(pinnedRole.ID)
	binding.WriteByte(2) // RuleOriginRuntime maps to BinaryBindingKindPinnedGoRuntime.
	writeUint16(binding, 0)
	writeUint64(binding, uint64(len(textBytes)))
	binding.Write(outputs.sourceLockSHA256[:])
	binding.Write(toolchainSHA256[:])
	binarySHA256 := sha256.Sum256(binaryBytes)
	textSHA256 := sha256.Sum256(textBytes)
	binding.Write(binarySHA256[:])
	binding.Write(textSHA256[:])
	bindingSHA256 := framedSHA256("hal/l8/pinned-binary-binding/linux-amd64/v1", binding.Bytes())
	bindingSetPreimage := new(bytes.Buffer)
	writeUint16(bindingSetPreimage, 1)
	writeUint16(bindingSetPreimage, 0)
	bindingSetPreimage.Write(binding.Bytes())
	bindingSetSHA256 := framedSHA256("hal/l8/pinned-binary-binding-set/linux-amd64/v1", bindingSetPreimage.Bytes())

	evidenceRow := new(bytes.Buffer)
	evidenceRow.Write(callsiteSHA256[:])
	evidenceRow.Write(bindingSHA256[:])
	instructionSHA256 := sha256.Sum256(instruction)
	evidenceRow.Write(instructionSHA256[:])
	writeUint64(evidenceRow, instructionOffset)

	envelope := new(bytes.Buffer)
	envelope.WriteString("HL8E")
	envelope.WriteByte(1)
	envelope.WriteByte(0)
	writeUint16(envelope, 1)
	writeUint16(envelope, 1)
	writeUint16(envelope, 0)
	envelope.Write(outputs.artifactSHA256[:])
	envelope.Write(outputs.sourceLockSHA256[:])
	envelope.Write(bindingSetSHA256[:])
	envelope.Write(binding.Bytes())
	envelope.Write(evidenceRow.Bytes())
	evidenceSHA256 := framedSHA256("hal/l8/pinned-callsite-evidence/linux-amd64/v1", envelope.Bytes())
	source, err := encodeEvidenceSource(evidenceSHA256)
	if err != nil {
		return generatedEvidence{}, err
	}
	return generatedEvidence{encoded: envelope.Bytes(), sha256: evidenceSHA256, source: source}, nil
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

func solePinnedRole(document rolesDocument) (roleInput, error) {
	var result roleInput
	count := 0
	for _, role := range document.Roles {
		if role.PinnedRuntimeCallsite {
			result = role
			count++
		}
	}
	if count != 1 || result.Origin != 3 || result.Path != 3 {
		return roleInput{}, errors.New("roles must contain exactly one runtime-origin pinned-direct callsite")
	}
	return result, nil
}

func findExactSymbol(file *elf.File, name string) (elf.Symbol, error) {
	symbols, err := file.Symbols()
	if err != nil {
		return elf.Symbol{}, fmt.Errorf("read final guest role symbols: %w", err)
	}
	var result elf.Symbol
	count := 0
	for _, symbol := range symbols {
		if symbol.Name == name {
			result = symbol
			count++
		}
	}
	if count != 1 || result.Size == 0 {
		return elf.Symbol{}, fmt.Errorf("final guest role symbol %q count = %d", name, count)
	}
	return result, nil
}

func encodeEvidenceSource(evidenceSHA256 [32]byte) ([]byte, error) {
	var source bytes.Buffer
	source.WriteString("// Code generated by tools/microvm/l8/policy/generate; DO NOT EDIT.\n")
	source.WriteString("//go:build l8_verified_pinned_callsite_evidence\n\n")
	source.WriteString("package syscallpolicy\n\n")
	fmt.Fprintf(&source, "var expectedPinnedCallsiteEvidenceSHA256 = %#v\n\n", evidenceSHA256)
	source.WriteString("func EmbeddedExpectedPinnedCallsiteEvidence() (ExpectedPinnedCallsiteEvidence, error) {\n")
	source.WriteString("\treturn ExpectedPinnedCallsiteEvidence{sha256: expectedPinnedCallsiteEvidenceSHA256, issuer: expectedEvidenceIssuer{issued: true}}, nil\n")
	source.WriteString("}\n")
	formatted, err := format.Source(source.Bytes())
	if err != nil {
		return nil, fmt.Errorf("format generated host evidence source: %w", err)
	}
	return formatted, nil
}

func mustDecodeHex(value string) []byte {
	result := make([]byte, len(value)/2)
	for index := range result {
		left := fromHex(value[index*2])
		right := fromHex(value[index*2+1])
		result[index] = left<<4 | right
	}
	return result
}

func fromHex(value byte) byte {
	if value >= '0' && value <= '9' {
		return value - '0'
	}
	return value - 'a' + 10
}
