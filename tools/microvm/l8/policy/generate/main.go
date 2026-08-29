package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

const (
	policyDir  = "tools/microvm/l8/policy"
	guestDir   = "internal/sandboxruntime/microvm/guestagent/syscallpolicy"
	d4LinuxDir = "internal/sandboxruntime/microvm/guestagent/credentialhelper/linux"
)

type generatedOutputs struct {
	artifact         []byte
	guestSource      []byte
	d4InstallSource  []byte
	artifactSHA256   [32]byte
	sourceLockSHA256 [32]byte
}

func (outputs generatedOutputs) files() map[string][]byte {
	return map[string][]byte{
		filepath.Join(policyDir, "verified-syscall-policy.hl8q"):               outputs.artifact,
		filepath.Join(policyDir, "verified-syscall-policy.hl8q.sha256"):        digestLine(outputs.artifactSHA256),
		filepath.Join(policyDir, "verified-syscall-policy.source-lock.sha256"): digestLine(outputs.sourceLockSHA256),
		filepath.Join(guestDir, "artifact_expected_d7_gen.go"):                 outputs.guestSource,
		filepath.Join(d4LinuxDir, "policy_install_inventory_d7_gen.go"):        outputs.d4InstallSource,
	}
}

type roleInput struct {
	ID                    uint8  `json:"id"`
	Name                  string `json:"name"`
	Stage                 uint8  `json:"stage"`
	Origin                uint8  `json:"origin"`
	Path                  uint8  `json:"path"`
	Syscall               string `json:"syscall"`
	PinnedRuntimeCallsite bool   `json:"pinnedRuntimeCallsite,omitempty"`
}

type callsiteInput struct {
	SourceUnit                string `json:"sourceUnit"`
	SourceUnitSHA256          string `json:"sourceUnitSHA256"`
	Symbol                    string `json:"symbol"`
	InstructionHex            string `json:"instructionHex"`
	InstructionOffsetInSymbol uint64 `json:"instructionOffsetInSymbol"`
	ArgumentTemplate          string `json:"argumentTemplate"`
}

type rolesDocument struct {
	Schema         string        `json:"schema"`
	Roles          []roleInput   `json:"roles"`
	PinnedCallsite callsiteInput `json:"pinnedCallsite"`
}

type d4InstallBinding struct {
	installRole uint8
	policyRole  uint8
	binaryKind  uint8
}

type catalogEntry struct {
	number uint32
	name   string
}

func exactWorkloadLockValues() map[string]string {
	return map[string]string{
		"format":    "hal-l8-workload-lock-v1",
		"l4_path":   "internal/sandboxruntime/microvm/guestagent/server/isolation_linux.go",
		"l4_sha256": "565a7c1dd6ae9618428580b8f11de5a504032c394c32b6f4ad8a4368df2f8cd3",
		"l7_path":   "internal/sandboxruntime/microvm/guestagent/l8composition/agent_supervisor.go",
		"l7_sha256": "05a7118b6468c1390cbc15ecbd22db87cd01e2e55098e90492f64c0a3565f859",
	}
}

func exactRuntimeLockValues() map[string]string {
	return map[string]string{
		"format":                   "hal-l8-runtime-lock-v1",
		"go_version":               "go1.25.7",
		"toolchain_module":         "golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64",
		"toolchain_archive_sha256": "43a6a44615934ab4533b010735fc39757accc93f421ffafa67a34f73c5703e7b",
		"runtime_source_path":      "src/internal/runtime/syscall/asm_linux_amd64.s",
		"runtime_source_sha256":    "dd6191356bf0c18b3c9862b19e4014f06e217987b225823612b6da56fb6e193a",
	}
}

func exactCatalogLockValues() map[string]string {
	return map[string]string{
		"format":         "hal-l8-catalog-lock-v1",
		"module":         "golang.org/x/sys@v0.41.0",
		"source_path":    "unix/zsysnum_linux_amd64.go",
		"source_sha256":  "d12bc509fbe79afd804a66297c7517076eea6f3c8d82780630cd07f561b043b6",
		"kernel_ceiling": "450",
	}
}

func exactRoles() []roleInput {
	return []roleInput{
		{ID: 1, Name: "launch-bootstrap", Stage: 4, Origin: 1, Path: 1, Syscall: "read"},
		{ID: 2, Name: "launch-base", Stage: 4, Origin: 3, Path: 3, Syscall: "read", PinnedRuntimeCallsite: true},
		{ID: 3, Name: "controller-bootstrap", Stage: 4, Origin: 1, Path: 1, Syscall: "read"},
		{ID: 4, Name: "steady-controller", Stage: 4, Origin: 1, Path: 1, Syscall: "read"},
		{ID: 5, Name: "agent-bootstrap", Stage: 4, Origin: 1, Path: 1, Syscall: "read"},
		{ID: 6, Name: "steady-agent", Stage: 4, Origin: 1, Path: 1, Syscall: "read"},
		{ID: 7, Name: "monitor-bootstrap", Stage: 4, Origin: 1, Path: 1, Syscall: "read"},
		{ID: 8, Name: "steady-monitor", Stage: 4, Origin: 1, Path: 1, Syscall: "read"},
		{ID: 9, Name: "workload-transition", Stage: 4, Origin: 1, Path: 1, Syscall: "read"},
		{ID: 10, Name: "workload", Stage: 4, Origin: 2, Path: 1, Syscall: "read"},
	}
}

func exactD4InstallBindings() [5]d4InstallBinding {
	return [5]d4InstallBinding{
		{installRole: 1, policyRole: 1, binaryKind: 1},
		{installRole: 2, policyRole: 3, binaryKind: 1},
		{installRole: 3, policyRole: 5, binaryKind: 1},
		{installRole: 4, policyRole: 7, binaryKind: 1},
		{installRole: 5, policyRole: 9, binaryKind: 1},
	}
}

func exactPinnedCallsite() callsiteInput {
	return callsiteInput{
		SourceUnit:                "src/internal/runtime/syscall/asm_linux_amd64.s",
		SourceUnitSHA256:          "dd6191356bf0c18b3c9862b19e4014f06e217987b225823612b6da56fb6e193a",
		Symbol:                    "internal/runtime/syscall.Syscall6",
		InstructionHex:            "0f05",
		InstructionOffsetInSymbol: 12,
		ArgumentTemplate:          "linux-amd64-syscall-abi-v1",
	}
}

func main() {
	rootFlag := flag.String("root", "", "repository root (defaults to discovery from the current directory)")
	check := flag.Bool("check", false, "verify checked-in outputs without writing")
	evidenceBinary := flag.String("evidence-binary", "", "final Go 1.25.7 guest role binary used to issue host-only HL8E")
	evidenceBinariesDir := flag.String("evidence-binaries-dir", "", "directory of complete final linux/amd64 guest role binaries used to issue host-only HL8E")
	flag.Parse()

	root := *rootFlag
	if root == "" {
		var err error
		root, err = discoverRepositoryRoot()
		if err != nil {
			fatal(err)
		}
	}
	outputs, err := generate(root)
	if err != nil {
		fatal(err)
	}
	var evidence generatedEvidence
	if *evidenceBinary != "" || *evidenceBinariesDir != "" {
		evidence, err = generateEvidenceFromInputs(root, evidenceInputs{binaryPath: *evidenceBinary, binariesDir: *evidenceBinariesDir}, outputs)
		if err != nil {
			fatal(err)
		}
	}
	if *check {
		if err := checkOutputs(root, outputs); err != nil {
			fatal(err)
		}
		if *evidenceBinary != "" || *evidenceBinariesDir != "" {
			if err := checkFileMap(root, evidence.files()); err != nil {
				fatal(err)
			}
		}
		return
	}
	if err := writeOutputs(root, outputs); err != nil {
		fatal(err)
	}
	if *evidenceBinary != "" || *evidenceBinariesDir != "" {
		if err := writeFileMap(root, evidence.files()); err != nil {
			fatal(err)
		}
	}
}

func generate(root string) (generatedOutputs, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return generatedOutputs{}, fmt.Errorf("resolve root: %w", err)
	}
	rolesBytes, err := readBounded(filepath.Join(root, policyDir, "roles-v1.yaml"), 1<<20)
	if err != nil {
		return generatedOutputs{}, err
	}
	roles, err := decodeRoles(rolesBytes)
	if err != nil {
		return generatedOutputs{}, err
	}
	workload, err := readExactLock(filepath.Join(root, policyDir, "workload-v1.lock"), exactWorkloadLockValues(), "workload-v1.lock")
	if err != nil {
		return generatedOutputs{}, err
	}
	runtimeLock, err := readExactLock(filepath.Join(root, policyDir, "runtime-go1.25.7.lock"), exactRuntimeLockValues(), "runtime-go1.25.7.lock")
	if err != nil {
		return generatedOutputs{}, err
	}
	catalogLock, err := readExactLock(filepath.Join(root, policyDir, "catalog-xsys-v0.41.0.lock"), exactCatalogLockValues(), "catalog-xsys-v0.41.0.lock")
	if err != nil {
		return generatedOutputs{}, err
	}
	generatorExecutableSHA256, err := readDigestFile(filepath.Join(root, policyDir, "generator-linux-amd64.sha256"))
	if err != nil {
		return generatedOutputs{}, err
	}

	if err := validateLockedFile(root, workload["l4_path"], workload["l4_sha256"]); err != nil {
		return generatedOutputs{}, fmt.Errorf("L4 lock: %w", err)
	}
	if err := validateLockedFile(root, workload["l7_path"], workload["l7_sha256"]); err != nil {
		return generatedOutputs{}, fmt.Errorf("L7 lock: %w", err)
	}
	if runtimeLock["go_version"] != "go1.25.7" || catalogLock["module"] != "golang.org/x/sys@v0.41.0" || catalogLock["source_path"] != "unix/zsysnum_linux_amd64.go" || catalogLock["kernel_ceiling"] != "450" {
		return generatedOutputs{}, errors.New("D7 runtime or catalog identity is not the frozen version")
	}
	if !equalHexDigest(roles.PinnedCallsite.SourceUnitSHA256, runtimeLock["runtime_source_sha256"]) {
		return generatedOutputs{}, errors.New("pinned callsite source does not match the runtime source lock")
	}
	if err := validatePinnedRuntimeSource(root, roles.PinnedCallsite, runtimeLock); err != nil {
		return generatedOutputs{}, err
	}

	catalogSource, err := locateCatalogSource(root, catalogLock)
	if err != nil {
		return generatedOutputs{}, err
	}
	catalog, err := parseCatalog(catalogSource, 450)
	if err != nil {
		return generatedOutputs{}, err
	}
	if len(catalog) == 0 || len(catalog) > 512 {
		return generatedOutputs{}, fmt.Errorf("catalog entry count %d is outside D7 bounds", len(catalog))
	}

	roleFSMSourceSHA256 := sha256.Sum256(rolesBytes)
	generatorSourceSHA256, err := hashGeneratorSources(root)
	if err != nil {
		return generatedOutputs{}, err
	}
	phaseHeadSourceSHA256, err := hashPhaseSources(root)
	if err != nil {
		return generatedOutputs{}, err
	}
	l4SHA256, err := parseDigest(workload["l4_sha256"])
	if err != nil {
		return generatedOutputs{}, fmt.Errorf("L4 digest: %w", err)
	}
	l7SHA256, err := parseDigest(workload["l7_sha256"])
	if err != nil {
		return generatedOutputs{}, fmt.Errorf("L7 digest: %w", err)
	}
	runtimeSourceSHA256, err := parseDigest(runtimeLock["runtime_source_sha256"])
	if err != nil {
		return generatedOutputs{}, fmt.Errorf("runtime source digest: %w", err)
	}
	toolchainSHA256, err := parseDigest(runtimeLock["toolchain_archive_sha256"])
	if err != nil {
		return generatedOutputs{}, fmt.Errorf("toolchain digest: %w", err)
	}
	catalogSourceSHA256, err := parseDigest(catalogLock["source_sha256"])
	if err != nil {
		return generatedOutputs{}, fmt.Errorf("catalog digest: %w", err)
	}

	workloadLockSHA256 := framedSHA256("hal/l8/syscall-workload-source-lock/linux-amd64/v1", joinDigests(l4SHA256, l7SHA256, roleFSMSourceSHA256, generatorSourceSHA256))
	runtimePreimage := append([]byte{byte(len("go1.25.7"))}, "go1.25.7"...)
	runtimePreimage = append(runtimePreimage, joinDigests(runtimeSourceSHA256, roleFSMSourceSHA256, generatorSourceSHA256)...)
	runtimeSourceLockSHA256 := framedSHA256("hal/l8/syscall-runtime-source-lock/linux-amd64/v1", runtimePreimage)
	catalogPreimage := append([]byte{byte(len(catalogLock["module"]))}, catalogLock["module"]...)
	catalogPreimage = append(catalogPreimage, byte(len(catalogLock["source_path"])))
	catalogPreimage = append(catalogPreimage, catalogLock["source_path"]...)
	ceiling := make([]byte, 4)
	binary.BigEndian.PutUint32(ceiling, 450)
	catalogPreimage = append(catalogPreimage, ceiling...)
	catalogPreimage = append(catalogPreimage, joinDigests(catalogSourceSHA256, generatorSourceSHA256)...)
	catalogSourceLockSHA256 := framedSHA256("hal/l8/syscall-catalog-source-lock/linux-amd64/v1", catalogPreimage)

	catalogBody, catalogNumbers, err := encodeCatalog(catalog, catalogLock)
	if err != nil {
		return generatedOutputs{}, err
	}
	rolesBody, workloadRuleIndex, runtimeRuleIndexes, err := encodeRoles(roles, catalogNumbers, toolchainSHA256)
	if err != nil {
		return generatedOutputs{}, err
	}
	ancestryBody := encodeAncestry()
	workloadBody := encodeWorkload(workloadLockSHA256, l4SHA256, l7SHA256, workloadRuleIndex)
	runtimeBody := encodeRuntime(runtimeSourceSHA256, runtimeSourceLockSHA256, runtimeRuleIndexes)
	sections := [6][]byte{catalogBody, rolesBody, ancestryBody, workloadBody, runtimeBody}
	provenanceBody := encodeProvenance([11][32]byte{
		phaseHeadSourceSHA256,
		roleFSMSourceSHA256,
		workloadLockSHA256,
		runtimeSourceLockSHA256,
		catalogSourceLockSHA256,
		generatorSourceSHA256,
		generatorExecutableSHA256,
		toolchainSHA256,
		sha256.Sum256(workloadBody),
		sha256.Sum256(runtimeBody),
		sha256.Sum256(catalogBody),
	})
	sections[5] = provenanceBody
	sourceLockSHA256 := framedSHA256("hal/l8/verified-policy-source-lock/linux-amd64/v1", joinDigests(
		phaseHeadSourceSHA256,
		roleFSMSourceSHA256,
		workloadLockSHA256,
		runtimeSourceLockSHA256,
		catalogSourceLockSHA256,
		generatorSourceSHA256,
		generatorExecutableSHA256,
		toolchainSHA256,
	))
	artifact := encodeEnvelope(catalogSourceSHA256, sourceLockSHA256, [6]uint16{uint16(len(catalog)), 10, 2, uint16(1), uint16(len(runtimeRuleIndexes)), 11}, sections)
	artifactSHA256 := framedSHA256("hal/l8/verified-syscall-policy/linux-amd64/v1", artifact)
	guestSource, err := encodeGuestSource(artifact, artifactSHA256, sourceLockSHA256)
	if err != nil {
		return generatedOutputs{}, err
	}
	d4InstallSource, err := encodeD4InstallInventorySource(roles, catalogNumbers)
	if err != nil {
		return generatedOutputs{}, err
	}
	return generatedOutputs{
		artifact:         artifact,
		guestSource:      guestSource,
		d4InstallSource:  d4InstallSource,
		artifactSHA256:   artifactSHA256,
		sourceLockSHA256: sourceLockSHA256,
	}, nil
}

func decodeRoles(encoded []byte) (rolesDocument, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var document rolesDocument
	if err := decoder.Decode(&document); err != nil {
		return rolesDocument{}, fmt.Errorf("decode roles-v1.yaml: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return rolesDocument{}, errors.New("roles-v1.yaml has trailing or malformed JSON")
	}
	wantRoles := exactRoles()
	if document.Schema != "hal-l8-policy-roles-v1" || len(document.Roles) != len(wantRoles) {
		return rolesDocument{}, errors.New("roles-v1.yaml does not contain the exact ten-role schema")
	}
	for index, role := range document.Roles {
		if role != wantRoles[index] {
			return rolesDocument{}, fmt.Errorf("role row %d does not match the exact ordered D7 rule", index)
		}
	}
	if document.PinnedCallsite != exactPinnedCallsite() {
		return rolesDocument{}, errors.New("pinned callsite record does not match the exact D7 input")
	}
	instruction, err := hex.DecodeString(document.PinnedCallsite.InstructionHex)
	if err != nil || len(instruction) == 0 || len(instruction) > 4096 {
		return rolesDocument{}, errors.New("pinned callsite instruction is invalid")
	}
	return document, nil
}

func encodeCatalog(entries []catalogEntry, lock map[string]string) ([]byte, map[string]uint32, error) {
	body := new(bytes.Buffer)
	module := lock["module"]
	path := lock["source_path"]
	body.WriteByte(byte(len(module)))
	body.WriteByte(byte(len(path)))
	writeUint16(body, 0)
	writeUint32(body, 450)
	body.WriteString(module)
	body.WriteString(path)
	numbers := make(map[string]uint32, len(entries))
	for _, entry := range entries {
		if _, exists := numbers[entry.name]; exists {
			return nil, nil, fmt.Errorf("duplicate catalog name %q", entry.name)
		}
		numbers[entry.name] = entry.number
		writeUint32(body, entry.number)
		class := byte(2)
		if entry.name == "read" {
			class = 1
		}
		body.WriteByte(class)
		body.WriteByte(byte(len(entry.name)))
		body.WriteByte(0)
		body.WriteByte(0)
		body.WriteString(entry.name)
	}
	return body.Bytes(), numbers, nil
}

func encodeRoles(document rolesDocument, catalog map[string]uint32, toolchainSHA256 [32]byte) ([]byte, uint32, []uint32, error) {
	edges := map[uint8][]uint8{
		1: {2},
		2: {3, 5, 7, 9},
		3: {4},
		5: {6},
		7: {8},
		9: {10},
	}
	body := new(bytes.Buffer)
	var workloadIndex uint32
	var runtimeIndexes []uint32
	var ruleIndex uint32
	for _, role := range document.Roles {
		number, ok := catalog[role.Syscall]
		if !ok {
			return nil, 0, nil, fmt.Errorf("role %s references absent syscall %q", role.Name, role.Syscall)
		}
		body.WriteByte(role.ID)
		body.WriteByte(1)
		writeUint16(body, uint16(len(edges[role.ID])))
		writeUint32(body, 1)
		body.WriteByte(role.Stage)
		body.Write(make([]byte, 7))
		writeUint64(body, 0)
		writeUint64(body, 0)
		for _, toRole := range edges[role.ID] {
			body.WriteByte(role.Stage)
			body.WriteByte(toRole)
			body.WriteByte(role.Stage)
			body.WriteByte(0)
			for index := 0; index < 4; index++ {
				writeUint64(body, 0)
			}
		}
		body.WriteByte(role.ID)
		body.WriteByte(role.Stage)
		body.WriteByte(role.Origin)
		body.WriteByte(role.Path)
		body.WriteByte(1)
		pinnedCount := byte(0)
		if role.PinnedRuntimeCallsite {
			pinnedCount = 1
		}
		body.WriteByte(pinnedCount)
		writeUint16(body, 0)
		writeUint64(body, 0)
		writeUint64(body, 0)
		writeUint32(body, number)
		writeUint32(body, 0)
		body.Write([]byte{0, 0, 0, 0})
		if role.PinnedRuntimeCallsite {
			row, err := encodePinnedRequirement(document.PinnedCallsite, toolchainSHA256, role.Origin == 3)
			if err != nil {
				return nil, 0, nil, err
			}
			body.Write(row)
		}
		if role.Origin == 2 {
			workloadIndex = ruleIndex
		}
		if role.Origin == 3 {
			runtimeIndexes = append(runtimeIndexes, ruleIndex)
		}
		ruleIndex++
	}
	if len(runtimeIndexes) == 0 || workloadIndex == 0 {
		return nil, 0, nil, errors.New("roles omit runtime or workload authority")
	}
	return body.Bytes(), workloadIndex, runtimeIndexes, nil
}

func encodePinnedRequirement(callsite callsiteInput, toolchainSHA256 [32]byte, runtimeOrigin bool) ([]byte, error) {
	sourceSHA256, err := parseDigest(callsite.SourceUnitSHA256)
	if err != nil {
		return nil, fmt.Errorf("pinned source digest: %w", err)
	}
	instruction, err := hex.DecodeString(callsite.InstructionHex)
	if err != nil {
		return nil, fmt.Errorf("pinned instruction: %w", err)
	}
	row := new(bytes.Buffer)
	writeUint16(row, 0)
	row.WriteByte(2)
	row.WriteByte(0)
	writeUint32(row, uint32(len(instruction)))
	writeUint32(row, uint32(len(instruction)))
	checks := uint32(1) << (20 - 1)
	if runtimeOrigin {
		checks |= uint32(1) << (16 - 1)
	}
	writeUint32(row, checks)
	writeUint16(row, uint16(len(instruction)))
	writeUint16(row, 0)
	row.Write(sourceSHA256[:])
	argumentSHA256 := framedSHA256("hal/l8/pinned-callsite-argument-template/linux-amd64/v1", []byte(callsite.ArgumentTemplate))
	row.Write(argumentSHA256[:])
	instructionSHA256 := sha256.Sum256(instruction)
	row.Write(instructionSHA256[:])
	row.Write(toolchainSHA256[:])
	return row.Bytes(), nil
}

func encodeAncestry() []byte {
	filterRow := make([]byte, 8)
	preimage := make([]byte, 4, 12)
	binary.BigEndian.PutUint32(preimage[:4], 1)
	preimage = append(preimage, filterRow...)
	unionSHA256 := framedSHA256("hal/l8/syscall-filter-projection/linux-amd64/v1", preimage)
	body := new(bytes.Buffer)
	for _, record := range []struct {
		ancestor    uint8
		descendants []uint8
	}{
		{ancestor: 2, descendants: []uint8{3, 4, 5, 6, 7, 8, 9, 10}},
		{ancestor: 9, descendants: []uint8{10}},
	} {
		body.WriteByte(record.ancestor)
		body.WriteByte(byte(len(record.descendants)))
		writeUint16(body, 0)
		body.Write(unionSHA256[:])
		body.Write(record.descendants)
	}
	return body.Bytes()
}

func encodeWorkload(sourceLock, l4, l7 [32]byte, ruleIndex uint32) []byte {
	body := new(bytes.Buffer)
	body.Write(sourceLock[:])
	body.Write(l4[:])
	body.Write(l7[:])
	writeUint32(body, ruleIndex)
	return body.Bytes()
}

func encodeRuntime(source, sourceLock [32]byte, ruleIndexes []uint32) []byte {
	body := new(bytes.Buffer)
	body.WriteByte(byte(len("go1.25.7")))
	body.Write([]byte{0, 0, 0})
	body.Write(source[:])
	body.Write(sourceLock[:])
	body.WriteString("go1.25.7")
	for _, index := range ruleIndexes {
		writeUint32(body, index)
	}
	return body.Bytes()
}

func encodeProvenance(digests [11][32]byte) []byte {
	body := new(bytes.Buffer)
	for _, digest := range digests {
		body.Write(digest[:])
	}
	return body.Bytes()
}

func encodeEnvelope(catalogSHA256, sourceLockSHA256 [32]byte, counts [6]uint16, bodies [6][]byte) []byte {
	sections := new(bytes.Buffer)
	for index, body := range bodies {
		sections.WriteByte(byte(index + 1))
		sections.WriteByte(0)
		writeUint16(sections, counts[index])
		writeUint32(sections, uint32(len(body)))
		digest := sha256.Sum256(body)
		sections.Write(digest[:])
		sections.Write(body)
	}
	header := make([]byte, 84)
	copy(header[:4], "HL8Q")
	header[4] = 1
	header[5] = 1
	binary.BigEndian.PutUint16(header[8:10], 6)
	binary.BigEndian.PutUint16(header[10:12], 1)
	binary.BigEndian.PutUint16(header[12:14], 178)
	binary.BigEndian.PutUint16(header[14:16], 6)
	binary.BigEndian.PutUint32(header[16:20], uint32(sections.Len()))
	copy(header[20:52], catalogSHA256[:])
	copy(header[52:84], sourceLockSHA256[:])
	return append(header, sections.Bytes()...)
}

func encodeGuestSource(artifact []byte, artifactSHA256, sourceLockSHA256 [32]byte) ([]byte, error) {
	var source bytes.Buffer
	source.WriteString("// Code generated by tools/microvm/l8/policy/generate; DO NOT EDIT.\n")
	source.WriteString("//go:build l8_verified_policy_artifact\n\n")
	source.WriteString("package syscallpolicy\n\n")
	fmt.Fprintf(&source, "var embeddedVerifiedPolicyArtifactBytes = %#v\n\n", artifact)
	fmt.Fprintf(&source, "var embeddedVerifiedPolicyArtifactSHA256 = %#v\n\n", artifactSHA256)
	fmt.Fprintf(&source, "var embeddedVerifiedPolicySourceLockSHA256 = %#v\n\n", sourceLockSHA256)
	source.WriteString("func EmbeddedVerifiedPolicyArtifact() (VerifiedPolicyArtifact, error) {\n")
	source.WriteString("\texpected := ExpectedPolicyArtifact{sha256: embeddedVerifiedPolicyArtifactSHA256, issuer: expectedIssuer{issued: true}}\n")
	source.WriteString("\tartifact, err := ImportVerifiedPolicyArtifact(embeddedVerifiedPolicyArtifactBytes, expected)\n")
	source.WriteString("\tif err != nil { return VerifiedPolicyArtifact{}, err }\n")
	source.WriteString("\tif artifact.SourceLockSHA256() != embeddedVerifiedPolicySourceLockSHA256 { return VerifiedPolicyArtifact{}, contractError(ErrorCodeDigestMismatch) }\n")
	source.WriteString("\treturn artifact, nil\n")
	source.WriteString("}\n")
	formatted, err := format.Source(source.Bytes())
	if err != nil {
		return nil, fmt.Errorf("format generated guest source: %w", err)
	}
	return formatted, nil
}

func encodeD4InstallInventorySource(document rolesDocument, catalog map[string]uint32) ([]byte, error) {
	bindings := exactD4InstallBindings()
	preimage := make([]byte, 4+len(bindings)*4)
	binary.BigEndian.PutUint16(preimage[:2], uint16(len(bindings)))
	for index, binding := range bindings {
		offset := 4 + index*4
		preimage[offset] = binding.installRole
		preimage[offset+1] = binding.policyRole
		preimage[offset+2] = binding.binaryKind
	}
	digest := framedSHA256("hal/l8/d4-native-install-table/linux-amd64/v1", preimage)

	var source bytes.Buffer
	source.WriteString("// Code generated by tools/microvm/l8/policy/generate; DO NOT EDIT.\n\n")
	source.WriteString("package linux\n\n")
	source.WriteString("func generatedPolicyInstallInventory() ([5]policyInstallBinding, [32]byte) {\n")
	source.WriteString("\treturn [5]policyInstallBinding{\n")
	for _, binding := range bindings {
		fmt.Fprintf(&source, "\t\t{installRole: %d, policyRole: %d, binaryKind: %d},\n", binding.installRole, binding.policyRole, binding.binaryKind)
	}
	fmt.Fprintf(&source, "\t}, %#v\n", digest)
	source.WriteString("}\n\n")
	source.WriteString("func generatedPolicyAdapterCallsiteInventory() []policyAdapterCallsite {\n")
	source.WriteString("\treturn []policyAdapterCallsite{\n")
	for _, role := range document.Roles {
		if role.Path != 2 {
			continue
		}
		number, ok := catalog[role.Syscall]
		if !ok {
			return nil, fmt.Errorf("D4 adapter callsite role %s references absent syscall %q", role.Name, role.Syscall)
		}
		fmt.Fprintf(&source, "\t\t{role: %d, stage: %d, rawSyscallNumber: %d},\n", role.ID, role.Stage, number)
	}
	source.WriteString("\t}\n")
	source.WriteString("}\n")
	formatted, err := format.Source(source.Bytes())
	if err != nil {
		return nil, fmt.Errorf("format D4 install inventory source: %w", err)
	}
	return formatted, nil
}

func locateCatalogSource(root string, lock map[string]string) ([]byte, error) {
	modulePath := strings.TrimPrefix(lock["module"], "golang.org/x/sys@")
	if modulePath == lock["module"] {
		return nil, errors.New("catalog module lock is malformed")
	}
	command := exec.Command("go", "env", "GOMODCACHE")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("locate Go module cache: %w", err)
	}
	path := filepath.Join(strings.TrimSpace(string(output)), "golang.org", "x", "sys@"+modulePath, filepath.FromSlash(lock["source_path"]))
	encoded, err := readBounded(path, 4<<20)
	if err != nil {
		return nil, fmt.Errorf("read pinned x/sys catalog source: %w", err)
	}
	want, err := parseDigest(lock["source_sha256"])
	if err != nil {
		return nil, err
	}
	if sha256.Sum256(encoded) != want {
		return nil, errors.New("pinned x/sys catalog source digest mismatch")
	}
	return encoded, nil
}

var syscallAssignment = regexp.MustCompile(`(?m)^\s*SYS_([A-Z0-9_]+)\s*=\s*([0-9]+)\s*$`)

func parseCatalog(source []byte, ceiling uint32) ([]catalogEntry, error) {
	matches := syscallAssignment.FindAllSubmatch(source, -1)
	entries := make([]catalogEntry, 0, len(matches))
	seenNumbers := make(map[uint32]struct{})
	for _, match := range matches {
		number64, err := strconv.ParseUint(string(match[2]), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parse syscall number: %w", err)
		}
		number := uint32(number64)
		if number > ceiling {
			continue
		}
		name := strings.ToLower(string(match[1]))
		if strings.HasPrefix(name, "_") && (number != 156 || name != "_sysctl") {
			return nil, fmt.Errorf("unsupported leading-underscore syscall row %d,%s", number, name)
		}
		if len(name) == 0 || len(name) > 64 {
			return nil, fmt.Errorf("syscall name %q is outside bounds", name)
		}
		if _, duplicate := seenNumbers[number]; duplicate {
			return nil, fmt.Errorf("duplicate syscall number %d", number)
		}
		seenNumbers[number] = struct{}{}
		entries = append(entries, catalogEntry{number: number, name: name})
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].number < entries[right].number })
	return entries, nil
}

func hashGeneratorSources(root string) ([32]byte, error) {
	return hashPaths(root, []string{
		filepath.Join(policyDir, "generate", "elf.go"),
		filepath.Join(policyDir, "generate", "evidence.go"),
		filepath.Join(policyDir, "generate", "graph.go"),
		filepath.Join(policyDir, "generate", "main.go"),
	})
}

func hashPhaseSources(root string) ([32]byte, error) {
	var paths []string
	for _, directory := range []string{
		guestDir,
		"internal/sandboxruntime/microvm/guestagent/rolebootstrap",
		d4LinuxDir,
	} {
		entries, err := os.ReadDir(filepath.Join(root, directory))
		if err != nil {
			return [32]byte{}, fmt.Errorf("read phase source directory %s: %w", directory, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "artifact_expected_d7_gen.go" || name == "pinned_callsite_evidence_expected_d7_gen.go" || name == "policy_install_inventory_d7_gen.go" || name == "generated_artifact_d7_gen.go" {
				continue
			}
			paths = append(paths, filepath.Join(directory, name))
		}
	}
	paths = append(paths, "cmd/hal-guest-init/main_linux.go")
	sort.Strings(paths)
	return hashPaths(root, paths)
}

func hashPaths(root string, paths []string) ([32]byte, error) {
	preimage := new(bytes.Buffer)
	for _, path := range paths {
		encoded, err := readBounded(filepath.Join(root, path), 8<<20)
		if err != nil {
			return [32]byte{}, err
		}
		if len(path) > 65535 {
			return [32]byte{}, errors.New("source path is too long")
		}
		writeUint16(preimage, uint16(len(path)))
		preimage.WriteString(filepath.ToSlash(path))
		writeUint64(preimage, uint64(len(encoded)))
		preimage.Write(encoded)
	}
	return framedSHA256("hal/l8/phase-source-set/linux-amd64/v1", preimage.Bytes()), nil
}

func readExactLock(path string, expected map[string]string, label string) (map[string]string, error) {
	encoded, err := readBounded(path, 1<<20)
	if err != nil {
		return nil, err
	}
	return decodeExactLock(encoded, expected, label)
}

func decodeExactLock(encoded []byte, expected map[string]string, label string) (map[string]string, error) {
	if len(encoded) == 0 || encoded[len(encoded)-1] != '\n' || bytes.ContainsRune(encoded, '\r') {
		return nil, fmt.Errorf("%s must end in one LF and contain no CR", label)
	}
	result := make(map[string]string)
	for lineIndex, line := range strings.Split(string(encoded[:len(encoded)-1]), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || value == "" || strings.TrimSpace(key) != key || strings.TrimSpace(value) != value {
			return nil, fmt.Errorf("invalid lock line %d in %s", lineIndex+1, label)
		}
		if _, duplicate := result[key]; duplicate {
			return nil, fmt.Errorf("duplicate lock key %q", key)
		}
		want, allowed := expected[key]
		if !allowed {
			return nil, fmt.Errorf("unknown lock key %q in %s", key, label)
		}
		if value != want {
			return nil, fmt.Errorf("lock key %q in %s does not match its exact value", key, label)
		}
		result[key] = value
	}
	if len(result) != len(expected) {
		return nil, fmt.Errorf("%s has %d keys, want %d", label, len(result), len(expected))
	}
	for key := range expected {
		if _, present := result[key]; !present {
			return nil, fmt.Errorf("%s is missing lock key %q", label, key)
		}
	}
	return result, nil
}

func validateLockedFile(root, relativePath, digestText string) error {
	if relativePath == "" || filepath.IsAbs(relativePath) || filepath.Clean(relativePath) != relativePath || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
		return errors.New("locked path is not a canonical repository-relative path")
	}
	encoded, err := readBounded(filepath.Join(root, relativePath), 8<<20)
	if err != nil {
		return err
	}
	want, err := parseDigest(digestText)
	if err != nil {
		return err
	}
	if sha256.Sum256(encoded) != want {
		return fmt.Errorf("locked source %s digest mismatch", filepath.ToSlash(relativePath))
	}
	return nil
}

func checkOutputs(root string, outputs generatedOutputs) error {
	return checkFileMap(root, outputs.files())
}

func checkFileMap(root string, files map[string][]byte) error {
	for path, want := range files {
		if len(want) == 0 {
			return fmt.Errorf("D7 output %s is unexpectedly empty", path)
		}
		got, err := readBounded(filepath.Join(root, path), int64(len(want)))
		if err != nil {
			return fmt.Errorf("read output %s: %w", path, err)
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("D7 output %s is stale", path)
		}
	}
	return nil
}

func writeOutputs(root string, outputs generatedOutputs) error {
	return writeFileMap(root, outputs.files())
}

func writeFileMap(root string, files map[string][]byte) error {
	for path, encoded := range files {
		absolute := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
		temporary, err := os.CreateTemp(filepath.Dir(absolute), ".l8-d7-*")
		if err != nil {
			return fmt.Errorf("create temporary output: %w", err)
		}
		temporaryPath := temporary.Name()
		cleanup := func() { _ = os.Remove(temporaryPath) }
		if _, err := temporary.Write(encoded); err != nil {
			_ = temporary.Close()
			cleanup()
			return fmt.Errorf("write temporary output: %w", err)
		}
		if err := temporary.Chmod(0o644); err != nil {
			_ = temporary.Close()
			cleanup()
			return fmt.Errorf("chmod temporary output: %w", err)
		}
		if err := temporary.Close(); err != nil {
			cleanup()
			return fmt.Errorf("close temporary output: %w", err)
		}
		if err := os.Rename(temporaryPath, absolute); err != nil {
			cleanup()
			return fmt.Errorf("replace output %s: %w", path, err)
		}
	}
	return nil
}

func discoverRepositoryRoot() (string, error) {
	current, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", errors.New("repository root not found")
		}
		current = parent
	}
}

func readBounded(path string, maximum int64) ([]byte, error) {
	return readBoundedWithIdentityHook(path, maximum, nil)
}

// readBoundedWithIdentityHook pins one regular-file identity before reading it.
// The hook exists only so tests can deterministically replace the pathname
// after the descriptor has been pinned; production callers always pass nil.
func readBoundedWithIdentityHook(path string, maximum int64, afterOpen func()) ([]byte, error) {
	if maximum <= 0 || maximum == int64(^uint64(0)>>1) {
		return nil, fmt.Errorf("file %s has an invalid read bound", path)
	}
	initial, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if initial.Mode()&os.ModeSymlink != 0 || !initial.Mode().IsRegular() || initial.Size() <= 0 || initial.Size() > maximum {
		return nil, fmt.Errorf("file %s is outside bounds", path)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open no-follow %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("open no-follow %s returned no file", path)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("fstat %s: %w", path, err)
	}
	if !opened.Mode().IsRegular() || opened.Size() <= 0 || opened.Size() > maximum || !os.SameFile(initial, opened) {
		return nil, fmt.Errorf("file %s changed identity or is outside bounds", path)
	}
	if afterOpen != nil {
		afterOpen()
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(encoded)) != opened.Size() || int64(len(encoded)) > maximum {
		return nil, fmt.Errorf("file %s changed size or has trailing bytes", path)
	}
	afterRead, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("fstat after read %s: %w", path, err)
	}
	if !os.SameFile(opened, afterRead) || afterRead.Size() != opened.Size() || !afterRead.Mode().IsRegular() {
		return nil, fmt.Errorf("file %s changed while being read", path)
	}
	current, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("restat %s: %w", path, err)
	}
	if current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) {
		return nil, fmt.Errorf("file %s changed pathname identity while being read", path)
	}
	return encoded, nil
}

func readDigestFile(path string) ([32]byte, error) {
	encoded, err := readBounded(path, 65)
	if err != nil {
		return [32]byte{}, err
	}
	if len(encoded) != 65 || encoded[64] != '\n' {
		return [32]byte{}, errors.New("digest file must be 64 lowercase hexadecimal bytes plus LF")
	}
	return parseDigest(string(encoded[:64]))
}

func parseDigest(value string) ([32]byte, error) {
	var result [32]byte
	if len(value) != 64 || strings.ToLower(value) != value {
		return result, errors.New("digest must be 64 lowercase hexadecimal bytes")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return result, errors.New("digest must be lowercase hexadecimal")
	}
	copy(result[:], decoded)
	if result == ([32]byte{}) {
		return [32]byte{}, errors.New("digest must be nonzero")
	}
	return result, nil
}

func equalHexDigest(left, right string) bool {
	leftDigest, leftErr := parseDigest(left)
	rightDigest, rightErr := parseDigest(right)
	return leftErr == nil && rightErr == nil && leftDigest == rightDigest
}

func framedSHA256(domain string, preimage []byte) [32]byte {
	encoded := make([]byte, 2, 2+len(domain)+len(preimage))
	binary.BigEndian.PutUint16(encoded[:2], uint16(len(domain)))
	encoded = append(encoded, domain...)
	encoded = append(encoded, preimage...)
	return sha256.Sum256(encoded)
}

func joinDigests(digests ...[32]byte) []byte {
	result := make([]byte, 0, len(digests)*sha256.Size)
	for _, digest := range digests {
		result = append(result, digest[:]...)
	}
	return result
}

func digestLine(digest [32]byte) []byte { return []byte(hex.EncodeToString(digest[:]) + "\n") }

func writeUint16(buffer *bytes.Buffer, value uint16) {
	_ = binary.Write(buffer, binary.BigEndian, value)
}
func writeUint32(buffer *bytes.Buffer, value uint32) {
	_ = binary.Write(buffer, binary.BigEndian, value)
}
func writeUint64(buffer *bytes.Buffer, value uint64) {
	_ = binary.Write(buffer, binary.BigEndian, value)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "l8 policy generation failed:", err)
	os.Exit(1)
}
