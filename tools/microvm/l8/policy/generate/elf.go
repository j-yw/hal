package main

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxGuestBinaryBytes        = 64 << 20
	pinnedGoRuntimeSymbol      = "internal/runtime/syscall.Syscall6"
	pinnedInstructionOffset    = 12
	guestModulePrefix          = "github.com/jywlabs/hal/"
	requiredGoToolchainVersion = "go1.25.7"
	guestInitBinaryName        = "hal-init"
	guestAgentBinaryName       = "hal-guest-agent"
	guestHelperBinaryName      = "hal-guest-credential-helper"
	guestMonitorBinaryName     = "hal-guest-mount-monitor"
	guestShimBinaryName        = "hal-guest-workload-shim"
	guestBootstrapBinaryName   = "hal-guest-role-bootstrap"
	guestInitPackagePath       = guestModulePrefix + "cmd/hal-guest-init"
	guestAgentPackagePath      = guestModulePrefix + "cmd/hal-guest-agent"
	guestHelperPackagePath     = guestModulePrefix + "cmd/hal-guest-credential-helper"
	guestMonitorPackagePath    = guestModulePrefix + "cmd/hal-guest-mount-monitor"
	guestShimPackagePath       = guestModulePrefix + "cmd/hal-guest-workload-shim"
)

var pinnedSyscallInstruction = []byte{0x0f, 0x05}

type evidenceInputs struct {
	binaryPath  string
	binariesDir string
}

type requiredGuestRoleBinary struct {
	name   string
	goPath string
	native bool
}

type inspectedGuestBinary struct {
	name                 string
	binarySHA256         [32]byte
	executableText       []byte
	executableTextSHA256 [32]byte
	textLength           uint64
	goPath               string
	goVersion            string
	native               bool
	hasGoRuntime         bool
	syscall6Found        bool
	syscall6TextOffset   uint64
	instruction          []byte
}

func requiredGuestRoleBinaries() []requiredGuestRoleBinary {
	return []requiredGuestRoleBinary{
		{name: guestInitBinaryName, goPath: guestInitPackagePath},
		{name: guestAgentBinaryName, goPath: guestAgentPackagePath},
		{name: guestHelperBinaryName, goPath: guestHelperPackagePath},
		{name: guestMonitorBinaryName, goPath: guestMonitorPackagePath},
		{name: guestShimBinaryName, goPath: guestShimPackagePath},
		{name: guestBootstrapBinaryName, native: true},
	}
}

func generateEvidenceFromInputs(root string, inputs evidenceInputs, outputs generatedOutputs) (generatedEvidence, error) {
	_ = root
	_ = outputs
	if inputs.binaryPath != "" && inputs.binariesDir != "" {
		return generatedEvidence{}, fmt.Errorf("%w: -evidence-binary and -evidence-binaries-dir are mutually exclusive", errEvidenceInputsUnavailable)
	}
	if inputs.binariesDir != "" {
		binaries, err := inspectGuestRoleBinariesDir(inputs.binariesDir)
		if err != nil {
			return generatedEvidence{}, fmt.Errorf("%w: %v", errEvidenceInputsUnavailable, err)
		}
		if err := requireCompleteHonestIssuanceInputs(binaries); err != nil {
			return generatedEvidence{}, fmt.Errorf("%w: %v", errEvidenceInputsUnavailable, err)
		}
		return generatedEvidence{}, fmt.Errorf("%w: unique/reachable D4/D6 call graph is unavailable", errEvidenceInputsUnavailable)
	}
	if inputs.binaryPath != "" {
		if _, err := inspectLinuxAMD64ELF(filepath.Base(inputs.binaryPath), inputs.binaryPath); err != nil {
			return generatedEvidence{}, fmt.Errorf("%w: %v", errEvidenceInputsUnavailable, err)
		}
		return generatedEvidence{}, fmt.Errorf("%w: a singular ELF is not the complete final guest role set", errEvidenceInputsUnavailable)
	}
	return generatedEvidence{}, errEvidenceInputsUnavailable
}

func inspectGuestRoleBinariesDir(dir string) ([]inspectedGuestBinary, error) {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve binaries dir: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, fmt.Errorf("stat binaries dir: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("binaries dir must be a regular directory")
	}
	required := requiredGuestRoleBinaries()
	binaries := make([]inspectedGuestBinary, 0, len(required))
	for _, role := range required {
		path := filepath.Join(absolute, role.name)
		if _, err := os.Lstat(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("missing role binary %s", role.name)
			}
			return nil, fmt.Errorf("stat role binary %s: %w", role.name, err)
		}
		inspected, err := inspectLinuxAMD64ELF(role.name, path)
		if err != nil {
			return nil, fmt.Errorf("inspect %s: %w", role.name, err)
		}
		if err := matchRequiredGuestRoleIdentity(role, inspected); err != nil {
			return nil, err
		}
		binaries = append(binaries, inspected)
	}
	return binaries, nil
}

func matchRequiredGuestRoleIdentity(role requiredGuestRoleBinary, binary inspectedGuestBinary) error {
	if role.native {
		if !binary.native || binary.hasGoRuntime || binary.goPath != "" {
			return fmt.Errorf("role binary %s is not the native bootstrap identity", role.name)
		}
		return nil
	}
	if binary.native || !binary.hasGoRuntime {
		return fmt.Errorf("role binary %s is not a pinned Go 1.25.7 guest role", role.name)
	}
	if binary.goPath != role.goPath {
		return fmt.Errorf("role binary %s identity %q is not %s", role.name, binary.goPath, role.goPath)
	}
	if binary.goVersion != requiredGoToolchainVersion {
		return fmt.Errorf("role binary %s toolchain %q is not %s", role.name, binary.goVersion, requiredGoToolchainVersion)
	}
	return nil
}

func requireCompleteHonestIssuanceInputs(binaries []inspectedGuestBinary) error {
	required := requiredGuestRoleBinaries()
	if len(binaries) != len(required) {
		return fmt.Errorf("guest role set has %d binaries, want %d", len(binaries), len(required))
	}
	byName := make(map[string]inspectedGuestBinary, len(binaries))
	for _, binary := range binaries {
		byName[binary.name] = binary
	}
	for _, role := range required {
		binary, ok := byName[role.name]
		if !ok {
			return fmt.Errorf("missing role binary %s", role.name)
		}
		if err := matchRequiredGuestRoleIdentity(role, binary); err != nil {
			return err
		}
	}
	launchBase, ok := byName[guestInitBinaryName]
	if !ok {
		return fmt.Errorf("missing role binary %s", guestInitBinaryName)
	}
	if err := provePinnedGoRuntimeCallsite(launchBase); err != nil {
		return err
	}
	if err := proveUniquePinnedSyscallGraph(launchBase); err != nil {
		return err
	}
	return errors.New("unique/reachable D4/D6 call graph is unavailable")
}

func provePinnedGoRuntimeCallsite(binary inspectedGuestBinary) error {
	if !binary.syscall6Found {
		return fmt.Errorf("role binary %s is missing %s", binary.name, pinnedGoRuntimeSymbol)
	}
	if !bytes.Equal(binary.instruction, pinnedSyscallInstruction) {
		return fmt.Errorf("role binary %s instruction %s is not source-derived 0f05", binary.name, hex.EncodeToString(binary.instruction))
	}
	end := binary.syscall6TextOffset + uint64(len(pinnedSyscallInstruction))
	if end < binary.syscall6TextOffset || end > binary.textLength {
		return fmt.Errorf("role binary %s pinned instruction exceeds executable text", binary.name)
	}
	got := binary.executableText[binary.syscall6TextOffset:end]
	if !bytes.Equal(got, pinnedSyscallInstruction) {
		return fmt.Errorf("role binary %s executable text does not contain source-derived 0f05 at the pinned offset", binary.name)
	}
	return nil
}

func proveUniquePinnedSyscallGraph(binary inspectedGuestBinary) error {
	count := countInstruction(binary.executableText, pinnedSyscallInstruction)
	if count != 1 {
		return fmt.Errorf("role binary %s executable text has %d syscall instructions; unique/reachable D4/D6 call graph is unavailable", binary.name, count)
	}
	return nil
}

func countInstruction(text, instruction []byte) int {
	if len(instruction) == 0 || len(text) < len(instruction) {
		return 0
	}
	count := 0
	for index := 0; index+len(instruction) <= len(text); index++ {
		if bytes.Equal(text[index:index+len(instruction)], instruction) {
			count++
		}
	}
	return count
}

func inspectLinuxAMD64ELF(name, path string) (inspectedGuestBinary, error) {
	encoded, err := readBounded(path, maxGuestBinaryBytes)
	if err != nil {
		return inspectedGuestBinary{}, err
	}
	file, err := elf.NewFile(bytes.NewReader(encoded))
	if err != nil {
		return inspectedGuestBinary{}, fmt.Errorf("parse ELF: %w", err)
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Machine != elf.EM_X86_64 || file.Data != elf.ELFDATA2LSB {
		return inspectedGuestBinary{}, errors.New("ELF is not linux/amd64 little-endian")
	}
	if file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return inspectedGuestBinary{}, errors.New("ELF is not an executable")
	}
	text, err := executableText(file, encoded)
	if err != nil {
		return inspectedGuestBinary{}, err
	}
	if len(text) == 0 {
		return inspectedGuestBinary{}, errors.New("ELF has no executable text")
	}
	result := inspectedGuestBinary{
		name:                 name,
		binarySHA256:         sha256.Sum256(encoded),
		executableText:       append([]byte(nil), text...),
		executableTextSHA256: sha256.Sum256(text),
		textLength:           uint64(len(text)),
		native:               isNativeBootstrapELF(file, encoded),
		hasGoRuntime:         file.Section(".gopclntab") != nil || file.Section(".go.buildinfo") != nil,
	}
	if info, err := buildinfo.Read(bytes.NewReader(encoded)); err == nil {
		result.goPath = info.Path
		result.goVersion = info.GoVersion
		result.hasGoRuntime = true
		result.native = false
	}
	value, size, err := lookupGoFunc(file, pinnedGoRuntimeSymbol)
	if err == nil {
		fileOff, textOff, err := mapVirtualAddress(file, encoded, value)
		if err != nil {
			return inspectedGuestBinary{}, err
		}
		pinnedInstructionEnd := pinnedInstructionOffset + uint64(len(pinnedSyscallInstruction))
		if pinnedInstructionEnd < pinnedInstructionOffset || size < pinnedInstructionEnd {
			return inspectedGuestBinary{}, fmt.Errorf("%s is shorter than the pinned offset and instruction", pinnedGoRuntimeSymbol)
		}
		instructionFileOff := fileOff + pinnedInstructionOffset
		if instructionFileOff < fileOff || instructionFileOff+uint64(len(pinnedSyscallInstruction)) > uint64(len(encoded)) {
			return inspectedGuestBinary{}, fmt.Errorf("%s pinned offset is outside the ELF", pinnedGoRuntimeSymbol)
		}
		instruction := encoded[instructionFileOff : instructionFileOff+uint64(len(pinnedSyscallInstruction))]
		instructionTextOff := textOff + pinnedInstructionOffset
		if instructionTextOff < textOff || instructionTextOff+uint64(len(pinnedSyscallInstruction)) > result.textLength {
			return inspectedGuestBinary{}, fmt.Errorf("%s pinned offset is outside executable text", pinnedGoRuntimeSymbol)
		}
		result.syscall6Found = true
		result.syscall6TextOffset = instructionTextOff
		result.instruction = append([]byte(nil), instruction...)
	}
	return result, nil
}

func isNativeBootstrapELF(file *elf.File, encoded []byte) bool {
	if file.Type != elf.ET_EXEC || file.Section(".gopclntab") != nil || file.Section(".go.buildinfo") != nil {
		return false
	}
	for _, prog := range file.Progs {
		if prog.Type == elf.PT_INTERP {
			return false
		}
	}
	if sec := file.Section(".interp"); sec != nil && sec.Size > 0 {
		return false
	}
	if needed, err := file.DynString(elf.DT_NEEDED); err == nil {
		for _, name := range needed {
			if name != "" {
				return false
			}
		}
	}
	for _, marker := range []string{"runtime.main", "Go build ID", "/lib64/ld-linux"} {
		if bytes.Contains(encoded, []byte(marker)) {
			return false
		}
	}
	symbols, err := file.Symbols()
	if err != nil && !strings.Contains(err.Error(), "no symbol section") {
		return false
	}
	hasStart := false
	for _, symbol := range symbols {
		if symbol.Name == "_start" {
			hasStart = true
		}
		if strings.Contains(symbol.Name, "runtime.") || symbol.Name == "main.main" || strings.Contains(symbol.Name, "libc") {
			return false
		}
	}
	return hasStart
}

func executableText(file *elf.File, encoded []byte) ([]byte, error) {
	type segment struct {
		vaddr  uint64
		off    uint64
		filesz uint64
	}
	var segments []segment
	for _, prog := range file.Progs {
		if prog.Type != elf.PT_LOAD || prog.Flags&elf.PF_X == 0 || prog.Filesz == 0 {
			continue
		}
		if prog.Off+prog.Filesz < prog.Off || prog.Off+prog.Filesz > uint64(len(encoded)) {
			return nil, errors.New("executable PT_LOAD is outside the ELF")
		}
		segments = append(segments, segment{vaddr: prog.Vaddr, off: prog.Off, filesz: prog.Filesz})
	}
	if len(segments) == 0 {
		return nil, errors.New("ELF has no executable PT_LOAD")
	}
	sort.Slice(segments, func(i, j int) bool {
		if segments[i].vaddr == segments[j].vaddr {
			return segments[i].off < segments[j].off
		}
		return segments[i].vaddr < segments[j].vaddr
	})
	var text bytes.Buffer
	for _, seg := range segments {
		text.Write(encoded[seg.off : seg.off+seg.filesz])
	}
	return text.Bytes(), nil
}

func mapVirtualAddress(file *elf.File, encoded []byte, value uint64) (fileOff, textOff uint64, err error) {
	type segment struct {
		vaddr  uint64
		off    uint64
		filesz uint64
	}
	var segments []segment
	for _, prog := range file.Progs {
		if prog.Type != elf.PT_LOAD || prog.Flags&elf.PF_X == 0 || prog.Filesz == 0 {
			continue
		}
		segments = append(segments, segment{vaddr: prog.Vaddr, off: prog.Off, filesz: prog.Filesz})
	}
	sort.Slice(segments, func(i, j int) bool {
		if segments[i].vaddr == segments[j].vaddr {
			return segments[i].off < segments[j].off
		}
		return segments[i].vaddr < segments[j].vaddr
	})
	var cursor uint64
	for _, seg := range segments {
		if value >= seg.vaddr && value < seg.vaddr+seg.filesz {
			delta := value - seg.vaddr
			off := seg.off + delta
			if off < seg.off || off > uint64(len(encoded)) {
				return 0, 0, errors.New("virtual address maps outside the ELF")
			}
			return off, cursor + delta, nil
		}
		next := cursor + seg.filesz
		if next < cursor {
			return 0, 0, errors.New("executable text offset overflow")
		}
		cursor = next
	}
	return 0, 0, errors.New("virtual address is outside executable text")
}

func lookupGoFunc(file *elf.File, name string) (value, size uint64, err error) {
	if value, size, err := lookupELFSymbol(file, name); err == nil {
		return value, size, nil
	}
	return lookupPclntabFunc(file, name)
}

func lookupELFSymbol(file *elf.File, name string) (value, size uint64, err error) {
	groups := make([][]elf.Symbol, 0, 2)
	if symbols, symErr := file.Symbols(); symErr == nil {
		groups = append(groups, symbols)
	}
	if symbols, dynErr := file.DynamicSymbols(); dynErr == nil {
		groups = append(groups, symbols)
	}
	var found *elf.Symbol
	for _, symbols := range groups {
		for index := range symbols {
			if symbols[index].Name != name {
				continue
			}
			if found != nil && (found.Value != symbols[index].Value || found.Size != symbols[index].Size) {
				return 0, 0, fmt.Errorf("ELF symbol %s is ambiguous", name)
			}
			symbol := symbols[index]
			found = &symbol
		}
	}
	if found == nil {
		return 0, 0, fmt.Errorf("ELF symbol %s is missing", name)
	}
	return found.Value, found.Size, nil
}

func lookupPclntabFunc(file *elf.File, name string) (value, size uint64, err error) {
	section := file.Section(".gopclntab")
	if section == nil {
		return 0, 0, errors.New("gopclntab is missing")
	}
	data, err := section.Data()
	if err != nil {
		return 0, 0, fmt.Errorf("read gopclntab: %w", err)
	}
	textStart := uint64(0)
	foundText := false
	for _, prog := range file.Progs {
		if prog.Type != elf.PT_LOAD || prog.Flags&elf.PF_X == 0 {
			continue
		}
		if !foundText || prog.Vaddr < textStart {
			textStart = prog.Vaddr
			foundText = true
		}
	}
	if !foundText {
		return 0, 0, errors.New("executable text start is missing")
	}
	table, err := gosym.NewTable(nil, gosym.NewLineTable(data, textStart))
	if err != nil {
		return 0, 0, fmt.Errorf("parse gopclntab: %w", err)
	}
	fn := table.LookupFunc(name)
	if fn == nil {
		return 0, 0, fmt.Errorf("pclntab function %s is missing", name)
	}
	if fn.End < fn.Entry {
		return 0, 0, fmt.Errorf("pclntab function %s has inverted bounds", name)
	}
	return fn.Entry, fn.End - fn.Entry, nil
}
