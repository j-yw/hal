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
	maxGuestBinaryBytes         = 64 << 20
	pinnedGoRuntimeSymbol       = "internal/runtime/syscall.Syscall6"
	pinnedInstructionOffset     = 12
	guestModulePrefix           = "github.com/jywlabs/hal/"
	requiredGoToolchainVersion  = "go1.25.7"
	guestInitBinaryName         = "hal-init"
	guestAgentBinaryName        = "hal-guest-agent"
	guestHelperBinaryName       = "hal-guest-credential-helper"
	guestMonitorBinaryName      = "hal-guest-mount-monitor"
	guestShimBinaryName         = "hal-guest-workload-shim"
	guestBootstrapBinaryName    = "hal-guest-role-bootstrap"
	guestInitPackagePath        = guestModulePrefix + "cmd/hal-guest-init"
	guestAgentPackagePath       = guestModulePrefix + "cmd/hal-guest-agent"
	guestHelperPackagePath      = guestModulePrefix + "cmd/hal-guest-credential-helper"
	guestMonitorPackagePath     = guestModulePrefix + "cmd/hal-guest-mount-monitor"
	guestShimPackagePath        = guestModulePrefix + "cmd/hal-guest-workload-shim"
	nativeBootstrapSymbol       = "_start"
	nativeBootstrapSyscallCount = 7
	launchBaseRoleID            = 2
	pinnedGoRuntimeBindingKind  = 2
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
	syscalls             []decodedSyscallSite
}

type decodedSyscallSite struct {
	symbol       string
	symbolOffset uint64
	textOffset   uint64
}

type executableFunction struct {
	name  string
	start uint64
	end   uint64
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
		evidence, err := encodePinnedCallsiteEvidence(outputs, binaries)
		if err != nil {
			return generatedEvidence{}, fmt.Errorf("%w: %v", errEvidenceInputsUnavailable, err)
		}
		return evidence, nil
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
	for _, binary := range binaries {
		if err := proveUniqueReachableSyscallGraph(binary); err != nil {
			return err
		}
	}
	return nil
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
	return proveUniqueReachableSyscallGraph(binary)
}

func proveUniqueReachableSyscallGraph(binary inspectedGuestBinary) error {
	if binary.native {
		return proveNativeSyscallGraph(binary)
	}
	pinned := 0
	for _, site := range binary.syscalls {
		if site.symbol == pinnedGoRuntimeSymbol {
			if site.symbolOffset != pinnedInstructionOffset {
				return fmt.Errorf("role binary %s pinned %s offset %d is not %d; unique/reachable D4/D6 call graph is unavailable", binary.name, pinnedGoRuntimeSymbol, site.symbolOffset, pinnedInstructionOffset)
			}
			if site.textOffset != binary.syscall6TextOffset {
				return fmt.Errorf("role binary %s pinned %s text offset does not match the inspector; unique/reachable D4/D6 call graph is unavailable", binary.name, pinnedGoRuntimeSymbol)
			}
			pinned++
			continue
		}
		if !classifiedNonAuthoritySyscallSymbol(site.symbol) {
			return fmt.Errorf("role binary %s has unclassified syscall site %s; unique/reachable D4/D6 call graph is unavailable", binary.name, site.symbol)
		}
	}
	if pinned != 1 {
		return fmt.Errorf("role binary %s has %d %s sites, want 1; unique/reachable D4/D6 call graph is unavailable", binary.name, pinned, pinnedGoRuntimeSymbol)
	}
	return nil
}

func proveNativeSyscallGraph(binary inspectedGuestBinary) error {
	if len(binary.syscalls) != nativeBootstrapSyscallCount {
		return fmt.Errorf("role binary %s has %d native syscall instructions, want %d; unique/reachable D4/D6 call graph is unavailable", binary.name, len(binary.syscalls), nativeBootstrapSyscallCount)
	}
	for _, site := range binary.syscalls {
		if site.symbol != nativeBootstrapSymbol {
			return fmt.Errorf("role binary %s has unclassified native syscall site %s; unique/reachable D4/D6 call graph is unavailable", binary.name, site.symbol)
		}
	}
	return nil
}

func classifiedNonAuthoritySyscallSymbol(symbol string) bool {
	switch {
	case symbol == pinnedGoRuntimeSymbol:
		return false
	case strings.HasPrefix(symbol, "runtime."):
		return true
	case symbol == "time.now" || strings.HasPrefix(symbol, "time.now."):
		return true
	case strings.HasPrefix(symbol, "syscall."):
		return true
	case strings.HasPrefix(symbol, "golang.org/x/sys/unix."):
		return true
	case strings.HasPrefix(symbol, "internal/runtime/syscall."):
		return true
	default:
		return false
	}
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

func decodeExecutableSyscallSites(file *elf.File, encoded []byte) ([]decodedSyscallSite, error) {
	functions, err := listExecutableFunctions(file)
	if err != nil {
		return nil, err
	}
	var sites []decodedSyscallSite
	for _, prog := range file.Progs {
		if prog.Type != elf.PT_LOAD || prog.Flags&elf.PF_X == 0 || prog.Filesz == 0 {
			continue
		}
		if prog.Off+prog.Filesz < prog.Off || prog.Off+prog.Filesz > uint64(len(encoded)) {
			return nil, errors.New("executable PT_LOAD is outside the ELF")
		}
		chunk := encoded[prog.Off : prog.Off+prog.Filesz]
		for index := 0; index+len(pinnedSyscallInstruction) <= len(chunk); index++ {
			if !bytes.Equal(chunk[index:index+len(pinnedSyscallInstruction)], pinnedSyscallInstruction) {
				continue
			}
			vaddr := prog.Vaddr + uint64(index)
			fn := containingExecutableFunction(functions, vaddr)
			if fn == nil {
				return nil, fmt.Errorf("syscall bytes at %#x are outside every FUNC symbol; unique/reachable D4/D6 call graph is unavailable", vaddr)
			}
			fileOff, _, err := mapVirtualAddress(file, encoded, fn.start)
			if err != nil {
				return nil, fmt.Errorf("map function %s: %w", fn.name, err)
			}
			size := fn.end - fn.start
			if fileOff+size < fileOff || fileOff+size > uint64(len(encoded)) {
				return nil, fmt.Errorf("function %s is outside the ELF", fn.name)
			}
			rel := vaddr - fn.start
			starts, err := amd64InstructionStartsAt(encoded[fileOff:fileOff+size], rel)
			if err != nil {
				return nil, fmt.Errorf("decode %s: %w", fn.name, err)
			}
			if !starts {
				continue
			}
			_, textOff, err := mapVirtualAddress(file, encoded, vaddr)
			if err != nil {
				return nil, fmt.Errorf("map syscall in %s: %w", fn.name, err)
			}
			sites = append(sites, decodedSyscallSite{symbol: fn.name, symbolOffset: rel, textOffset: textOff})
		}
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].textOffset == sites[j].textOffset {
			return sites[i].symbol < sites[j].symbol
		}
		return sites[i].textOffset < sites[j].textOffset
	})
	return sites, nil
}

func listExecutableFunctions(file *elf.File) ([]executableFunction, error) {
	groups := make([][]elf.Symbol, 0, 2)
	if symbols, err := file.Symbols(); err == nil {
		groups = append(groups, symbols)
	} else if !strings.Contains(err.Error(), "no symbol section") {
		return nil, err
	}
	if symbols, err := file.DynamicSymbols(); err == nil {
		groups = append(groups, symbols)
	}
	textEnd := uint64(0)
	for _, prog := range file.Progs {
		if prog.Type != elf.PT_LOAD || prog.Flags&elf.PF_X == 0 {
			continue
		}
		end := prog.Vaddr + prog.Filesz
		if end > textEnd {
			textEnd = end
		}
	}
	byStart := make(map[uint64]executableFunction)
	for _, symbols := range groups {
		for _, symbol := range symbols {
			if elf.ST_TYPE(symbol.Info) != elf.STT_FUNC || symbol.Name == "" || skipExecutableFunctionName(symbol.Name) {
				continue
			}
			end := symbol.Value + symbol.Size
			if symbol.Size == 0 {
				end = 0
			} else if end < symbol.Value {
				return nil, fmt.Errorf("function %s has inverted bounds", symbol.Name)
			}
			candidate := executableFunction{name: symbol.Name, start: symbol.Value, end: end}
			existing, ok := byStart[symbol.Value]
			if !ok || preferExecutableFunction(candidate, existing) {
				byStart[symbol.Value] = candidate
				continue
			}
			if existing.name != candidate.name && existing.end == candidate.end {
				return nil, fmt.Errorf("function start %#x is ambiguous", symbol.Value)
			}
		}
	}
	functions := make([]executableFunction, 0, len(byStart))
	for _, function := range byStart {
		functions = append(functions, function)
	}
	sort.Slice(functions, func(i, j int) bool { return functions[i].start < functions[j].start })
	for index := range functions {
		if functions[index].end != 0 {
			continue
		}
		end := textEnd
		if index+1 < len(functions) && functions[index+1].start < end {
			end = functions[index+1].start
		}
		if end <= functions[index].start {
			return nil, fmt.Errorf("function %s has no executable span", functions[index].name)
		}
		functions[index].end = end
	}
	return functions, nil
}

func skipExecutableFunctionName(name string) bool {
	switch name {
	case "runtime.text", "runtime.etext":
		return true
	default:
		return false
	}
}

func preferExecutableFunction(candidate, existing executableFunction) bool {
	if existing.name == candidate.name {
		if existing.end == 0 && candidate.end != 0 {
			return true
		}
		return false
	}
	if existing.end == 0 && candidate.end != 0 {
		return true
	}
	if existing.end != 0 && candidate.end != 0 && candidate.end-candidate.start < existing.end-existing.start {
		return true
	}
	return false
}

func containingExecutableFunction(functions []executableFunction, vaddr uint64) *executableFunction {
	var best *executableFunction
	for index := range functions {
		if vaddr < functions[index].start || vaddr >= functions[index].end {
			continue
		}
		if best == nil || functions[index].end-functions[index].start < best.end-best.start {
			best = &functions[index]
		}
	}
	return best
}

func amd64InstructionStartsAt(function []byte, offset uint64) (bool, error) {
	if offset >= uint64(len(function)) {
		return false, errors.New("instruction offset is outside the function")
	}
	cursor := 0
	for uint64(cursor) < offset {
		length, ok := amd64InstructionLength(function[cursor:])
		if !ok || length <= 0 {
			return false, errors.New("x86-64 decode failed before the candidate instruction")
		}
		next := cursor + length
		if next <= cursor || next > len(function) {
			return false, errors.New("x86-64 decode overflowed the function")
		}
		cursor = next
	}
	return uint64(cursor) == offset, nil
}

func amd64InstructionLength(code []byte) (int, bool) {
	if len(code) == 0 {
		return 0, false
	}
	index := 0
	operand16 := false
	rexW := false
	for prefix := 0; prefix < 15 && index < len(code); prefix++ {
		value := code[index]
		switch value {
		case 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65:
			index++
			continue
		case 0x66:
			operand16 = true
			index++
			continue
		case 0x67:
			return 0, false
		}
		if value >= 0x40 && value <= 0x4F {
			rexW = value&0x08 != 0
			index++
			continue
		}
		break
	}
	if index >= len(code) {
		return 0, false
	}
	opcode := code[index]
	index++
	twoByte := false
	threeByte := byte(0)
	if opcode == 0x0F {
		if index >= len(code) {
			return 0, false
		}
		opcode = code[index]
		index++
		twoByte = true
		if opcode == 0x38 || opcode == 0x3A {
			if index >= len(code) {
				return 0, false
			}
			threeByte = opcode
			opcode = code[index]
			index++
		}
	}
	hasModRM := false
	imm := 0
	switch {
	case !twoByte:
		hasModRM, imm = amd64OneByteMeta(opcode, operand16, rexW)
	case threeByte == 0x3A:
		hasModRM = true
		imm = 1
	case threeByte == 0x38:
		hasModRM = true
	case opcode >= 0x80 && opcode <= 0x8F:
		if operand16 {
			imm = 2
		} else {
			imm = 4
		}
	case opcode == 0x05 || opcode == 0x06 || opcode == 0x07 || opcode == 0x08 || opcode == 0x09 || opcode == 0x0B || opcode == 0x30 || opcode == 0x31 || opcode == 0x32 || opcode == 0x33 || opcode == 0x34 || opcode == 0x35 || opcode == 0x37 || opcode == 0xA0 || opcode == 0xA1 || opcode == 0xA2 || opcode == 0xA8 || opcode == 0xA9 || opcode == 0xAA:
	default:
		hasModRM = true
	}
	var modrm byte
	if hasModRM {
		next, decodedModRM, ok := amd64ConsumeModRM(code, index)
		if !ok {
			return 0, false
		}
		index = next
		modrm = decodedModRM
		if !twoByte && (opcode == 0xF6 || opcode == 0xF7) && (modrm>>3)&7 == 0 {
			if opcode == 0xF6 {
				imm = 1
			} else if operand16 {
				imm = 2
			} else {
				imm = 4
			}
		}
	}
	if index+imm > len(code) {
		return 0, false
	}
	return index + imm, true
}

func amd64OneByteMeta(opcode byte, operand16, rexW bool) (hasModRM bool, imm int) {
	immSize := 4
	if operand16 {
		immSize = 2
	}
	switch opcode {
	case 0x04, 0x0C, 0x14, 0x1C, 0x24, 0x2C, 0x34, 0x3C, 0xA8, 0x6A:
		return false, 1
	case 0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D, 0xA9:
		if rexW {
			return false, 4
		}
		return false, immSize
	case 0x68:
		return false, immSize
	case 0x80, 0x83, 0xC0, 0xC1, 0xC6, 0x6B:
		return true, 1
	case 0x81, 0xC7, 0x69:
		return true, immSize
	case 0xC2, 0xCA:
		return false, 2
	case 0xC8:
		return false, 3
	case 0xE8, 0xE9:
		return false, immSize
	case 0xEB, 0xE0, 0xE1, 0xE2, 0xE3:
		return false, 1
	case 0xF6:
		return true, 0
	case 0xF7:
		return true, 0
	case 0xFE, 0xFF, 0x8F:
		return true, 0
	}
	switch {
	case opcode <= 0x3F && opcode&0x04 == 0:
		return true, 0
	case opcode >= 0x70 && opcode <= 0x7F:
		return false, 1
	case opcode >= 0x84 && opcode <= 0x8B || opcode == 0x8C || opcode == 0x8D || opcode == 0x8E || opcode == 0x63:
		return true, 0
	case opcode >= 0xB0 && opcode <= 0xB7:
		return false, 1
	case opcode >= 0xB8 && opcode <= 0xBF:
		if rexW {
			return false, 8
		}
		return false, immSize
	case opcode >= 0xD0 && opcode <= 0xD3 || opcode >= 0xD8 && opcode <= 0xDF:
		return true, 0
	}
	return false, 0
}

func amd64ConsumeModRM(code []byte, index int) (int, byte, bool) {
	if index >= len(code) {
		return 0, 0, false
	}
	modrm := code[index]
	index++
	mod := modrm >> 6
	rm := modrm & 7
	if mod != 3 && rm == 4 {
		if index >= len(code) {
			return 0, 0, false
		}
		sib := code[index]
		index++
		if mod == 0 && sib&7 == 5 {
			index += 4
		}
	}
	switch mod {
	case 0:
		if rm == 5 {
			index += 4
		}
	case 1:
		index++
	case 2:
		index += 4
	}
	if index > len(code) {
		return 0, 0, false
	}
	return index, modrm, true
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
	sites, err := decodeExecutableSyscallSites(file, encoded)
	if err != nil {
		return inspectedGuestBinary{}, err
	}
	result.syscalls = sites
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
