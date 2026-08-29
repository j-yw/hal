package main

import (
	"bytes"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	nativeBootstrapSymbol       = "_start"
	goRoleEntrySymbol           = "main.main"
	nativeBootstrapSyscallCount = 7
	syscallKindSyscall          = "syscall"
	syscallKindSysenter         = "sysenter"
	syscallKindInt80            = "int80"
)

type decodedSyscallSite struct {
	symbol       string
	symbolOffset uint64
	textOffset   uint64
	kind         string
	number       uint32
	numberKnown  bool
}

type executableFunction struct {
	name  string
	start uint64
	end   uint64
}

type reachableSyscallGraph struct {
	entry             string
	allSites          []decodedSyscallSite
	reachableSites    []decodedSyscallSite
	extraSites        []decodedSyscallSite
	reachableNames    []string
	unboundedIndirect bool
}

type amd64Insn struct {
	n         int
	syscall   bool
	sysenter  bool
	int80     bool
	callRel   bool
	jmpRel    bool
	indirect  bool
	movEAXImm bool
	rel       int64
	imm       uint32
}

func roleEntrySymbol(binary inspectedGuestBinary) string {
	if binary.native {
		return nativeBootstrapSymbol
	}
	return goRoleEntrySymbol
}

func isPinnedDirectSyscall(binary inspectedGuestBinary, site decodedSyscallSite) bool {
	if site.symbol != pinnedGoRuntimeSymbol || site.symbolOffset != pinnedInstructionOffset || site.kind != syscallKindSyscall {
		return false
	}
	if !binary.syscall6Found || site.textOffset != binary.syscall6TextOffset {
		return false
	}
	end := site.textOffset + uint64(len(pinnedSyscallInstruction))
	if end < site.textOffset || end > binary.textLength {
		return false
	}
	return bytes.Equal(binary.executableText[site.textOffset:end], pinnedSyscallInstruction)
}

func extraReachableSyscallName(binary inspectedGuestBinary, site decodedSyscallSite) string {
	if isPinnedDirectSyscall(binary, site) {
		return ""
	}
	if site.numberKnown {
		return linuxAMD64SyscallName(site.number)
	}
	return "unknown:" + site.symbol
}

func extraReachableSyscallNames(binary inspectedGuestBinary) []string {
	seen := make(map[string]struct{})
	var names []string
	for _, site := range binary.extraSyscalls {
		name := extraReachableSyscallName(binary, site)
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func proveBoundedReachableSyscallGraph(binaries []inspectedGuestBinary) error {
	var reasons []string
	for _, binary := range binaries {
		if binary.graphErr != nil {
			return binary.graphErr
		}
		entry := binary.entry
		if entry == "" {
			entry = roleEntrySymbol(binary)
		}
		if binary.native {
			if err := proveNativeReachableSyscallGraph(binary); err != nil {
				reasons = append(reasons, err.Error())
				continue
			}
		}
		extras := extraReachableSyscallNames(binary)
		if len(extras) == 0 {
			if binary.unboundedIndirect {
				reasons = append(reasons, fmt.Sprintf("role binary %s has a reachable unbounded indirect call from %s; unique/reachable D4/D6 call graph is unavailable", binary.name, entry))
			}
			continue
		}
		reasons = append(reasons, fmt.Sprintf("role binary %s has reachable extra syscalls from %s: %s", binary.name, entry, strings.Join(extras, ", ")))
	}
	if len(reasons) == 0 {
		return nil
	}
	return fmt.Errorf("unique/reachable D4/D6 call graph is unavailable: %s", strings.Join(reasons, "; "))
}

func proveNativeReachableSyscallGraph(binary inspectedGuestBinary) error {
	if binary.entry != nativeBootstrapSymbol {
		return fmt.Errorf("role binary %s native entry is %q, want %s", binary.name, binary.entry, nativeBootstrapSymbol)
	}
	for _, site := range binary.reachableSyscalls {
		if site.symbol != nativeBootstrapSymbol {
			return fmt.Errorf("role binary %s has reachable extra syscall %s in %s from %s", binary.name, extraReachableSyscallName(binary, site), site.symbol, nativeBootstrapSymbol)
		}
	}
	if len(binary.reachableSyscalls) == 0 {
		return fmt.Errorf("role binary %s decoded no syscalls on the reachable path from %s", binary.name, nativeBootstrapSymbol)
	}
	return nil
}

func computeReachableSyscallGraph(file *elf.File, encoded []byte, binary inspectedGuestBinary) (reachableSyscallGraph, error) {
	functions, err := listExecutableFunctions(file, binary.hasGoRuntime)
	if err != nil {
		return reachableSyscallGraph{}, fmt.Errorf("role binary %s: %w", binary.name, err)
	}
	entry := roleEntrySymbol(binary)
	start, err := lookupExecutableFunction(functions, entry)
	if err != nil {
		return reachableSyscallGraph{}, fmt.Errorf("role binary %s: %w", binary.name, err)
	}

	type decodedFunction struct {
		sites     []decodedSyscallSite
		targets   []uint64
		indirect  bool
		decodeErr error
	}
	decoded := make(map[uint64]*decodedFunction, len(functions))
	var decodeOne func(executableFunction) *decodedFunction
	decodeOne = func(fn executableFunction) *decodedFunction {
		if cached, ok := decoded[fn.start]; ok {
			return cached
		}
		result := &decodedFunction{}
		decoded[fn.start] = result
		fileOff, textOff, mapErr := mapVirtualAddress(file, encoded, fn.start)
		if mapErr != nil {
			result.decodeErr = fmt.Errorf("map function %s: %w", fn.name, mapErr)
			return result
		}
		size := fn.end - fn.start
		if fileOff+size < fileOff || fileOff+size > uint64(len(encoded)) {
			result.decodeErr = fmt.Errorf("function %s is outside the ELF", fn.name)
			return result
		}
		sites, targets, indirect, decodeErr := decodeFunctionSyscallGraph(fn, encoded[fileOff:fileOff+size], textOff)
		if decodeErr != nil {
			result.decodeErr = decodeErr
			return result
		}
		result.sites = sites
		result.targets = targets
		result.indirect = indirect
		return result
	}

	visited := make(map[uint64]struct{})
	queue := []executableFunction{start}
	visited[start.start] = struct{}{}
	var reachable []executableFunction
	var reachableSites []decodedSyscallSite
	var extras []decodedSyscallSite
	unbounded := false
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		reachable = append(reachable, fn)
		body := decodeOne(fn)
		if body.decodeErr != nil {
			return reachableSyscallGraph{}, fmt.Errorf("role binary %s: %w", binary.name, body.decodeErr)
		}
		if body.indirect {
			unbounded = true
		}
		for _, site := range body.sites {
			reachableSites = append(reachableSites, site)
			if extraReachableSyscallName(binary, site) != "" {
				extras = append(extras, site)
			}
		}
		for _, target := range body.targets {
			callee := containingExecutableFunction(functions, target)
			if callee == nil {
				unbounded = true
				continue
			}
			if _, seen := visited[callee.start]; seen {
				continue
			}
			visited[callee.start] = struct{}{}
			queue = append(queue, *callee)
		}
	}

	var allSites []decodedSyscallSite
	for _, fn := range functions {
		body := decodeOne(fn)
		if body.decodeErr != nil {
			continue
		}
		allSites = append(allSites, body.sites...)
	}
	sortSyscallSites(allSites)
	sortSyscallSites(reachableSites)
	sortSyscallSites(extras)
	names := make([]string, 0, len(reachable))
	for _, fn := range reachable {
		names = append(names, fn.name)
	}
	sort.Strings(names)
	return reachableSyscallGraph{
		entry:             entry,
		allSites:          allSites,
		reachableSites:    reachableSites,
		extraSites:        extras,
		reachableNames:    names,
		unboundedIndirect: unbounded,
	}, nil
}

func decodeFunctionSyscallGraph(fn executableFunction, code []byte, textOff uint64) ([]decodedSyscallSite, []uint64, bool, error) {
	var sites []decodedSyscallSite
	var targets []uint64
	indirect := false
	var raxImm *uint32
	for cursor := 0; cursor < len(code); {
		insn, ok := amd64DecodeInsn(code[cursor:])
		if !ok || insn.n <= 0 {
			if isHarmlessFunctionTail(code[cursor:]) {
				break
			}
			return nil, nil, false, fmt.Errorf("decode %s at offset %d: x86-64 decode failed", fn.name, cursor)
		}
		vaddr := fn.start + uint64(cursor)
		next := cursor + insn.n
		if next <= cursor || next > len(code) {
			return nil, nil, false, fmt.Errorf("decode %s at offset %d: x86-64 decode overflowed the function", fn.name, cursor)
		}
		if insn.syscall || insn.sysenter || insn.int80 {
			site := decodedSyscallSite{
				symbol:       fn.name,
				symbolOffset: uint64(cursor),
				textOffset:   textOff + uint64(cursor),
				kind:         syscallKindSyscall,
			}
			if insn.sysenter {
				site.kind = syscallKindSysenter
			}
			if insn.int80 {
				site.kind = syscallKindInt80
			}
			if raxImm != nil {
				site.numberKnown = true
				site.number = *raxImm
			}
			sites = append(sites, site)
		}
		if insn.movEAXImm {
			imm := insn.imm
			raxImm = &imm
		} else if insn.callRel || insn.indirect {
			raxImm = nil
		}
		if insn.indirect {
			indirect = true
		}
		if insn.callRel || insn.jmpRel {
			target := int64(vaddr) + int64(insn.n) + insn.rel
			if target < 0 {
				return nil, nil, false, fmt.Errorf("decode %s at offset %d: relative transfer underflowed", fn.name, cursor)
			}
			dest := uint64(target)
			if insn.callRel || dest < fn.start || dest >= fn.end {
				targets = append(targets, dest)
			}
		}
		cursor = next
	}
	return sites, targets, indirect, nil
}

func sortSyscallSites(sites []decodedSyscallSite) {
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].textOffset == sites[j].textOffset {
			if sites[i].symbol == sites[j].symbol {
				return sites[i].symbolOffset < sites[j].symbolOffset
			}
			return sites[i].symbol < sites[j].symbol
		}
		return sites[i].textOffset < sites[j].textOffset
	})
}

func lookupExecutableFunction(functions []executableFunction, name string) (executableFunction, error) {
	var found executableFunction
	have := false
	for index := range functions {
		if functions[index].name != name {
			continue
		}
		candidate := functions[index]
		if !have || preferExecutableFunction(candidate, found) {
			found = candidate
			have = true
		}
	}
	if !have {
		return executableFunction{}, fmt.Errorf("function %s is missing", name)
	}
	return found, nil
}

func listExecutableFunctions(file *elf.File, goRuntime bool) ([]executableFunction, error) {
	var functions []executableFunction
	if goRuntime {
		pclntab, err := listPclntabFunctions(file)
		if err != nil {
			return nil, err
		}
		functions = pclntab
	}
	elfFuncs, err := listELFFunctions(file)
	if err != nil {
		return nil, err
	}
	return mergeExecutableFunctions(functions, elfFuncs)
}

func listPclntabFunctions(file *elf.File) ([]executableFunction, error) {
	section := file.Section(".gopclntab")
	if section == nil {
		return nil, errors.New("gopclntab is missing")
	}
	data, err := section.Data()
	if err != nil {
		return nil, fmt.Errorf("read gopclntab: %w", err)
	}
	textStart, err := pclntabTextStart(file)
	if err != nil {
		return nil, err
	}
	table, err := gosym.NewTable(nil, gosym.NewLineTable(data, textStart))
	if err != nil {
		return nil, fmt.Errorf("parse gopclntab: %w", err)
	}
	functions := make([]executableFunction, 0, len(table.Funcs))
	for index := range table.Funcs {
		fn := table.Funcs[index]
		if fn.Name == "" || skipExecutableFunctionName(fn.Name) || fn.End <= fn.Entry {
			continue
		}
		functions = append(functions, executableFunction{name: fn.Name, start: fn.Entry, end: fn.End})
	}
	if len(functions) == 0 {
		return nil, errors.New("gopclntab has no functions")
	}
	return functions, nil
}

func listELFFunctions(file *elf.File) ([]executableFunction, error) {
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
			if existing.name != candidate.name && existing.end == candidate.end && existing.end != 0 {
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

func mergeExecutableFunctions(primary, extra []executableFunction) ([]executableFunction, error) {
	byStart := make(map[uint64]executableFunction, len(primary)+len(extra))
	for _, function := range primary {
		byStart[function.start] = function
	}
	for _, function := range extra {
		existing, ok := byStart[function.start]
		if !ok {
			byStart[function.start] = function
			continue
		}
		if preferExecutableFunction(function, existing) {
			byStart[function.start] = function
		}
	}
	functions := make([]executableFunction, 0, len(byStart))
	for _, function := range byStart {
		if function.end <= function.start {
			return nil, fmt.Errorf("function %s has inverted bounds", function.name)
		}
		functions = append(functions, function)
	}
	sort.Slice(functions, func(i, j int) bool { return functions[i].start < functions[j].start })
	return functions, nil
}

func skipExecutableFunctionName(name string) bool {
	switch name {
	case "runtime.text", "runtime.etext":
		return true
	default:
		return strings.HasPrefix(name, "go:buildid")
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

func isHarmlessFunctionTail(code []byte) bool {
	if len(code) == 0 {
		return true
	}
	pad := true
	for _, value := range code {
		if value != 0x90 && value != 0xCC {
			pad = false
			break
		}
	}
	if pad {
		return true
	}
	opcode := code[0]
	return opcode == 0xE8 || opcode == 0xE9 || opcode == 0xEB || opcode >= 0x70 && opcode <= 0x7F
}

func pclntabTextStart(file *elf.File) (uint64, error) {
	if value, _, err := lookupELFSymbol(file, "runtime.text"); err == nil && value != 0 {
		return value, nil
	}
	return executableTextStart(file)
}

func executableTextStart(file *elf.File) (uint64, error) {
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
		return 0, errors.New("executable text start is missing")
	}
	return textStart, nil
}

func amd64DecodeInsn(code []byte) (amd64Insn, bool) {
	length, ok := amd64InstructionLength(code)
	if !ok || length <= 0 || length > len(code) {
		return amd64Insn{}, false
	}
	index := 0
	operand16 := false
	rexW := false
	rexB := false
	for index < length {
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
			return amd64Insn{}, false
		}
		if value >= 0x40 && value <= 0x4F {
			rexW = value&0x08 != 0
			rexB = value&0x01 != 0
			index++
			continue
		}
		break
	}
	if index >= length {
		return amd64Insn{}, false
	}
	opcode := code[index]
	index++
	insn := amd64Insn{n: length}
	if opcode == 0x0F {
		if index >= length {
			return amd64Insn{}, false
		}
		switch code[index] {
		case 0x05:
			insn.syscall = true
		case 0x34:
			insn.sysenter = true
		}
		return insn, true
	}
	if opcode == 0xCD && index < length && code[index] == 0x80 {
		insn.int80 = true
		return insn, true
	}
	if opcode == 0xE8 && !operand16 && length >= 5 {
		insn.callRel = true
		insn.rel = int64(int32(binary.LittleEndian.Uint32(code[length-4 : length])))
		return insn, true
	}
	if opcode == 0xE9 && !operand16 && length >= 5 {
		insn.jmpRel = true
		insn.rel = int64(int32(binary.LittleEndian.Uint32(code[length-4 : length])))
		return insn, true
	}
	if opcode == 0xEB && length >= 2 {
		insn.jmpRel = true
		insn.rel = int64(int8(code[length-1]))
		return insn, true
	}
	if opcode == 0xFF && index < length {
		reg := (code[index] >> 3) & 7
		if reg == 2 || reg == 4 {
			insn.indirect = true
		}
		return insn, true
	}
	if opcode&0xF8 == 0xB8 {
		rd := opcode & 7
		if rd == 0 && !rexB {
			if rexW {
				if length < 9 {
					return insn, true
				}
				imm := binary.LittleEndian.Uint64(code[length-8 : length])
				if imm == uint64(uint32(imm)) {
					insn.movEAXImm = true
					insn.imm = uint32(imm)
				}
			} else if length >= 5 {
				insn.movEAXImm = true
				insn.imm = binary.LittleEndian.Uint32(code[length-4 : length])
			}
		}
		return insn, true
	}
	if opcode == 0xC7 && index < length {
		modrm := code[index]
		if (modrm>>3)&7 == 0 && modrm>>6 == 3 && modrm&7 == 0 && !rexB && length >= index+5 {
			insn.movEAXImm = true
			insn.imm = binary.LittleEndian.Uint32(code[length-4 : length])
		}
	}
	return insn, true
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
	case 0xCD:
		return false, 1
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

func linuxAMD64SyscallName(number uint32) string {
	if name := linuxAMD64SyscallNames[number]; name != "" {
		return name
	}
	return fmt.Sprintf("nr:%d", number)
}

var linuxAMD64SyscallNames = map[uint32]string{
	0:   "read",
	1:   "write",
	2:   "open",
	3:   "close",
	4:   "stat",
	5:   "fstat",
	6:   "lstat",
	7:   "poll",
	8:   "lseek",
	9:   "mmap",
	10:  "mprotect",
	11:  "munmap",
	12:  "brk",
	13:  "rt_sigaction",
	14:  "rt_sigprocmask",
	15:  "rt_sigreturn",
	16:  "ioctl",
	17:  "pread64",
	18:  "pwrite64",
	19:  "readv",
	20:  "writev",
	21:  "access",
	22:  "pipe",
	23:  "select",
	24:  "sched_yield",
	25:  "mremap",
	26:  "msync",
	27:  "mincore",
	28:  "madvise",
	29:  "shmget",
	30:  "shmat",
	31:  "shmctl",
	32:  "dup",
	33:  "dup2",
	34:  "pause",
	35:  "nanosleep",
	36:  "getitimer",
	37:  "alarm",
	38:  "setitimer",
	39:  "getpid",
	40:  "sendfile",
	41:  "socket",
	42:  "connect",
	43:  "accept",
	44:  "sendto",
	45:  "recvfrom",
	46:  "sendmsg",
	47:  "recvmsg",
	48:  "shutdown",
	49:  "bind",
	50:  "listen",
	51:  "getsockname",
	52:  "getpeername",
	53:  "socketpair",
	54:  "setsockopt",
	55:  "getsockopt",
	56:  "clone",
	57:  "fork",
	58:  "vfork",
	59:  "execve",
	60:  "exit",
	61:  "wait4",
	62:  "kill",
	63:  "uname",
	64:  "semget",
	65:  "semop",
	66:  "semctl",
	67:  "shmdt",
	68:  "msgget",
	69:  "msgsnd",
	70:  "msgrcv",
	71:  "msgctl",
	72:  "fcntl",
	73:  "flock",
	74:  "fsync",
	75:  "fdatasync",
	76:  "truncate",
	77:  "ftruncate",
	78:  "getdents",
	79:  "getcwd",
	80:  "chdir",
	81:  "fchdir",
	82:  "rename",
	83:  "mkdir",
	84:  "rmdir",
	85:  "creat",
	86:  "link",
	87:  "unlink",
	88:  "symlink",
	89:  "readlink",
	90:  "chmod",
	91:  "fchmod",
	92:  "chown",
	93:  "fchown",
	94:  "lchown",
	95:  "umask",
	96:  "gettimeofday",
	97:  "getrlimit",
	98:  "getrusage",
	99:  "sysinfo",
	100: "times",
	101: "ptrace",
	102: "getuid",
	103: "syslog",
	104: "getgid",
	105: "setuid",
	106: "setgid",
	107: "geteuid",
	108: "getegid",
	109: "setpgid",
	110: "getppid",
	111: "getpgrp",
	112: "setsid",
	113: "setreuid",
	114: "setregid",
	115: "getgroups",
	116: "setgroups",
	117: "setresuid",
	118: "getresuid",
	119: "setresgid",
	120: "getresgid",
	121: "getpgid",
	122: "setfsuid",
	123: "setfsgid",
	124: "getsid",
	125: "capget",
	126: "capset",
	127: "rt_sigpending",
	128: "rt_sigtimedwait",
	129: "rt_sigqueueinfo",
	130: "rt_sigsuspend",
	131: "sigaltstack",
	132: "utime",
	133: "mknod",
	134: "uselib",
	135: "personality",
	136: "ustat",
	137: "statfs",
	138: "fstatfs",
	139: "sysfs",
	140: "getpriority",
	141: "setpriority",
	142: "sched_setparam",
	143: "sched_getparam",
	144: "sched_setscheduler",
	145: "sched_getscheduler",
	146: "sched_get_priority_max",
	147: "sched_get_priority_min",
	148: "sched_rr_get_interval",
	149: "mlock",
	150: "munlock",
	151: "mlockall",
	152: "munlockall",
	153: "vhangup",
	154: "modify_ldt",
	155: "pivot_root",
	156: "_sysctl",
	157: "prctl",
	158: "arch_prctl",
	159: "adjtimex",
	160: "setrlimit",
	161: "chroot",
	162: "sync",
	163: "acct",
	164: "settimeofday",
	165: "mount",
	166: "umount2",
	167: "swapon",
	168: "swapoff",
	169: "reboot",
	170: "sethostname",
	171: "setdomainname",
	172: "iopl",
	173: "ioperm",
	174: "create_module",
	175: "init_module",
	176: "delete_module",
	177: "get_kernel_syms",
	178: "query_module",
	179: "quotactl",
	180: "nfsservctl",
	181: "getpmsg",
	182: "putpmsg",
	183: "afs_syscall",
	184: "tuxcall",
	185: "security",
	186: "gettid",
	187: "readahead",
	188: "setxattr",
	189: "lsetxattr",
	190: "fsetxattr",
	191: "getxattr",
	192: "lgetxattr",
	193: "fgetxattr",
	194: "listxattr",
	195: "llistxattr",
	196: "flistxattr",
	197: "removexattr",
	198: "lremovexattr",
	199: "fremovexattr",
	200: "tkill",
	201: "time",
	202: "futex",
	203: "sched_setaffinity",
	204: "sched_getaffinity",
	205: "set_thread_area",
	206: "io_setup",
	207: "io_destroy",
	208: "io_getevents",
	209: "io_submit",
	210: "io_cancel",
	211: "get_thread_area",
	212: "lookup_dcookie",
	213: "epoll_create",
	214: "epoll_ctl_old",
	215: "epoll_wait_old",
	216: "remap_file_pages",
	217: "getdents64",
	218: "set_tid_address",
	219: "restart_syscall",
	220: "semtimedop",
	221: "fadvise64",
	222: "timer_create",
	223: "timer_settime",
	224: "timer_gettime",
	225: "timer_getoverrun",
	226: "timer_delete",
	227: "clock_settime",
	228: "clock_gettime",
	229: "clock_getres",
	230: "clock_nanosleep",
	231: "exit_group",
	232: "epoll_wait",
	233: "epoll_ctl",
	234: "tgkill",
	235: "utimes",
	236: "vserver",
	237: "mbind",
	238: "set_mempolicy",
	239: "get_mempolicy",
	240: "mq_open",
	241: "mq_unlink",
	242: "mq_timedsend",
	243: "mq_timedreceive",
	244: "mq_notify",
	245: "mq_getsetattr",
	246: "kexec_load",
	247: "waitid",
	248: "add_key",
	249: "request_key",
	250: "keyctl",
	251: "ioprio_set",
	252: "ioprio_get",
	253: "inotify_init",
	254: "inotify_add_watch",
	255: "inotify_rm_watch",
	256: "migrate_pages",
	257: "openat",
	258: "mkdirat",
	259: "mknodat",
	260: "fchownat",
	261: "futimesat",
	262: "newfstatat",
	263: "unlinkat",
	264: "renameat",
	265: "linkat",
	266: "symlinkat",
	267: "readlinkat",
	268: "fchmodat",
	269: "faccessat",
	270: "pselect6",
	271: "ppoll",
	272: "unshare",
	273: "set_robust_list",
	274: "get_robust_list",
	275: "splice",
	276: "tee",
	277: "sync_file_range",
	278: "vmsplice",
	279: "move_pages",
	280: "utimensat",
	281: "epoll_pwait",
	282: "signalfd",
	283: "timerfd_create",
	284: "eventfd",
	285: "fallocate",
	286: "timerfd_settime",
	287: "timerfd_gettime",
	288: "accept4",
	289: "signalfd4",
	290: "eventfd2",
	291: "epoll_create1",
	292: "dup3",
	293: "pipe2",
	294: "inotify_init1",
	295: "preadv",
	296: "pwritev",
	297: "rt_tgsigqueueinfo",
	298: "perf_event_open",
	299: "recvmmsg",
	300: "fanotify_init",
	301: "fanotify_mark",
	302: "prlimit64",
	303: "name_to_handle_at",
	304: "open_by_handle_at",
	305: "clock_adjtime",
	306: "syncfs",
	307: "sendmmsg",
	308: "setns",
	309: "getcpu",
	310: "process_vm_readv",
	311: "process_vm_writev",
	312: "kcmp",
	313: "finit_module",
	314: "sched_setattr",
	315: "sched_getattr",
	316: "renameat2",
	317: "seccomp",
	318: "getrandom",
	319: "memfd_create",
	320: "kexec_file_load",
	321: "bpf",
	322: "execveat",
	323: "userfaultfd",
	324: "membarrier",
	325: "mlock2",
	326: "copy_file_range",
	327: "preadv2",
	328: "pwritev2",
	329: "pkey_mprotect",
	330: "pkey_alloc",
	331: "pkey_free",
	332: "statx",
	333: "io_pgetevents",
	334: "rseq",
	335: "uretprobe",
	424: "pidfd_send_signal",
	425: "io_uring_setup",
	426: "io_uring_enter",
	427: "io_uring_register",
	428: "open_tree",
	429: "move_mount",
	430: "fsopen",
	431: "fsconfig",
	432: "fsmount",
	433: "fspick",
	434: "pidfd_open",
	435: "clone3",
	436: "close_range",
	437: "openat2",
	438: "pidfd_getfd",
	439: "faccessat2",
	440: "process_madvise",
	441: "epoll_pwait2",
	442: "mount_setattr",
	443: "quotactl_fd",
	444: "landlock_create_ruleset",
	445: "landlock_add_rule",
	446: "landlock_restrict_self",
	447: "memfd_secret",
	448: "process_mrelease",
	449: "futex_waitv",
	450: "set_mempolicy_home_node",
}
