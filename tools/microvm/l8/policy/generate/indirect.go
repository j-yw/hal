package main

import (
	"debug/elf"
	"encoding/binary"
)

const maxProvenJumpTableEntries = 256

type goTextResolver struct {
	file      *elf.File
	encoded   []byte
	functions []executableFunction
	loadU64   func(uint64) (uint64, bool)
}

type decodedInsnSite struct {
	cursor int
	vaddr  uint64
	insn   amd64Insn
}

func (resolver *goTextResolver) readU64(va uint64) (uint64, bool) {
	if resolver == nil {
		return 0, false
	}
	if resolver.loadU64 != nil {
		return resolver.loadU64(va)
	}
	if resolver.file == nil {
		return 0, false
	}
	off, err := mapLoadAddress(resolver.file, resolver.encoded, va)
	if err != nil || off+8 < off || off+8 > uint64(len(resolver.encoded)) {
		return 0, false
	}
	return binary.LittleEndian.Uint64(resolver.encoded[off : off+8]), true
}

func followListedSpanTarget(functions []executableFunction, dest uint64) (*executableFunction, bool) {
	callee := containingExecutableFunction(functions, dest)
	if callee == nil {
		return nil, true
	}
	return callee, false
}

func resolveIndirectInsn(fn executableFunction, insn amd64Insn, history []decodedInsnSite, resolver *goTextResolver) (targets []uint64, resolved bool) {
	if !insn.indirect {
		return nil, true
	}
	if insn.indirectReg {
		if dest, ok := provenRegisterIndirectTarget(insn.rmReg, history, resolver); ok {
			return []uint64{dest}, true
		}
		return nil, false
	}
	if insn.sib && insn.sibScale == 8 && insn.modrmMod == 0 {
		return resolveSIBJumpTable(fn, insn, history, resolver)
	}
	return nil, false
}

func provenRegisterIndirectTarget(reg uint8, history []decodedInsnSite, resolver *goTextResolver) (uint64, bool) {
	if resolver == nil {
		return 0, false
	}
	for i := len(history) - 1; i >= 0; i-- {
		site := history[i]
		if site.insn.leaRIP && site.insn.leaReg == reg {
			dest := int64(site.vaddr) + int64(site.insn.n) + int64(site.insn.leaDisp)
			if dest < 0 {
				return 0, false
			}
			callee := containingExecutableFunction(resolver.functions, uint64(dest))
			if callee == nil || uint64(dest) != callee.start {
				return 0, false
			}
			return uint64(dest), true
		}
		if insnClobbersReg(site.insn, reg) {
			return 0, false
		}
	}
	return 0, false
}

func resolveSIBJumpTable(fn executableFunction, insn amd64Insn, history []decodedInsnSite, resolver *goTextResolver) ([]uint64, bool) {
	if resolver == nil || insn.sibIndex == 4 {
		return nil, false
	}
	tableVA, haveTable := uint64(0), false
	length, haveLen := 0, false
	sawJA := false
	for i := len(history) - 1; i >= 0; i-- {
		site := history[i]
		if !haveTable && site.insn.leaRIP && site.insn.leaReg == insn.sibBase {
			dest := int64(site.vaddr) + int64(site.insn.n) + int64(site.insn.leaDisp)
			if dest < 0 {
				return nil, false
			}
			tableVA = uint64(dest)
			haveTable = true
			continue
		}
		if site.insn.ja {
			sawJA = true
			continue
		}
		if !haveLen && site.insn.andImm && site.insn.andReg == insn.sibIndex {
			if site.insn.andVal >= maxProvenJumpTableEntries {
				return nil, false
			}
			length = int(site.insn.andVal) + 1
			haveLen = true
			continue
		}
		if !haveLen && sawJA && site.insn.cmpImm && site.insn.cmpReg == insn.sibIndex {
			if site.insn.cmpVal >= maxProvenJumpTableEntries {
				return nil, false
			}
			length = int(site.insn.cmpVal) + 1
			haveLen = true
			continue
		}
		if !haveTable && insnClobbersReg(site.insn, insn.sibBase) {
			return nil, false
		}
		if !haveLen && insnClobbersReg(site.insn, insn.sibIndex) {
			return nil, false
		}
	}
	if !haveTable || !haveLen || length <= 0 || length > maxProvenJumpTableEntries {
		return nil, false
	}
	var extra []uint64
	for index := 0; index < length; index++ {
		entryVA := tableVA + uint64(index)*8
		if entryVA < tableVA {
			return nil, false
		}
		dest, ok := resolver.readU64(entryVA)
		if !ok {
			return nil, false
		}
		if dest == 0 {
			continue
		}
		callee := containingExecutableFunction(resolver.functions, dest)
		if callee == nil {
			return nil, false
		}
		if dest >= fn.start && dest < fn.end {
			continue
		}
		extra = append(extra, dest)
	}
	return extra, true
}

func insnClobbersReg(insn amd64Insn, reg uint8) bool {
	if insn.jmpRel || insn.cmpImm {
		return false
	}
	if insn.nop {
		return false
	}
	if insn.leaRIP {
		return insn.leaReg == reg
	}
	if insn.andImm {
		return insn.andReg == reg
	}
	if insn.movEAXImm {
		return reg == 0
	}
	if insn.callRel || insn.indirect || insn.syscall || insn.sysenter || insn.int80 {
		return true
	}
	if insn.preserveRAX && insn.preserveTrapSlot {
		return false
	}
	return true
}
