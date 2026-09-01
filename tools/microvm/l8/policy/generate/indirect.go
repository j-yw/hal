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
	// interiorEntries records relative transfers from any listed function into
	// the interior of another listed span. A table fact cannot be used when one
	// of those entry points can skip it and still reach the indirect jump.
	interiorEntries map[uint64][]uint64
	// pointerTaken is the closed set of listed function starts whose addresses
	// appear as 8-byte pointers in non-executable, non-pclntab ELF contents.
	pointerTaken []uint64
	itabs        map[uint64]struct{}
	loadU64      func(uint64) (uint64, bool)
}

const itabFunOffset = 24

type registerFactKind uint8

const (
	registerFactNone registerFactKind = iota
	registerFactCode
	registerFactItab
)

type registerFact struct {
	kind registerFactKind
	va   uint64
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
	off, err := mapReadOnlyLoadAddress(resolver.file, resolver.encoded, va, 8)
	if err != nil {
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

func resolveIndirectInsn(fn executableFunction, insn amd64Insn, history []decodedInsnSite, resolver *goTextResolver, branchTargets []int, transferCursor int) (targets []uint64, resolved bool) {
	if !insn.indirect {
		return nil, true
	}
	if insn.nonCanonicalMem {
		return nil, false
	}
	if insn.indirectReg {
		return resolveRegisterIndirectTargets(fn, insn, history, resolver, branchTargets, transferCursor)
	}
	if insn.indirectJump && insn.sib && !insn.sibNoBase && insn.sibScale == 8 && insn.modrmMod == 0 {
		targets, _, resolved := resolveSIBJumpTable(fn, insn, history, resolver, branchTargets, transferCursor)
		return targets, resolved
	}
	return nil, false
}

func resolveRegisterIndirectTargets(fn executableFunction, insn amd64Insn, history []decodedInsnSite, resolver *goTextResolver, branchTargets []int, transferCursor int) ([]uint64, bool) {
	if dest, ok := provenRegisterCodePointer(fn, insn.indirectRegID, history, resolver, branchTargets, transferCursor); ok {
		return []uint64{dest}, true
	}
	return resolvePointerTakenCallTargets(resolver)
}

func resolvePointerTakenCallTargets(resolver *goTextResolver) ([]uint64, bool) {
	if resolver == nil || len(resolver.pointerTaken) == 0 {
		return nil, false
	}
	// The static section inventory is a useful known subset, but it is not a
	// complete points-to proof. Go may materialize closure code pointers at
	// runtime (for example with a RIP-relative LEA) without storing the address
	// in any inventoried section. Traverse the known subset while keeping the
	// register-indirect transfer unbounded.
	return append([]uint64(nil), resolver.pointerTaken...), false
}

func provenRegisterCodePointer(fn executableFunction, reg uint8, history []decodedInsnSite, resolver *goTextResolver, branchTargets []int, transferCursor int) (uint64, bool) {
	fact, ok := provenRegisterFact(fn, reg, history, resolver, branchTargets, transferCursor)
	if !ok || fact.kind != registerFactCode {
		return 0, false
	}
	return fact.va, true
}

func provenRegisterFact(fn executableFunction, reg uint8, history []decodedInsnSite, resolver *goTextResolver, branchTargets []int, transferCursor int) (registerFact, bool) {
	if resolver == nil {
		return registerFact{}, false
	}
	for i := len(history) - 1; i >= 0; i-- {
		site := history[i]
		if site.insn.leaRIP && site.insn.operand64 && !site.insn.nonCanonicalMem && site.insn.leaReg == reg {
			if !jumpTableFactReachesTransfer(fn, site.cursor, transferCursor, resolver, branchTargets) {
				return registerFact{}, false
			}
			dest, ok := amd64RIPRelativeTarget(site)
			if !ok {
				return registerFact{}, false
			}
			return classifyLoadedPointer(resolver, dest)
		}
		if site.insn.movRIP && site.insn.operand64 && !site.insn.nonCanonicalMem && site.insn.leaReg == reg {
			if !jumpTableFactReachesTransfer(fn, site.cursor, transferCursor, resolver, branchTargets) {
				return registerFact{}, false
			}
			addr, ok := amd64RIPRelativeTarget(site)
			if !ok {
				return registerFact{}, false
			}
			dest, ok := resolver.readU64(addr)
			if !ok {
				return registerFact{}, false
			}
			return classifyLoadedPointer(resolver, dest)
		}
		if site.insn.movLoad && site.insn.operand64 && !site.insn.nonCanonicalMem && site.insn.leaReg == reg {
			if !jumpTableFactReachesTransfer(fn, site.cursor, transferCursor, resolver, branchTargets) {
				return registerFact{}, false
			}
			base, ok := provenRegisterFact(fn, site.insn.sibBase, history[:i], resolver, branchTargets, site.cursor)
			if !ok {
				return registerFact{}, false
			}
			disp := site.insn.leaDisp
			if disp < 0 {
				return registerFact{}, false
			}
			if base.kind == registerFactItab && disp >= itabFunOffset && disp%8 == 0 {
				methodVA := base.va + uint64(disp)
				if methodVA < base.va {
					return registerFact{}, false
				}
				dest, ok := resolver.readU64(methodVA)
				if !ok {
					return registerFact{}, false
				}
				return listedFunctionStart(resolver, dest)
			}
			return registerFact{}, false
		}
		if insnClobbersReg(site.insn, reg) {
			return registerFact{}, false
		}
	}
	return registerFact{}, false
}

func classifyLoadedPointer(resolver *goTextResolver, dest uint64) (registerFact, bool) {
	if resolver != nil {
		if _, ok := resolver.itabs[dest]; ok {
			return registerFact{kind: registerFactItab, va: dest}, true
		}
	}
	return listedFunctionStart(resolver, dest)
}

func listedFunctionStart(resolver *goTextResolver, dest uint64) (registerFact, bool) {
	if resolver == nil {
		return registerFact{}, false
	}
	callee := containingExecutableFunction(resolver.functions, dest)
	if callee == nil || dest != callee.start {
		return registerFact{}, false
	}
	return registerFact{kind: registerFactCode, va: dest}, true
}

func resolvedLocalJumpTableEntries(fn executableFunction, code []byte, resolver *goTextResolver, branchTargets []int) []int {
	if resolver == nil {
		return nil
	}
	var entries []int
	var history []decodedInsnSite
	for cursor := 0; cursor < len(code); {
		insn, ok := amd64DecodeInsn(code[cursor:])
		if !ok || insn.n <= 0 {
			return entries
		}
		if insn.indirectJump && !insn.nonCanonicalMem && insn.sib && !insn.sibNoBase && insn.sibScale == 8 && insn.modrmMod == 0 {
			_, local, resolved := resolveSIBJumpTable(fn, insn, history, resolver, branchTargets, cursor)
			if resolved {
				entries = append(entries, local...)
			}
		}
		history = append(history, decodedInsnSite{cursor: cursor, vaddr: fn.start + uint64(cursor), insn: insn})
		cursor += insn.n
	}
	return entries
}

func resolveSIBJumpTable(fn executableFunction, insn amd64Insn, history []decodedInsnSite, resolver *goTextResolver, branchTargets []int, transferCursor int) (extra []uint64, localEntries []int, resolved bool) {
	if resolver == nil || insn.sibIndex == 4 {
		return nil, nil, false
	}
	tableVA, haveTable := provenJumpTableBase(fn, insn.sibBase, history, resolver, branchTargets, transferCursor)
	length, haveLen := provenJumpTableLength(fn, insn.sibIndex, history, resolver, branchTargets, transferCursor, insn.n)
	if !haveTable || !haveLen || length <= 0 || length > maxProvenJumpTableEntries {
		return nil, nil, false
	}
	for index := 0; index < length; index++ {
		entryVA := tableVA + uint64(index)*8
		if entryVA < tableVA {
			return nil, nil, false
		}
		dest, ok := resolver.readU64(entryVA)
		if !ok {
			return nil, nil, false
		}
		callee := containingExecutableFunction(resolver.functions, dest)
		if callee == nil {
			return nil, nil, false
		}
		if dest >= fn.start && dest < fn.end {
			localEntries = append(localEntries, int(dest-fn.start))
			continue
		}
		// A cross-function interior entry may skip code-pointer facts at the
		// start of the destination function. The graph currently traverses a
		// listed callee from its canonical start, so only that exact start is a
		// complete cross-function table target proof.
		if dest != callee.start {
			return nil, nil, false
		}
		extra = append(extra, dest)
	}
	return extra, localEntries, true
}

func provenJumpTableBase(fn executableFunction, reg uint8, history []decodedInsnSite, resolver *goTextResolver, branchTargets []int, transferCursor int) (uint64, bool) {
	for i := len(history) - 1; i >= 0; i-- {
		site := history[i]
		if site.insn.leaRIP && site.insn.operand64 && !site.insn.nonCanonicalMem && site.insn.leaReg == reg {
			if !jumpTableFactReachesTransfer(fn, site.cursor, transferCursor, resolver, branchTargets) {
				return 0, false
			}
			return amd64RIPRelativeTarget(site)
		}
		if insnClobbersReg(site.insn, reg) {
			return 0, false
		}
	}
	return 0, false
}

func provenJumpTableLength(fn executableFunction, reg uint8, history []decodedInsnSite, resolver *goTextResolver, branchTargets []int, transferCursor, transferLength int) (int, bool) {
	for i := len(history) - 1; i >= 0; i-- {
		site := history[i]
		if site.insn.andImm && !site.insn.nonCanonicalMem && site.insn.andReg == reg {
			if site.insn.andVal >= maxProvenJumpTableEntries || !jumpTableFactReachesTransfer(fn, site.cursor, transferCursor, resolver, branchTargets) {
				return 0, false
			}
			return int(site.insn.andVal) + 1, true
		}
		if site.insn.ja {
			cmpIndex := i - 1
			for cmpIndex >= 0 && history[cmpIndex].insn.nop {
				cmpIndex--
			}
			if cmpIndex >= 0 {
				cmp := history[cmpIndex]
				jaTarget, targetOK := amd64RIPRelativeTarget(site)
				transferVA := fn.start + uint64(transferCursor)
				transferEnd := transferVA + uint64(transferLength)
				if transferVA < fn.start || transferEnd < transferVA {
					return 0, false
				}
				if targetOK && !site.insn.nonCanonicalMem && jaTarget >= transferEnd && jaTarget < fn.end &&
					cmp.insn.cmpImm && cmp.insn.operand64 && !cmp.insn.nonCanonicalMem && cmp.insn.cmpReg == reg &&
					cmp.insn.cmpVal < maxProvenJumpTableEntries &&
					jumpTableFactReachesTransfer(fn, cmp.cursor, transferCursor, resolver, branchTargets) {
					return int(cmp.insn.cmpVal) + 1, true
				}
			}
		}
		if insnClobbersReg(site.insn, reg) {
			return 0, false
		}
	}
	return 0, false
}

func jumpTableFactReachesTransfer(fn executableFunction, sourceCursor, transferCursor int, resolver *goTextResolver, branchTargets []int) bool {
	if !amd64ConstantFactReachesTransfer(sourceCursor, transferCursor, branchTargets) {
		return false
	}
	if resolver == nil {
		return true
	}
	sourceVA := fn.start + uint64(sourceCursor)
	transferVA := fn.start + uint64(transferCursor)
	if sourceVA < fn.start || transferVA < fn.start {
		return false
	}
	for _, entry := range resolver.interiorEntries[fn.start] {
		if entry > sourceVA && entry <= transferVA {
			return false
		}
	}
	return true
}

func amd64RIPRelativeTarget(site decodedInsnSite) (uint64, bool) {
	next := site.vaddr + uint64(site.insn.n)
	if next < site.vaddr {
		return 0, false
	}
	if site.insn.leaRIP || site.insn.movRIP {
		return addSignedAMD64Displacement(next, int64(site.insn.leaDisp))
	}
	if site.insn.jmpRel {
		return addSignedAMD64Displacement(next, site.insn.rel)
	}
	return 0, false
}

func addSignedAMD64Displacement(base uint64, displacement int64) (uint64, bool) {
	if displacement >= 0 {
		target := base + uint64(displacement)
		return target, target >= base
	}
	delta := uint64(-(displacement + 1)) + 1
	if delta > base {
		return 0, false
	}
	return base - delta, true
}

func insnClobbersReg(insn amd64Insn, reg uint8) bool {
	if insn.jmpRel || insn.cmpImm {
		return false
	}
	if insn.nop || insn.flagsOnly || insn.memStore {
		return false
	}
	if insn.leaRIP || insn.movRIP || insn.movLoad {
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
