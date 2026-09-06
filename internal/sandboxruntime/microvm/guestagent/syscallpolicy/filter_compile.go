package syscallpolicy

import (
	"encoding/binary"
	"sort"
)

const (
	compiledFilterDomain = "hal/l8/compiled-seccomp-filter/linux-amd64/v1"
	bpfMaxInsns          = 4096
	bpfMaxSteps          = 65536
	seccompDataNR        = 0
	seccompDataArch      = 4
	seccompDataArg0      = 16
	auditArchX86_64      = 0xc000003e
	x32SyscallBit        = 0x40000000
	seccompDataBytes     = 64
	bpfKillFlag          = 0
	bpfMatchedFlag       = 1

	bpfLd  = 0x00
	bpfAlu = 0x04
	bpfJmp = 0x05
	bpfRet = 0x06
	bpfSt  = 0x02
	bpfW   = 0x00
	bpfImm = 0x00
	bpfAbs = 0x20
	bpfMem = 0x60
	bpfAnd = 0x50
	bpfJa  = 0x00
	bpfJeq = 0x10
	bpfJgt = 0x20
	bpfJge = 0x30
	bpfK   = 0x00
)

const (
	bpfLdImm    = bpfLd | bpfW | bpfImm
	bpfLdAbs    = bpfLd | bpfW | bpfAbs
	bpfLdMem    = bpfLd | bpfW | bpfMem
	bpfAluAndK  = bpfAlu | bpfAnd | bpfK
	bpfJmpJa    = bpfJmp | bpfJa
	bpfJmpJeqK  = bpfJmp | bpfJeq | bpfK
	bpfJmpJgtK  = bpfJmp | bpfJgt | bpfK
	bpfJmpJgeK  = bpfJmp | bpfJge | bpfK
	bpfJmpJsetK = bpfJmp | 0x40 | bpfK
	bpfRetK     = bpfRet | bpfK
)

// SockFilter is one classic Linux sock_filter instruction.
type SockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

// CompiledFilter is the classic BPF sock_fprog body for one FilterProfile.
type CompiledFilter struct {
	instructions []SockFilter
	sha256       [32]byte
}

func (filter CompiledFilter) Instructions() []SockFilter {
	if len(filter.instructions) == 0 {
		return nil
	}
	return append([]SockFilter(nil), filter.instructions...)
}

func (filter CompiledFilter) Len() int { return len(filter.instructions) }

func (filter CompiledFilter) SHA256() [32]byte { return filter.sha256 }

func (filter CompiledFilter) CanonicalBytes() []byte {
	if len(filter.instructions) == 0 {
		return nil
	}
	encoded := make([]byte, 0, len(filter.instructions)*8)
	for _, insn := range filter.instructions {
		var row [8]byte
		binary.LittleEndian.PutUint16(row[0:2], insn.Code)
		row[2] = insn.Jt
		row[3] = insn.Jf
		binary.LittleEndian.PutUint32(row[4:8], insn.K)
		encoded = append(encoded, row[:]...)
	}
	return encoded
}

// CompileFilterProfile is D4's host-side compiler from a verified FilterProfile
// to a deny-by-default classic BPF program. Actions match FilterProfile.Decide.
func CompileFilterProfile(profile FilterProfile) (CompiledFilter, error) {
	if profile.profile == nil || zeroDigest(profile.profile.sha256) {
		return CompiledFilter{}, contractError(ErrorCodeOwnership)
	}
	if profile.profile.kernelCeiling == 0 {
		return CompiledFilter{}, contractError(ErrorCodeCatalog)
	}
	program, err := compileProfileProgram(profile.profile)
	if err != nil {
		return CompiledFilter{}, err
	}
	filter := CompiledFilter{instructions: program}
	preimage := append(append([]byte(nil), profile.profile.sha256[:]...), filter.CanonicalBytes()...)
	filter.sha256 = framedSHA256(compiledFilterDomain, preimage)
	return filter, nil
}

// CompileIssuedRoleFilter imports an issued HL8Q artifact and compiles that
// role's FilterProfile. The private issuer marker stays inside this leaf.
func CompileIssuedRoleFilter(encoded []byte, digest [32]byte, role Role) (CompiledFilter, error) {
	if len(encoded) == 0 || zeroDigest(digest) {
		return CompiledFilter{}, contractError(ErrorCodeOwnership)
	}
	if err := ValidateRole(role); err != nil {
		return CompiledFilter{}, err
	}
	artifact, err := ImportVerifiedPolicyArtifact(encoded, ExpectedPolicyArtifact{
		sha256: digest,
		issuer: expectedIssuer{issued: true},
	})
	if err != nil {
		return CompiledFilter{}, err
	}
	policy, err := NewPolicy(artifact)
	if err != nil {
		return CompiledFilter{}, err
	}
	profile, err := policy.FilterProfile(role)
	if err != nil {
		return CompiledFilter{}, err
	}
	return CompileFilterProfile(profile)
}

func (filter CompiledFilter) Action(auditArchitecture uint32, rawSyscallNumber uint32, arguments [6]uint64) Action {
	action, err := evalClassicSeccomp(filter.instructions, auditArchitecture, rawSyscallNumber, arguments)
	if err != nil {
		return ActionKillProcess
	}
	return action
}

type labelID int

type bpfFixup struct {
	index int
	kind  byte
	label labelID
}

type bpfGen struct {
	insns  []SockFilter
	labels map[labelID]int
	fixups []bpfFixup
	nextID labelID
}

func compileProfileProgram(profile *filterProfile) ([]SockFilter, error) {
	g := &bpfGen{labels: make(map[labelID]int)}
	rulesByNumber := make(map[SyscallNumber][]*filterRule)
	for _, rule := range profile.rules {
		if rule == nil {
			return nil, contractError(ErrorCodeEncoding)
		}
		rulesByNumber[rule.syscallNumber] = append(rulesByNumber[rule.syscallNumber], rule)
	}
	type dispatchRow struct {
		number SyscallNumber
		rules  []*filterRule
	}
	rows := make([]dispatchRow, 0)
	for _, entry := range profile.catalog {
		if entry == nil {
			return nil, contractError(ErrorCodeCatalog)
		}
		if entry.class == SyscallClassFatal {
			continue
		}
		if ValidateSyscallClass(entry.class) != nil {
			return nil, contractError(ErrorCodeCatalog)
		}
		rows = append(rows, dispatchRow{number: entry.number, rules: rulesByNumber[entry.number]})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].number < rows[j].number })
	handlers := make([]labelID, len(rows))
	for index := range rows {
		handlers[index] = g.newLabel()
	}

	g.ldAbs(seccompDataArch)
	g.emit(bpfJmpJeqK, 1, 0, auditArchX86_64)
	g.ret(uint32(ActionKillProcess))
	g.ldAbs(seccompDataNR)
	g.emit(bpfJmpJsetK, 0, 1, x32SyscallBit)
	g.ret(uint32(ActionKillProcess))
	g.emit(bpfJmpJgtK, 0, 1, uint32(profile.kernelCeiling))
	g.ret(uint32(ActionKillProcess))

	for index, row := range rows {
		g.emit(bpfJmpJeqK, 0, 1, uint32(row.number))
		g.ja(handlers[index])
	}
	g.ret(uint32(ActionKillProcess))
	for index, row := range rows {
		g.place(handlers[index])
		if err := g.compileNumber(row.rules); err != nil {
			return nil, err
		}
	}
	if err := g.resolve(); err != nil {
		return nil, err
	}
	return g.insns, nil
}

func (g *bpfGen) compileNumber(rules []*filterRule) error {
	if len(rules) == 0 {
		g.ret(uint32(ActionErrnoEPERM))
		return nil
	}
	allow := g.newLabel()
	kill := g.newLabel()
	eperm := g.newLabel()
	g.emit(bpfLdImm, 0, 0, 0)
	g.emit(bpfSt, 0, 0, bpfKillFlag)
	for _, rule := range rules {
		nextRule := g.newLabel()
		g.emit(bpfLdImm, 0, 0, 1)
		g.emit(bpfSt, 0, 0, bpfMatchedFlag)
		for _, clause := range rule.clauses {
			if clause == nil {
				return contractError(ErrorCodeEncoding)
			}
			clauseFail := g.newLabel()
			clauseOK := g.newLabel()
			if err := g.compileClause(clause, clauseFail); err != nil {
				return err
			}
			g.ja(clauseOK)
			g.place(clauseFail)
			g.emit(bpfLdImm, 0, 0, 0)
			g.emit(bpfSt, 0, 0, bpfMatchedFlag)
			if clause.mismatchAction == ActionKillProcess {
				g.emit(bpfLdImm, 0, 0, 1)
				g.emit(bpfSt, 0, 0, bpfKillFlag)
			}
			g.place(clauseOK)
		}
		g.emit(bpfLdMem, 0, 0, bpfMatchedFlag)
		g.emit(bpfJmpJeqK, 0, 1, 1)
		g.ja(allow)
		g.place(nextRule)
	}
	g.emit(bpfLdMem, 0, 0, bpfKillFlag)
	g.emit(bpfJmpJeqK, 0, 1, 1)
	g.ja(kill)
	g.ja(eperm)
	g.place(kill)
	g.ret(uint32(ActionKillProcess))
	g.place(eperm)
	g.ret(uint32(ActionErrnoEPERM))
	g.place(allow)
	g.ret(uint32(ActionAllow))
	return nil
}

func (g *bpfGen) compileClause(clause *scalarClause, fail labelID) error {
	if clause.argumentIndex > 5 {
		return contractError(ErrorCodeBounds)
	}
	lo := uint32(seccompDataArg0 + int(clause.argumentIndex)*8)
	hi := lo + 4
	switch clause.operation {
	case ScalarEqual:
		if len(clause.values) < 1 {
			return contractError(ErrorCodeEncoding)
		}
		g.requireEqual64(lo, hi, clause.values[0], fail)
	case ScalarMaskedEqual:
		if len(clause.values) < 1 {
			return contractError(ErrorCodeEncoding)
		}
		g.requireMaskedEqual64(lo, hi, clause.mask, clause.values[0], fail)
	case ScalarOneOf:
		g.requireOneOf64(lo, hi, clause.values, fail)
	case ScalarUnsignedRange:
		if len(clause.values) < 2 {
			return contractError(ErrorCodeEncoding)
		}
		g.requireUnsignedRange64(lo, hi, clause.values[0], clause.values[1], fail)
	case ScalarZero:
		g.requireEqual64(lo, hi, 0, fail)
	case ScalarNonzero:
		g.requireNonzero64(lo, hi, fail)
	default:
		return contractError(ErrorCodeEncoding)
	}
	return nil
}

func (g *bpfGen) requireEqual64(loOff, hiOff uint32, value uint64, fail labelID) {
	g.ldAbs(loOff)
	g.requireAEq(uint32(value), fail)
	g.ldAbs(hiOff)
	g.requireAEq(uint32(value>>32), fail)
}

func (g *bpfGen) requireMaskedEqual64(loOff, hiOff uint32, mask, value uint64, fail labelID) {
	g.ldAbs(loOff)
	g.emit(bpfAluAndK, 0, 0, uint32(mask))
	g.requireAEq(uint32(value), fail)
	g.ldAbs(hiOff)
	g.emit(bpfAluAndK, 0, 0, uint32(mask>>32))
	g.requireAEq(uint32(value>>32), fail)
}

func (g *bpfGen) requireOneOf64(loOff, hiOff uint32, values []uint64, fail labelID) {
	if len(values) == 0 {
		g.ja(fail)
		return
	}
	ok := g.newLabel()
	for _, value := range values {
		next := g.newLabel()
		g.ldAbs(loOff)
		g.emit(bpfJmpJeqK, 1, 0, uint32(value))
		g.ja(next)
		g.ldAbs(hiOff)
		g.emit(bpfJmpJeqK, 0, 1, uint32(value>>32))
		g.ja(ok)
		g.place(next)
	}
	g.ja(fail)
	g.place(ok)
}

func (g *bpfGen) requireUnsignedRange64(loOff, hiOff uint32, low, high uint64, fail labelID) {
	g.requireUnsignedGE64(loOff, hiOff, low, fail)
	g.requireUnsignedLE64(loOff, hiOff, high, fail)
}

func (g *bpfGen) requireUnsignedGE64(loOff, hiOff uint32, bound uint64, fail labelID) {
	ok := g.newLabel()
	boundLo := uint32(bound)
	boundHi := uint32(bound >> 32)
	g.ldAbs(hiOff)
	g.emit(bpfJmpJgtK, 0, 1, boundHi)
	g.ja(ok)
	g.emit(bpfJmpJeqK, 1, 0, boundHi)
	g.ja(fail)
	g.ldAbs(loOff)
	g.emit(bpfJmpJgeK, 0, 1, boundLo)
	g.ja(ok)
	g.ja(fail)
	g.place(ok)
}

func (g *bpfGen) requireUnsignedLE64(loOff, hiOff uint32, bound uint64, fail labelID) {
	ok := g.newLabel()
	boundLo := uint32(bound)
	boundHi := uint32(bound >> 32)
	g.ldAbs(hiOff)
	g.emit(bpfJmpJgtK, 0, 1, boundHi)
	g.ja(fail)
	g.emit(bpfJmpJeqK, 1, 0, boundHi)
	g.ja(ok)
	g.ldAbs(loOff)
	g.emit(bpfJmpJgtK, 0, 1, boundLo)
	g.ja(fail)
	g.ja(ok)
	g.place(ok)
}

func (g *bpfGen) requireNonzero64(loOff, hiOff uint32, fail labelID) {
	ok := g.newLabel()
	g.ldAbs(loOff)
	g.emit(bpfJmpJeqK, 1, 0, 0)
	g.ja(ok)
	g.ldAbs(hiOff)
	g.emit(bpfJmpJeqK, 0, 1, 0)
	g.ja(fail)
	g.place(ok)
}

func (g *bpfGen) requireAEq(k uint32, fail labelID) {
	g.emit(bpfJmpJeqK, 1, 0, k)
	g.ja(fail)
}

func (g *bpfGen) newLabel() labelID {
	g.nextID++
	return g.nextID
}

func (g *bpfGen) place(id labelID) {
	g.labels[id] = len(g.insns)
}

func (g *bpfGen) emit(code uint16, jt, jf uint8, k uint32) {
	g.insns = append(g.insns, SockFilter{Code: code, Jt: jt, Jf: jf, K: k})
}

func (g *bpfGen) ldAbs(offset uint32) { g.emit(bpfLdAbs, 0, 0, offset) }

func (g *bpfGen) ret(k uint32) { g.emit(bpfRetK, 0, 0, k) }

func (g *bpfGen) ja(id labelID) {
	g.fixups = append(g.fixups, bpfFixup{index: len(g.insns), kind: 'a', label: id})
	g.emit(bpfJmpJa, 0, 0, 0)
}

func (g *bpfGen) resolve() error {
	if len(g.insns) == 0 || len(g.insns) > bpfMaxInsns {
		return contractError(ErrorCodeBounds)
	}
	for _, fix := range g.fixups {
		target, ok := g.labels[fix.label]
		if !ok {
			return contractError(ErrorCodeEncoding)
		}
		delta := target - fix.index - 1
		if delta < 0 {
			return contractError(ErrorCodeBounds)
		}
		switch fix.kind {
		case 'a':
			g.insns[fix.index].K = uint32(delta)
		default:
			return contractError(ErrorCodeEncoding)
		}
	}
	return nil
}

func evalClassicSeccomp(insns []SockFilter, arch, nr uint32, arguments [6]uint64) (Action, error) {
	if len(insns) == 0 || len(insns) > bpfMaxInsns {
		return ActionKillProcess, contractError(ErrorCodeBounds)
	}
	packet := make([]byte, seccompDataBytes)
	binary.LittleEndian.PutUint32(packet[seccompDataNR:seccompDataNR+4], nr)
	binary.LittleEndian.PutUint32(packet[seccompDataArch:seccompDataArch+4], arch)
	for index, value := range arguments {
		binary.LittleEndian.PutUint64(packet[seccompDataArg0+index*8:seccompDataArg0+(index+1)*8], value)
	}
	var a uint32
	var mem [16]uint32
	pc := 0
	for step := 0; step < bpfMaxSteps; step++ {
		if pc < 0 || pc >= len(insns) {
			return ActionKillProcess, contractError(ErrorCodeEncoding)
		}
		insn := insns[pc]
		switch insn.Code {
		case bpfLdImm:
			a = insn.K
			pc++
		case bpfLdAbs:
			if insn.K > uint32(len(packet)-4) {
				return ActionKillProcess, contractError(ErrorCodeBounds)
			}
			a = binary.LittleEndian.Uint32(packet[insn.K : insn.K+4])
			pc++
		case bpfLdMem:
			if insn.K > 15 {
				return ActionKillProcess, contractError(ErrorCodeBounds)
			}
			a = mem[insn.K]
			pc++
		case bpfSt:
			if insn.K > 15 {
				return ActionKillProcess, contractError(ErrorCodeBounds)
			}
			mem[insn.K] = a
			pc++
		case bpfAluAndK:
			a &= insn.K
			pc++
		case bpfJmpJa:
			pc += 1 + int(insn.K)
		case bpfJmpJeqK:
			if a == insn.K {
				pc += 1 + int(insn.Jt)
			} else {
				pc += 1 + int(insn.Jf)
			}
		case bpfJmpJgtK:
			if a > insn.K {
				pc += 1 + int(insn.Jt)
			} else {
				pc += 1 + int(insn.Jf)
			}
		case bpfJmpJgeK:
			if a >= insn.K {
				pc += 1 + int(insn.Jt)
			} else {
				pc += 1 + int(insn.Jf)
			}
		case bpfJmpJsetK:
			if a&insn.K != 0 {
				pc += 1 + int(insn.Jt)
			} else {
				pc += 1 + int(insn.Jf)
			}
		case bpfRetK:
			switch Action(insn.K) {
			case ActionAllow, ActionErrnoEPERM, ActionKillProcess:
				return Action(insn.K), nil
			default:
				return ActionKillProcess, contractError(ErrorCodeEncoding)
			}
		default:
			return ActionKillProcess, contractError(ErrorCodeEncoding)
		}
	}
	return ActionKillProcess, contractError(ErrorCodeBounds)
}
