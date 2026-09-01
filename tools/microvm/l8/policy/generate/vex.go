package main

func amd64VectorInstructionEnd(code []byte, start int, operand16 bool) (int, bool) {
	if start >= len(code) {
		return 0, false
	}
	index := start
	first := code[index]
	index++
	mapSel := 0
	switch first {
	case 0xC5:
		if index >= len(code) {
			return 0, false
		}
		index++
		mapSel = 1
	case 0xC4:
		if index+1 >= len(code) {
			return 0, false
		}
		vex1 := code[index]
		index += 2
		switch vex1 & 0x1f {
		case 1:
			mapSel = 1
		case 2:
			mapSel = 2
		case 3:
			mapSel = 3
		default:
			return 0, false
		}
	case 0x62:
		if index+2 >= len(code) {
			return 0, false
		}
		p0 := code[index]
		if p0&0x0c != 0 {
			return 0, false
		}
		switch p0 & 3 {
		case 1:
			mapSel = 1
		case 2:
			mapSel = 2
		case 3:
			mapSel = 3
		default:
			return 0, false
		}
		index += 3
	default:
		return 0, false
	}
	if index >= len(code) {
		return 0, false
	}
	opcode := code[index]
	index++
	hasModRM := true
	imm := 0
	switch mapSel {
	case 1:
		hasModRM, imm = amd64TwoByte0FMeta(opcode, operand16)
	case 2:
		hasModRM = true
	case 3:
		hasModRM = true
		imm = 1
	default:
		return 0, false
	}
	if hasModRM {
		next, _, ok := amd64ConsumeModRM(code, index)
		if !ok {
			return 0, false
		}
		index = next
	}
	if index+imm > len(code) {
		return 0, false
	}
	return index + imm, true
}

func amd64TwoByte0FMeta(opcode byte, operand16 bool) (hasModRM bool, imm int) {
	switch {
	case opcode >= 0x80 && opcode <= 0x8F:
		if operand16 {
			return false, 2
		}
		return false, 4
	case opcode == 0x05 || opcode == 0x06 || opcode == 0x07 || opcode == 0x08 || opcode == 0x09 || opcode == 0x0B || opcode == 0x30 || opcode == 0x31 || opcode == 0x32 || opcode == 0x33 || opcode == 0x34 || opcode == 0x35 || opcode == 0x37 || opcode == 0x77 || opcode == 0xA0 || opcode == 0xA1 || opcode == 0xA2 || opcode == 0xA8 || opcode == 0xA9 || opcode == 0xAA:
		return false, 0
	case opcode == 0x70 || opcode == 0x71 || opcode == 0x72 || opcode == 0x73 || opcode == 0xA4 || opcode == 0xAC || opcode == 0xBA || opcode == 0xC2 || opcode == 0xC4 || opcode == 0xC5 || opcode == 0xC6:
		return true, 1
	default:
		return true, 0
	}
}
