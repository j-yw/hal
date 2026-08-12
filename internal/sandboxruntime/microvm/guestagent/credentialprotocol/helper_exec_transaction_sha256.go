package credentialprotocol

import (
	"encoding/binary"
	"runtime"
)

// helperExecSHA256 is a minimal streaming SHA-256 owner whose entire retained
// state is explicitly wipeable. It exists because crypto/sha256.Reset leaves
// the unused portion of its internal message block untouched.
type helperExecSHA256 struct {
	chaining [8]uint32
	block    [64]byte
	used     uint8
	length   uint64
}

func newHelperExecSHA256() *helperExecSHA256 {
	owner := &helperExecSHA256{}
	owner.chaining = [8]uint32{
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}
	return owner
}

func (owner *helperExecSHA256) Write(payload []byte) {
	owner.length += uint64(len(payload))
	if owner.used != 0 {
		count := copy(owner.block[int(owner.used):], payload)
		owner.used += uint8(count)
		payload = payload[count:]
		if owner.used == uint8(len(owner.block)) {
			owner.consume(owner.block[:])
			clear(owner.block[:])
			owner.used = 0
		}
	}
	for len(payload) >= len(owner.block) {
		owner.consume(payload[:len(owner.block)])
		payload = payload[len(owner.block):]
	}
	if len(payload) != 0 {
		owner.used = uint8(copy(owner.block[:], payload))
	}
}

func (owner *helperExecSHA256) Sum256() [32]byte {
	copyOwner := *owner
	defer copyOwner.Wipe()
	bitLength := owner.length << 3
	var padding [72]byte
	padding[0] = 0x80
	paddingLength := 56 - int(owner.length%64)
	if paddingLength <= 0 {
		paddingLength += 64
	}
	copyOwner.Write(padding[:paddingLength])
	var encodedLength [8]byte
	binary.BigEndian.PutUint64(encodedLength[:], bitLength)
	copyOwner.Write(encodedLength[:])
	var digest [32]byte
	for index, word := range copyOwner.chaining {
		binary.BigEndian.PutUint32(digest[index*4:], word)
	}
	return digest
}

func (owner *helperExecSHA256) Wipe() {
	if owner == nil {
		return
	}
	clear(owner.chaining[:])
	clear(owner.block[:])
	owner.used = 0
	owner.length = 0
	runtime.KeepAlive(owner)
}

func (owner *helperExecSHA256) consume(message []byte) {
	constants := [...]uint32{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	}
	var schedule [64]uint32
	for index := 0; index < 16; index++ {
		schedule[index] = binary.BigEndian.Uint32(message[index*4:])
	}
	for index := 16; index < len(schedule); index++ {
		low := helperExecRotateRight32(schedule[index-15], 7) ^ helperExecRotateRight32(schedule[index-15], 18) ^ (schedule[index-15] >> 3)
		high := helperExecRotateRight32(schedule[index-2], 17) ^ helperExecRotateRight32(schedule[index-2], 19) ^ (schedule[index-2] >> 10)
		schedule[index] = schedule[index-16] + low + schedule[index-7] + high
	}
	a, b, c, d := owner.chaining[0], owner.chaining[1], owner.chaining[2], owner.chaining[3]
	e, f, g, h := owner.chaining[4], owner.chaining[5], owner.chaining[6], owner.chaining[7]
	for index := range schedule {
		upper := helperExecRotateRight32(e, 6) ^ helperExecRotateRight32(e, 11) ^ helperExecRotateRight32(e, 25)
		choice := (e & f) ^ (^e & g)
		first := h + upper + choice + constants[index] + schedule[index]
		lower := helperExecRotateRight32(a, 2) ^ helperExecRotateRight32(a, 13) ^ helperExecRotateRight32(a, 22)
		majority := (a & b) ^ (a & c) ^ (b & c)
		second := lower + majority
		h, g, f, e, d, c, b, a = g, f, e, d+first, c, b, a, first+second
	}
	owner.chaining[0] += a
	owner.chaining[1] += b
	owner.chaining[2] += c
	owner.chaining[3] += d
	owner.chaining[4] += e
	owner.chaining[5] += f
	owner.chaining[6] += g
	owner.chaining[7] += h
	clear(schedule[:])
	a, b, c, d, e, f, g, h = 0, 0, 0, 0, 0, 0, 0, 0
	runtime.KeepAlive(schedule)
}

func helperExecRotateRight32(value uint32, shift uint) uint32 {
	return value>>shift | value<<(32-shift)
}
