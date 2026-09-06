package main

import (
	"debug/elf"
	"encoding/binary"
)

func collectItabAddresses(file *elf.File, encoded []byte) map[uint64]struct{} {
	if file == nil || len(encoded) < 8 {
		return nil
	}
	section := file.Section(".itablink")
	if section == nil || section.FileSize < 8 {
		return nil
	}
	end := section.Offset + section.FileSize
	if end < section.Offset || end > uint64(len(encoded)) {
		return nil
	}
	off := section.Offset
	if rem := off % 8; rem != 0 {
		off += 8 - rem
	}
	itabs := make(map[uint64]struct{})
	for off+8 <= end {
		va := binary.LittleEndian.Uint64(encoded[off : off+8])
		if va != 0 {
			itabs[va] = struct{}{}
		}
		next := off + 8
		if next <= off {
			break
		}
		off = next
	}
	if len(itabs) == 0 {
		return nil
	}
	return itabs
}
