package main

import (
	"debug/elf"
	"encoding/binary"
	"testing"
)

func TestL8D7CollectItabAddressesReadsItablink(t *testing.T) {
	encoded := make([]byte, 24)
	binary.LittleEndian.PutUint64(encoded[0:8], 0x2000)
	binary.LittleEndian.PutUint64(encoded[8:16], 0)
	binary.LittleEndian.PutUint64(encoded[16:24], 0x3000)
	itablink := &elf.Section{SectionHeader: elf.SectionHeader{
		Name:     ".itablink",
		Offset:   0,
		FileSize: 24,
	}}
	got := collectItabAddresses(&elf.File{Sections: []*elf.Section{itablink}}, encoded)
	if _, ok := got[0x2000]; !ok {
		t.Fatalf("itabs = %v, want 0x2000", got)
	}
	if _, ok := got[0x3000]; !ok {
		t.Fatalf("itabs = %v, want 0x3000", got)
	}
	if _, ok := got[0]; ok {
		t.Fatal("zero itablink word was treated as an itab")
	}
}
