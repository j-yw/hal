package main

import (
	"debug/elf"
	"encoding/binary"
	"sort"
)

func collectPointerTakenFunctionTargets(file *elf.File, encoded []byte, functions []executableFunction) []uint64 {
	if file == nil || len(encoded) < 8 || len(functions) == 0 {
		return nil
	}
	starts := make(map[uint64]struct{}, len(functions))
	for _, fn := range functions {
		starts[fn.start] = struct{}{}
	}
	seen := make(map[uint64]struct{})
	var targets []uint64
	add := func(dest uint64) {
		if _, ok := starts[dest]; !ok {
			return
		}
		if _, ok := seen[dest]; ok {
			return
		}
		seen[dest] = struct{}{}
		targets = append(targets, dest)
	}
	for _, section := range pointerTakenSections(file) {
		if section.FileSize < 8 {
			continue
		}
		end := section.Offset + section.FileSize
		if end < section.Offset || end > uint64(len(encoded)) {
			continue
		}
		off := section.Offset
		if rem := off % 8; rem != 0 {
			off += 8 - rem
		}
		for off+8 <= end {
			add(binary.LittleEndian.Uint64(encoded[off : off+8]))
			next := off + 8
			if next <= off {
				break
			}
			off = next
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i] < targets[j] })
	return targets
}

func pointerTakenSections(file *elf.File) []*elf.Section {
	if file == nil {
		return nil
	}
	var sections []*elf.Section
	for _, section := range file.Sections {
		if section == nil || !includedPointerTakenSection(section.Name) {
			continue
		}
		sections = append(sections, section)
	}
	return sections
}

func includedPointerTakenSection(name string) bool {
	switch name {
	case ".noptrdata", ".data", ".itablink":
		return true
	default:
		return false
	}
}
