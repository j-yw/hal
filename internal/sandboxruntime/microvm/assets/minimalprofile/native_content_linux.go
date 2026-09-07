//go:build linux

package minimalprofile

import "strings"

// Keep the original marker vocabulary and inspect each occurrence, without
// allocating an image-sized match inventory or altering the measured bytes.
func hasSecretContent(data []byte) bool {
	if int64(len(data)) > maxContent {
		return true
	}
	for offset := 0; offset < len(data); {
		match := secretContent.FindIndex(data[offset:])
		if match == nil {
			return false
		}
		start, end := offset+match[0], offset+match[1]
		// Private-key headers and canaries never qualify for an exception.
		if data[end-1] != '=' {
			return true
		}
		// The original case-folding regex also recognizes Unicode aliases.
		// Keep rejecting them; the two harmless grammars have ASCII keys only.
		for _, b := range data[start:end] {
			if b >= 0x80 {
				return true
			}
		}
		if end < len(data) && data[end] == '=' {
			if !nativeContentTypeTest(data, start, end) {
				return true
			}
		} else if !nativeContentExample(data, start, end) {
			return true
		}
		// Advance only past this marker, not its line or surrounding expression.
		offset = end
	}
	return false
}

func nativeContentExample(data []byte, start, end int) bool {
	right := end
	for right < len(data) && nativeContentHorizontal(data[right]) {
		right++
	}
	if len(data)-right < 3 || string(data[right:right+3]) != "..." {
		return false
	}
	right += 3
	for right < len(data) && nativeContentHorizontal(data[right]) {
		right++
	}
	if right != len(data) && data[right] != '\n' && !(data[right] == '\r' && right+1 < len(data) && data[right+1] == '\n') {
		return false
	}
	left := start
	for left > 0 && nativeContentHorizontal(data[left-1]) {
		left--
	}
	if left != start && left >= 6 && string(data[left-6:left]) == "export" {
		left -= 6
		for left > 0 && nativeContentHorizontal(data[left-1]) {
			left--
		}
	}
	return left == 0 || data[left-1] == '\n'
}

func nativeContentTypeTest(data []byte, start, end int) bool {
	// The caller already consumed the first '=' and observed the second.
	right := end + 1
	if right < len(data) && data[right] == '=' {
		right++
	}
	for right < len(data) && nativeContentHorizontal(data[right]) {
		right++
	}
	if len(data)-right < 8 || (string(data[right:right+8]) != `"string"` && string(data[right:right+8]) != `'string'`) {
		return false
	}
	right += 8
	if right != len(data) && !strings.ContainsRune(" \t\r\n),;:&|?!}]", rune(data[right])) {
		return false
	}
	// Walk only this qualified identifier, not the entire earlier file/line.
	left := start
	for {
		if left == 0 || data[left-1] != '.' {
			return false
		}
		left--
		identEnd := left
		for left > 0 && (nativeContentIdentifierStart(data[left-1]) || (data[left-1] >= '0' && data[left-1] <= '9')) {
			left--
		}
		if left == identEnd || !nativeContentIdentifierStart(data[left]) {
			return false
		}
		if left == 0 || data[left-1] != '.' {
			break
		}
	}
	identStart := left
	for left > 0 && nativeContentHorizontal(data[left-1]) {
		left--
	}
	if left == identStart || left < 6 || string(data[left-6:left]) != "typeof" {
		return false
	}
	left -= 6
	return left == 0 || strings.ContainsRune(" \t\r\n(!&|?:={[,;", rune(data[left-1]))
}

func nativeContentHorizontal(b byte) bool { return b == ' ' || b == '\t' }

func nativeContentIdentifierStart(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b == '_' || b == '$'
}
