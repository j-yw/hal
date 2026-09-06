package applicationroute

import (
	"reflect"
	"strings"
)

const (
	maxRequestAuthorityBytes  = 512
	maxRequestPathBytes       = 4096
	maxRequestRawQueryBytes   = 4096
	maxRequestHeaderNames     = 128
	maxRequestHeaderNameBytes = 256
)

func validateRequestLiveShape(definition Definition, request Request) error {
	if !validRequestTarget(request.Target) ||
		!strings.HasPrefix(request.Target.Path, definition.Prefix) ||
		!validRequestHeaderValues(request.Headers) {
		return ErrHandlerDispatch
	}
	return nil
}

func validRequestTarget(target RequestTarget) bool {
	return validRequestAuthority(target.Authority) &&
		validRequestPath(target.Path) &&
		validRequestRawQuery(target.RawQuery)
}

func validRequestAuthority(authority string) bool {
	if len(authority) == 0 || len(authority) > maxRequestAuthorityBytes {
		return false
	}
	for index := range len(authority) {
		value := authority[index]
		if !visibleASCII(value) || strings.ContainsRune("@/\\?#", rune(value)) {
			return false
		}
	}
	return true
}

func validRequestPath(path string) bool {
	if len(path) == 0 || len(path) > maxRequestPathBytes || path[0] != '/' {
		return false
	}
	for index := range len(path) {
		value := path[index]
		if !visibleASCII(value) || strings.ContainsRune("\\?#", rune(value)) {
			return false
		}
	}
	return canonicalPercentTriplets(path)
}

func validRequestRawQuery(rawQuery string) bool {
	if len(rawQuery) > maxRequestRawQueryBytes || strings.HasPrefix(rawQuery, "?") {
		return false
	}
	for index := range len(rawQuery) {
		value := rawQuery[index]
		if !visibleASCII(value) || strings.ContainsRune("\\#", rune(value)) {
			return false
		}
	}
	return canonicalPercentTriplets(rawQuery)
}

func visibleASCII(value byte) bool {
	return value > 0x20 && value < 0x7f
}

func canonicalPercentTriplets(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] != '%' {
			continue
		}
		if index+2 >= len(value) || !uppercaseHex(value[index+1]) || !uppercaseHex(value[index+2]) {
			return false
		}
		index += 2
	}
	return true
}

func uppercaseHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'A' && value <= 'F'
}

func validRequestHeaderValues(headers RequestHeaderValues) bool {
	if nilRequestHeaderValues(headers) {
		return false
	}
	first, ok := safeRequestHeaderNames(headers)
	if !ok || len(first) > maxRequestHeaderNames {
		return false
	}
	snapshot := append([]string(nil), first...)
	if len(first) > 0 {
		first[0] = ""
	}
	second, ok := safeRequestHeaderNames(headers)
	if !ok || !sameRequestHeaderNames(snapshot, second) || !validRequestHeaderNames(snapshot) {
		return false
	}
	for _, name := range snapshot {
		firstCount, firstOK := safeRequestHeaderValueCount(headers, name)
		secondCount, secondOK := safeRequestHeaderValueCount(headers, name)
		if !firstOK || !secondOK || firstCount <= 0 || firstCount != secondCount {
			return false
		}
	}
	return true
}

func nilRequestHeaderValues(headers RequestHeaderValues) bool {
	if headers == nil {
		return true
	}
	value := reflect.ValueOf(headers)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func safeRequestHeaderNames(headers RequestHeaderValues) (names []string, ok bool) {
	ok = true
	defer func() {
		if recover() != nil {
			names = nil
			ok = false
		}
	}()
	return headers.Names(), true
}

func safeRequestHeaderValueCount(headers RequestHeaderValues, name string) (count int, ok bool) {
	ok = true
	defer func() {
		if recover() != nil {
			count = 0
			ok = false
		}
	}()
	return headers.ValueCount(name), true
}

func sameRequestHeaderNames(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validRequestHeaderNames(names []string) bool {
	for index, name := range names {
		if len(name) == 0 || len(name) > maxRequestHeaderNameBytes ||
			index > 0 && names[index-1] >= name {
			return false
		}
		for byteIndex := range len(name) {
			if !validRequestHeaderNameByte(name[byteIndex]) {
				return false
			}
		}
	}
	return true
}

func validRequestHeaderNameByte(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= '0' && value <= '9' ||
		strings.ContainsRune("!#$%&'*+-.^_`|~", rune(value))
}
