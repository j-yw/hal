package v2control

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

const maxIdentityJSONDepth = 4

// MarshalJobIdentity emits the exact validated lower-camel canonical object.
func MarshalJobIdentity(identity JobIdentity) ([]byte, error) {
	if err := ValidateJobIdentity(identity); err != nil {
		return nil, err
	}
	wire, err := json.Marshal(identity)
	if err != nil {
		return nil, ErrInvalidJobIdentityJSON
	}
	return wire, nil
}

// DecodeJobIdentity accepts only the exact canonical object emitted by
// MarshalJobIdentity and returns a defensive value.
func DecodeJobIdentity(wire []byte) (JobIdentity, error) {
	if len(wire) == 0 || !utf8.Valid(wire) || rejectDuplicateJSONKeys(wire) != nil {
		return JobIdentity{}, ErrInvalidJobIdentityJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var identity JobIdentity
	if err := decoder.Decode(&identity); err != nil {
		return JobIdentity{}, ErrInvalidJobIdentityJSON
	}
	if err := requireJSONEOF(decoder); err != nil {
		return JobIdentity{}, ErrInvalidJobIdentityJSON
	}
	canonical, err := MarshalJobIdentity(identity)
	if err != nil || !bytes.Equal(canonical, wire) {
		return JobIdentity{}, ErrInvalidJobIdentityJSON
	}
	return cloneJobIdentity(identity), nil
}

func rejectDuplicateJSONKeys(wire []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxIdentityJSONDepth {
		return ErrInvalidJobIdentityJSON
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalidJobIdentityJSON
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, ok := keyToken.(string)
			if keyErr != nil || !ok {
				return ErrInvalidJobIdentityJSON
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrInvalidJobIdentityJSON
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			return ErrInvalidJobIdentityJSON
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			return ErrInvalidJobIdentityJSON
		}
	default:
		return ErrInvalidJobIdentityJSON
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra struct{}
	err := decoder.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	return ErrInvalidJobIdentityJSON
}
