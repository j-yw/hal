package guestagent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

const maxStrictJSONDepth = 64

func strictUnmarshalObject(encoded []byte, destination any) error {
	if len(encoded) == 0 || !utf8.Valid(encoded) {
		return fmt.Errorf("response must be one UTF-8 JSON object")
	}
	if err := validateStrictJSONObject(encoded, maxStrictJSONDepth); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func validateStrictJSONObject(encoded []byte, maximumDepth int) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	root, ok := token.(json.Delim)
	if !ok || root != '{' {
		return fmt.Errorf("JSON root must be an object")
	}
	if err := validateStrictObjectTokens(decoder, 1, maximumDepth); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func validateStrictObjectTokens(decoder *json.Decoder, depth, maximumDepth int) error {
	if depth > maximumDepth {
		return fmt.Errorf("JSON nesting exceeds limit")
	}
	keys := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("JSON object key is malformed")
		}
		if _, duplicate := keys[key]; duplicate {
			return fmt.Errorf("JSON object contains duplicate key")
		}
		keys[key] = struct{}{}
		if err := validateStrictValueTokens(decoder, depth+1, maximumDepth); err != nil {
			return err
		}
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return fmt.Errorf("JSON object is not terminated")
	}
	return nil
}

func validateStrictArrayTokens(decoder *json.Decoder, depth, maximumDepth int) error {
	if depth > maximumDepth {
		return fmt.Errorf("JSON nesting exceeds limit")
	}
	for decoder.More() {
		if err := validateStrictValueTokens(decoder, depth+1, maximumDepth); err != nil {
			return err
		}
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != ']' {
		return fmt.Errorf("JSON array is not terminated")
	}
	return nil
}

func validateStrictValueTokens(decoder *json.Decoder, depth, maximumDepth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		return validateStrictObjectTokens(decoder, depth, maximumDepth)
	case '[':
		return validateStrictArrayTokens(decoder, depth, maximumDepth)
	default:
		return fmt.Errorf("JSON value delimiter is malformed")
	}
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("JSON contains trailing data")
}
