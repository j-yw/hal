package v2control

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"
)

func validCredentialPrepareJSONInput(wire []byte) bool {
	if len(wire) == 0 || len(wire) > maxCredentialPrepareJSONBytes || !utf8.Valid(wire) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.UseNumber()
	tokens := 0
	if !scanCredentialPrepareJSONValue(decoder, 0, &tokens) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func scanCredentialPrepareJSONValue(decoder *json.Decoder, depth int, tokens *int) bool {
	token, err := decoder.Token()
	*tokens++
	if err != nil || *tokens > maxCredentialPrepareJSONTokens {
		return false
	}
	if value, ok := token.(string); ok && len(value) > maxCredentialPrepareJSONStringBytes {
		return false
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return true
	}
	nestedDepth := depth + 1
	if nestedDepth > maxCredentialPrepareJSONDepth {
		return false
	}
	switch delimiter {
	case '{':
		var keys [maxCredentialPrepareJSONObjectFields]string
		keyCount := 0
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			*tokens++
			key, isString := keyToken.(string)
			if keyErr != nil || !isString || len(key) > maxCredentialPrepareJSONStringBytes ||
				*tokens > maxCredentialPrepareJSONTokens || keyCount == len(keys) {
				return false
			}
			for index := 0; index < keyCount; index++ {
				if keys[index] == key {
					return false
				}
			}
			keys[keyCount] = key
			keyCount++
			if !scanCredentialPrepareJSONValue(decoder, nestedDepth, tokens) {
				return false
			}
		}
		closing, closeErr := decoder.Token()
		*tokens++
		return closeErr == nil && closing == json.Delim('}') && *tokens <= maxCredentialPrepareJSONTokens
	case '[':
		for decoder.More() {
			if !scanCredentialPrepareJSONValue(decoder, nestedDepth, tokens) {
				return false
			}
		}
		closing, closeErr := decoder.Token()
		*tokens++
		return closeErr == nil && closing == json.Delim(']') && *tokens <= maxCredentialPrepareJSONTokens
	default:
		return false
	}
}

func expectPrepareDelimiter(decoder *json.Decoder, want byte) bool {
	token, err := decoder.Token()
	delimiter, ok := token.(json.Delim)
	return err == nil && ok && delimiter == json.Delim(want)
}

func expectPrepareKey(decoder *json.Decoder, want string) bool {
	token, err := decoder.Token()
	key, ok := token.(string)
	return err == nil && ok && key == want
}

func readPrepareString(decoder *json.Decoder) (string, bool) {
	token, err := decoder.Token()
	value, ok := token.(string)
	return value, err == nil && ok && len(value) <= maxCredentialPrepareJSONStringBytes
}

func readPrepareUint64(decoder *json.Decoder) (uint64, bool) {
	token, err := decoder.Token()
	number, ok := token.(json.Number)
	if err != nil || !ok {
		return 0, false
	}
	value, parseErr := strconv.ParseUint(number.String(), 10, 64)
	return value, parseErr == nil && strconv.FormatUint(value, 10) == number.String()
}

func readPrepareInt64(decoder *json.Decoder) (int64, bool) {
	token, err := decoder.Token()
	number, ok := token.(json.Number)
	if err != nil || !ok {
		return 0, false
	}
	value, parseErr := strconv.ParseInt(number.String(), 10, 64)
	return value, parseErr == nil && strconv.FormatInt(value, 10) == number.String()
}

func readPrepareTrue(decoder *json.Decoder) bool {
	token, err := decoder.Token()
	value, ok := token.(bool)
	return err == nil && ok && value
}

func requirePrepareJSONEOF(decoder *json.Decoder) error {
	var trailing struct{}
	if err := decoder.Decode(&trailing); err == io.EOF {
		return nil
	}
	return ErrInvalidCredentialPrepareRequestJSON
}
