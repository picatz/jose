// Package strictjson rejects JSON whose objects repeat a member name.
//
// RFC 7515 §4 lets a JOSE parser either reject duplicate Header Parameter
// names or keep the last one. Keeping the last one is what encoding/json
// does, but another implementation may keep the first, so the same bytes
// could mean "alg":"none" to one verifier and "alg":"ES256" to another.
// Rejecting duplicates removes that disagreement.
//
// https://www.rfc-editor.org/rfc/rfc7515.html#section-4
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// maxDepth bounds nesting so hostile input cannot exhaust the stack.
const maxDepth = 64

// CheckDuplicates reports an error if data is not a single JSON value or
// if any object in it, at any depth, repeats a member name.
func CheckDuplicates(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := checkValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

func checkValue(decoder *json.Decoder, depth int) error {
	if depth > maxDepth {
		return errors.New("JSON nested too deeply")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			name, err := decoder.Token()
			if err != nil {
				return err
			}
			key, _ := name.(string)
			if seen[key] {
				return fmt.Errorf("duplicate member %q", key)
			}
			seen[key] = true
			if err := checkValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := checkValue(decoder, depth+1); err != nil {
				return err
			}
		}
	}
	_, err = decoder.Token() // the closing delimiter
	return err
}
