package strictjson

import (
	"strings"
	"testing"
)

func TestCheckDuplicates(t *testing.T) {
	for input, ok := range map[string]bool{
		`{"alg":"ES256","kid":"1"}`:           true,
		`{"a":{"b":1},"c":[{"b":2},{"b":3}]}`: true,
		`[]`:                                  true,
		`{"alg":"none","alg":"ES256"}`:        false,
		`{"jwk":{"kty":"EC","kty":"RSA"}}`:    false,
		`{"x":[{"y":1,"y":2}]}`:               false,
		`{"alg":"ES256"} {}`:                  false,
		`{"alg":`:                             false,
		strings.Repeat("[", 100) + strings.Repeat("]", 100): false,
	} {
		if err := CheckDuplicates([]byte(input)); (err == nil) != ok {
			t.Errorf("CheckDuplicates(%.40q) = %v, want ok=%v", input, err, ok)
		}
	}
}
