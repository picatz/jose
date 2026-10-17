package header_test

import (
	"errors"
	"testing"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
)

func TestAlgorithmAndEncryptionAlgorithm(t *testing.T) {
	// Values built in code are typed; values decoded from JSON are strings.
	for _, v := range []any{jwa.RS256, "RS256"} {
		got, err := header.Parameters{header.Algorithm: v}.Algorithm()
		if err != nil || got != jwa.RS256 {
			t.Errorf("Algorithm(%T) = %q, %v", v, got, err)
		}
	}
	for _, v := range []any{jwa.A128GCM, "A128GCM"} {
		got, err := header.Parameters{header.EncryptionAlgorithm: v}.EncryptionAlgorithm()
		if err != nil || got != jwa.A128GCM {
			t.Errorf("EncryptionAlgorithm(%T) = %q, %v", v, got, err)
		}
	}

	if _, err := (header.Parameters{}).Algorithm(); !errors.Is(err, header.ErrParameterNotFound) {
		t.Errorf("Algorithm() missing: error = %v", err)
	}
	if _, err := (header.Parameters{}).EncryptionAlgorithm(); !errors.Is(err, header.ErrParameterNotFound) {
		t.Errorf("EncryptionAlgorithm() missing: error = %v", err)
	}
	if _, err := (header.Parameters{header.Algorithm: 42}).Algorithm(); !errors.Is(err, header.ErrInvalidParameterType) {
		t.Errorf("Algorithm() int: error = %v", err)
	}
	if _, err := (header.Parameters{header.EncryptionAlgorithm: 42}).EncryptionAlgorithm(); !errors.Is(err, header.ErrInvalidParameterType) {
		t.Errorf("EncryptionAlgorithm() int: error = %v", err)
	}
}

func TestValidateCriticalHeadersWrapsSentinel(t *testing.T) {
	tests := map[string]header.Parameters{
		"not an array": {header.Critical: "exp"},
		"empty":        {header.Critical: []any{}},
		"non-string":   {header.Critical: []any{1}},
		"standard":     {header.Critical: []any{header.KeyID}, header.KeyID: "k"},
		"unsupported":  {header.Critical: []any{"x-ext"}, "x-ext": 1},
		"missing":      {header.Critical: []any{"x-known"}},
	}
	for name, h := range tests {
		t.Run(name, func(t *testing.T) {
			err := h.ValidateCriticalHeaders([]string{"x-known"})
			if !errors.Is(err, header.ErrCriticalHeaderValidation) {
				t.Fatalf("error = %v, want ErrCriticalHeaderValidation", err)
			}
		})
	}
	if err := (header.Parameters{header.Critical: []any{"x-known"}, "x-known": 1}).ValidateCriticalHeaders([]string{"x-known"}); err != nil {
		t.Errorf("supported critical header: %v", err)
	}
	if err := (header.Parameters{}).ValidateCriticalHeaders(nil); err != nil {
		t.Errorf("no crit: %v", err)
	}
}
