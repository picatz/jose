package header_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
)

func TestJSONDecode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(t *testing.T, params header.Parameters)
	}{
		{
			name:  "typ and alg",
			input: `{"typ":"JWT","alg":"HS256"}`,
			check: func(t *testing.T, params header.Parameters) {
				typ, err := params.Type()
				if err != nil {
					t.Fatalf("params.Type() error = %v", err)
				}
				if typ != jwt.Type {
					t.Fatalf("typ = %v, want %v", typ, jwt.Type)
				}

				alg, err := params.Algorithm()
				if err != nil {
					t.Fatalf("params.Algorithm() error = %v", err)
				}
				if alg != jwa.HS256 {
					t.Fatalf("alg = %v, want %v", alg, jwa.HS256)
				}
			},
		},
		{
			name:  "typ and alg and kid",
			input: `{"typ":"JWT","alg":"HS256","kid":"key-id"}`,
			check: func(t *testing.T, params header.Parameters) {
				typ, err := params.Type()
				if err != nil {
					t.Fatalf("params.Type() error = %v", err)
				}
				if typ != jwt.Type {
					t.Fatalf("typ = %v, want %v", typ, jwt.Type)
				}

				alg, err := params.Algorithm()
				if err != nil {
					t.Fatalf("params.Algorithm() error = %v", err)
				}
				if alg != jwa.HS256 {
					t.Fatalf("alg = %v, want %v", alg, jwa.HS256)
				}

				kid, err := params.Get(header.KeyID)
				if err != nil {
					t.Fatalf("params.Get() error = %v", err)
				}
				if kid != "key-id" {
					t.Fatalf("kid = %q, want %q", kid, "key-id")
				}
			},
		},
		{
			name:  "typ and alg and kid and crit",
			input: `{"typ":"JWT","alg":"HS256","kid":"key-id","crit":["exp","nbf"]}`,
			check: func(t *testing.T, params header.Parameters) {
				typ, err := params.Type()
				if err != nil {
					t.Fatalf("params.Type() error = %v", err)
				}
				if typ != jwt.Type {
					t.Fatalf("typ = %v, want %v", typ, jwt.Type)
				}

				alg, err := params.Algorithm()
				if err != nil {
					t.Fatalf("params.Algorithm() error = %v", err)
				}
				if alg != jwa.HS256 {
					t.Fatalf("alg = %v, want %v", alg, jwa.HS256)
				}

				kid, err := params.Get(header.KeyID)
				if err != nil {
					t.Fatalf("params.Get() error = %v", err)
				}
				if kid != "key-id" {
					t.Fatalf("kid = %q, want %q", kid, "key-id")
				}

				crit, err := params.Get(header.Critical)
				if err != nil {
					t.Fatalf("params.Get() error = %v", err)
				}
				if !reflect.DeepEqual(crit, []any{"exp", "nbf"}) {
					t.Fatalf("crit = %v, want %v", crit, []any{"exp", "nbf"})
				}
			},
		},
		{
			name:  "missing typ",
			input: `{"alg":"HS256"}`,
			check: func(t *testing.T, params header.Parameters) {
				typ, err := params.Type()
				if !errors.Is(err, header.ErrParameterNotFound) {
					t.Fatalf("params.Type() error = %v, want %v", err, header.ErrParameterNotFound)
				}
				if typ != "" {
					t.Fatalf("typ = %q, want %q", typ, "")
				}
			},
		},
		{
			name:  "missing alg",
			input: `{"typ":"JWT"}`,
			check: func(t *testing.T, params header.Parameters) {
				alg, err := params.Algorithm()
				if !errors.Is(err, header.ErrParameterNotFound) {
					t.Fatalf("params.Algorithm() error = %v, want %v", err, header.ErrParameterNotFound)
				}
				if alg != "" {
					t.Fatalf("alg = %q, want %q", alg, "")
				}
			},
		},
		{
			name:  "invalid typ",
			input: `{"typ":123,"alg":"HS256"}`,
			check: func(t *testing.T, params header.Parameters) {
				typ, err := params.Type()
				if !errors.Is(err, header.ErrInvalidParameterType) {
					t.Fatalf("params.Type() error = %v, want %v", err, header.ErrInvalidParameterType)
				}
				if typ != "" {
					t.Fatalf("typ = %q, want %q", typ, "")
				}
			},
		},
		{
			name:  "invalid alg",
			input: `{"typ":"JWT","alg":123}`,
			check: func(t *testing.T, params header.Parameters) {
				alg, err := params.Algorithm()
				if !errors.Is(err, header.ErrInvalidParameterType) {
					t.Fatalf("params.Algorithm() error = %v, want %v", err, header.ErrInvalidParameterType)
				}
				if alg != "" {
					t.Fatalf("alg = %q, want %q", alg, "")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var params header.Parameters
			err := json.NewDecoder(strings.NewReader(test.input)).Decode(&params)
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}

			test.check(t, params)
		})
	}
}
