package header_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
	"github.com/stretchr/testify/require"
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
				require.NoError(t, err)
				require.Equal(t, jwt.Type, typ)

				alg, err := params.Algorithm()
				require.NoError(t, err)
				require.Equal(t, jwa.HS256, alg)
			},
		},
		{
			name:  "typ and alg and kid",
			input: `{"typ":"JWT","alg":"HS256","kid":"key-id"}`,
			check: func(t *testing.T, params header.Parameters) {
				typ, err := params.Type()
				require.NoError(t, err)
				require.Equal(t, jwt.Type, typ)

				alg, err := params.Algorithm()
				require.NoError(t, err)
				require.Equal(t, jwa.HS256, alg)

				kid, err := params.Get(header.KeyID)
				require.NoError(t, err)
				require.Equal(t, "key-id", kid)
			},
		},
		{
			name:  "typ and alg and kid and crit",
			input: `{"typ":"JWT","alg":"HS256","kid":"key-id","crit":["exp","nbf"]}`,
			check: func(t *testing.T, params header.Parameters) {
				typ, err := params.Type()
				require.NoError(t, err)
				require.Equal(t, jwt.Type, typ)

				alg, err := params.Algorithm()
				require.NoError(t, err)
				require.Equal(t, jwa.HS256, alg)

				kid, err := params.Get(header.KeyID)
				require.NoError(t, err)
				require.Equal(t, "key-id", kid)

				crit, err := params.Get(header.Critical)
				require.NoError(t, err)
				require.Equal(t, []any{"exp", "nbf"}, crit)
			},
		},
		{
			name:  "missing typ",
			input: `{"alg":"HS256"}`,
			check: func(t *testing.T, params header.Parameters) {
				typ, err := params.Type()
				require.Error(t, err)
				require.ErrorIs(t, err, header.ErrParameterNotFound)
				require.Equal(t, "", typ)
			},
		},
		{
			name:  "missing alg",
			input: `{"typ":"JWT"}`,
			check: func(t *testing.T, params header.Parameters) {
				alg, err := params.Algorithm()
				require.Error(t, err)
				require.ErrorIs(t, err, header.ErrParameterNotFound)
				require.Equal(t, "", alg)
			},
		},
		{
			name:  "invalid typ",
			input: `{"typ":123,"alg":"HS256"}`,
			check: func(t *testing.T, params header.Parameters) {
				typ, err := params.Type()
				require.Error(t, err)
				require.ErrorIs(t, err, header.ErrInvalidParameterType)
				require.Equal(t, "", typ)
			},
		},
		{
			name:  "invalid alg",
			input: `{"typ":"JWT","alg":123}`,
			check: func(t *testing.T, params header.Parameters) {
				alg, err := params.Algorithm()
				require.Error(t, err)
				require.ErrorIs(t, err, header.ErrInvalidParameterType)
				require.Equal(t, "", alg)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var params header.Parameters
			err := json.NewDecoder(strings.NewReader(test.input)).Decode(&params)
			require.NoError(t, err)

			test.check(t, params)
		})
	}
}
