package header

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJSONDecode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(t *testing.T, params Parameters)
	}{
		{
			name:  "typ and alg",
			input: `{"typ":"JWT","alg":"HS256"}`,
			check: func(t *testing.T, params Parameters) {
				typ, err := params.Type()
				require.NoError(t, err)
				require.Equal(t, "JWT", typ)

				alg, err := params.Algorithm()
				require.NoError(t, err)
				require.Equal(t, "HS256", alg)
			},
		},
		{
			name:  "typ and alg and kid",
			input: `{"typ":"JWT","alg":"HS256","kid":"key-id"}`,
			check: func(t *testing.T, params Parameters) {
				typ, err := params.Type()
				require.NoError(t, err)
				require.Equal(t, "JWT", typ)

				alg, err := params.Algorithm()
				require.NoError(t, err)
				require.Equal(t, "HS256", alg)

				kid, err := params.Get(KeyID)
				require.NoError(t, err)
				require.Equal(t, "key-id", kid)
			},
		},
		{
			name:  "typ and alg and kid and crit",
			input: `{"typ":"JWT","alg":"HS256","kid":"key-id","crit":["exp","nbf"]}`,
			check: func(t *testing.T, params Parameters) {
				typ, err := params.Type()
				require.NoError(t, err)
				require.Equal(t, "JWT", typ)

				alg, err := params.Algorithm()
				require.NoError(t, err)
				require.Equal(t, "HS256", alg)

				kid, err := params.Get(KeyID)
				require.NoError(t, err)
				require.Equal(t, "key-id", kid)

				crit, err := params.Get(Critical)
				require.NoError(t, err)
				require.Equal(t, []any{"exp", "nbf"}, crit)
			},
		},
		{
			name:  "missing typ",
			input: `{"alg":"HS256"}`,
			check: func(t *testing.T, params Parameters) {
				typ, err := params.Type()
				require.Error(t, err)
				require.ErrorIs(t, err, ErrParameterNotFound)
				require.Equal(t, "", typ)
			},
		},
		{
			name:  "missing alg",
			input: `{"typ":"JWT"}`,
			check: func(t *testing.T, params Parameters) {
				alg, err := params.Algorithm()
				require.Error(t, err)
				require.ErrorIs(t, err, ErrParameterNotFound)
				require.Equal(t, "", alg)
			},
		},
		{
			name:  "invalid typ",
			input: `{"typ":123,"alg":"HS256"}`,
			check: func(t *testing.T, params Parameters) {
				typ, err := params.Type()
				require.Error(t, err)
				require.ErrorIs(t, err, ErrInvalidParameterType)
				require.Equal(t, "", typ)
			},
		},
		{
			name:  "invalid alg",
			input: `{"typ":"JWT","alg":123}`,
			check: func(t *testing.T, params Parameters) {
				alg, err := params.Algorithm()
				require.Error(t, err)
				require.ErrorIs(t, err, ErrInvalidParameterType)
				require.Equal(t, "", alg)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var params Parameters
			err := json.NewDecoder(strings.NewReader(test.input)).Decode(&params)
			require.NoError(t, err)

			test.check(t, params)
		})
	}
}
