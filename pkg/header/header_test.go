package header

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJSONDecode(t *testing.T) {
	input := `{"typ":"JWT","alg":"HS256"}`

	params := Parameters{}
	err := json.NewDecoder(strings.NewReader(input)).Decode(&params)
	require.NoError(t, err)

	typ, err := params.Type()
	require.NoError(t, err)
	require.Equal(t, "JWT", typ)

	b64urlStr, err := params.Base64URLString()
	require.NoError(t, err)
	require.NotEmpty(t, b64urlStr)
}
