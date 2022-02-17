package base64

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeDecode(t *testing.T) {
	tests := []struct {
		Name  string
		Input []byte
	}{
		{
			Name:  "plaintext",
			Input: []byte("hello world"),
		},
		{
			Name: "random bytes",
			Input: func() []byte {
				numBytes := 32
				buff := make([]byte, numBytes)

				n, err := rand.Read(buff)
				require.NoError(t, err)
				require.Equal(t, n, numBytes)

				t.Logf("random bytes for test: %x", buff)

				return buff
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			encoded := Encode(test.Input)
			require.NotEmpty(t, encoded)

			decoded, err := Decode(encoded)
			require.NoError(t, err)
			require.NotEmpty(t, decoded)
			require.Equal(t, test.Input, decoded)
		})
	}
}
