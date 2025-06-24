package base64

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeDecode(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "empty input",
			input: []byte{},
		},
		{
			name:  "single byte",
			input: []byte{0x01},
		},
		{
			name:  "plaintext",
			input: []byte("hello world"),
		},
		{
			name:  "binary data",
			input: []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD},
		},
		{
			name: "random bytes",
			input: func() []byte {
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
		t.Run(test.name, func(t *testing.T) {
			// Handle empty input case - should return empty string
			if len(test.input) == 0 {
				encoded, err := Encode(test.input)
				require.Error(t, err)
				require.Equal(t, "", encoded)
				return
			}

			encoded, err := Encode(test.input)
			require.NoError(t, err)

			// Verify no padding characters in output
			require.NotContains(t, encoded, "=", "encoded output should not contain padding")

			decoded, err := Decode(encoded)
			require.NoError(t, err)
			require.Equal(t, test.input, decoded)
		})
	}
}

// TestRFCCompliance tests known base64url test vectors from RFC specifications
func TestRFCCompliance(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "RFC 4648 example 1",
			input:    []byte("f"),
			expected: "Zg",
		},
		{
			name:     "RFC 4648 example 2",
			input:    []byte("fo"),
			expected: "Zm8",
		},
		{
			name:     "RFC 4648 example 3",
			input:    []byte("foo"),
			expected: "Zm9v",
		},
		{
			name:     "RFC 4648 example 4",
			input:    []byte("foob"),
			expected: "Zm9vYg",
		},
		{
			name:     "RFC 4648 example 5",
			input:    []byte("fooba"),
			expected: "Zm9vYmE",
		},
		{
			name:     "RFC 4648 example 6",
			input:    []byte("foobar"),
			expected: "Zm9vYmFy",
		},
		{
			name:     "URL-safe characters",
			input:    []byte{0x3E, 0x3F}, // produces '+/' in standard base64, '-_' in base64url
			expected: "Pj8",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := Encode(test.input)
			require.NoError(t, err)
			require.Equal(t, test.expected, encoded)

			decoded, err := Decode(test.expected)
			require.NoError(t, err)
			require.Equal(t, test.input, decoded)
		})
	}
}

// TestDecodeWithPadding tests that decode works with padded input
func TestDecodeWithPadding(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
	}{
		{
			name:     "no padding needed",
			input:    "Zm9vYmFy", // "foobar"
			expected: []byte("foobar"),
		},
		{
			name:     "one padding character",
			input:    "Zm9vYmE=", // "fooba"
			expected: []byte("fooba"),
		},
		{
			name:     "two padding characters",
			input:    "Zm9vYg==", // "foob"
			expected: []byte("foob"),
		},
		{
			name:     "already unpadded",
			input:    "Zm9vYmE", // "fooba" without padding
			expected: []byte("fooba"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoded, err := Decode(test.input)
			require.NoError(t, err)
			require.Equal(t, test.expected, decoded)
		})
	}
}

// TestDecodeErrors tests error conditions
func TestDecodeErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "invalid character",
			input: "Zm9v@mFy", // contains invalid character '@'
		},
		{
			name:  "standard base64 characters",
			input: "Zm9v+mFy", // contains '+' which is not valid in base64url
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode(test.input)
			require.Error(t, err)
		})
	}
}

// TestPaddingRemoval verifies that encoding never produces padding
func TestPaddingRemoval(t *testing.T) {
	inputs := [][]byte{
		[]byte("a"),      // 1 byte - would need 2 padding chars
		[]byte("aa"),     // 2 bytes - would need 1 padding char
		[]byte("aaa"),    // 3 bytes - no padding needed
		[]byte("aaaa"),   // 4 bytes - would need 2 padding chars
		[]byte("aaaaa"),  // 5 bytes - would need 1 padding char
		[]byte("aaaaaa"), // 6 bytes - no padding needed
	}

	for _, input := range inputs {
		t.Run(fmt.Sprintf("input_%d_bytes", len(input)), func(t *testing.T) {
			encoded, err := Encode(input)
			require.NoError(t, err)
			require.NotContains(t, encoded, "=", "encoded output should never contain padding")

			// Verify round-trip
			decoded, err := Decode(encoded)
			require.NoError(t, err)
			require.Equal(t, input, decoded)
		})
	}
}

// BenchmarkEncode benchmarks the encoding function
func BenchmarkEncode(b *testing.B) {

	sizes := []int{16, 64, 256, 1024, 4096}

	for _, size := range sizes {
		data := make([]byte, size)
		rand.Read(data)

		var err error
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				_, err = Encode(data)
				if err != nil {
					b.Fatalf("encoding failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkDecode benchmarks the decoding function
func BenchmarkDecode(b *testing.B) {
	sizes := []int{16, 64, 256, 1024, 4096}

	for _, size := range sizes {
		data := make([]byte, size)
		rand.Read(data)
		encoded, err := Encode(data)
		require.NoError(b, err)

		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				_, _ = Decode(encoded)
			}
		})
	}
}

// TestEmptyInput specifically tests empty input handling
func TestEmptyInput(t *testing.T) {
	t.Run("encode empty slice", func(t *testing.T) {
		result, err := Encode([]byte{})
		require.Error(t, err, "encoding empty slice should return an error")
		require.Equal(t, "", result, "encoding empty slice should return empty string")
	})

	t.Run("encode nil slice", func(t *testing.T) {
		result, err := Encode(nil)
		require.Error(t, err, "encoding nil slice should return an error")
		require.Equal(t, "", result, "encoding nil slice should return empty string")
	})

	t.Run("decode empty string", func(t *testing.T) {
		result, err := Decode("")
		require.Error(t, err)
		require.Nil(t, result, "decoding empty string should return nil")
	})
}

// TestErrorWrapping verifies that errors are properly wrapped
func TestErrorWrapping(t *testing.T) {
	_, err := Decode("invalid@base64url")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid base64url input")
}

// TestLongInput tests with longer inputs to verify performance and correctness
func TestLongInput(t *testing.T) {
	// Create a 1MB input
	input := make([]byte, 1024*1024)
	for i := range input {
		input[i] = byte(i % 256)
	}

	encoded, err := Encode(input)
	require.NoError(t, err)
	require.NotEmpty(t, encoded)
	require.NotContains(t, encoded, "=", "should not contain padding")

	decoded, err := Decode(encoded)
	require.NoError(t, err)
	require.Equal(t, input, decoded)
}
