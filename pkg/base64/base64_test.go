package base64

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
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
				if err != nil {
					t.Fatalf("rand.Read() error = %v", err)
				}
				if numBytes != n {
					t.Fatalf("rand.Read() = %d, want %d", n, numBytes)
				}

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
				if err == nil {
					t.Fatal("Encode() error = nil, want non-nil")
				}
				if encoded != "" {
					t.Fatalf("encoded = %q, want %q", encoded, "")
				}
				return
			}

			encoded, err := Encode(test.input)
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}

			// Verify no padding characters in output
			if strings.Contains(encoded, "=") {
				t.Fatalf("encoded = %q, want no %q", encoded, "=")
			}

			decoded, err := Decode(encoded)
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if !bytes.Equal(decoded, test.input) {
				t.Fatalf("decoded = %x, want %x", decoded, test.input)
			}
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
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			if encoded != test.expected {
				t.Fatalf("encoded = %v, want %v", encoded, test.expected)
			}

			decoded, err := Decode(test.expected)
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if !bytes.Equal(decoded, test.input) {
				t.Fatalf("decoded = %x, want %x", decoded, test.input)
			}
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
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if !bytes.Equal(decoded, test.expected) {
				t.Fatalf("decoded = %x, want %x", decoded, test.expected)
			}
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
			if err == nil {
				t.Fatal("Decode() error = nil, want non-nil")
			}
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
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			if strings.Contains(encoded, "=") {
				t.Fatalf("encoded = %q, want no %q", encoded, "=")
			}

			// Verify round-trip
			decoded, err := Decode(encoded)
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if !bytes.Equal(decoded, input) {
				t.Fatalf("decoded = %x, want %x", decoded, input)
			}
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
		if err != nil {
			b.Fatalf("Encode() error = %v", err)
		}

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
		if err == nil {
			t.Fatal("Encode(empty) error = nil, want non-nil")
		}
		if result != "" {
			t.Fatalf("Encode(empty) = %q, want empty string", result)
		}
	})

	t.Run("encode nil slice", func(t *testing.T) {
		result, err := Encode(nil)
		if err == nil {
			t.Fatal("Encode(nil) error = nil, want non-nil")
		}
		if result != "" {
			t.Fatalf("Encode(nil) = %q, want empty string", result)
		}
	})

	t.Run("decode empty string", func(t *testing.T) {
		result, err := Decode("")
		if err == nil {
			t.Fatal("Decode() error = nil, want non-nil")
		}
		if result != nil {
			t.Fatalf("Decode(\"\") = %v, want nil", result)
		}
	})
}

// TestErrorWrapping verifies that errors are properly wrapped
func TestErrorWrapping(t *testing.T) {
	_, err := Decode("invalid@base64url")
	if err == nil || !strings.Contains(err.Error(), "invalid base64url input") {
		t.Fatalf("Decode() error = %v, want error containing %q", err, "invalid base64url input")
	}
}

// TestLongInput tests with longer inputs to verify performance and correctness
func TestLongInput(t *testing.T) {
	// Create a 1MB input
	input := make([]byte, 1024*1024)
	for i := range input {
		input[i] = byte(i % 256)
	}

	encoded, err := Encode(input)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if len(encoded) == 0 {
		t.Fatal("encoded is empty")
	}
	if strings.Contains(encoded, "=") {
		t.Fatalf("encoded = %q, want no %q", encoded, "=")
	}

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Fatalf("Decode(Encode(input)) did not round-trip a %d-byte input (got %d bytes)", len(input), len(decoded))
	}
}
