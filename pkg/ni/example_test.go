package ni_test

import (
	"crypto"
	"fmt"

	"github.com/picatz/jose/pkg/ni"
)

// Sum names some bytes by their digest. This is the example from
// RFC 6920 section 8.1.
func ExampleSum() {
	u, _ := ni.Sum(crypto.SHA256, []byte("Hello World!"))
	fmt.Println(u)
	// Output: ni:///sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk
}

// Matches checks received bytes against a URI received from someone else.
func ExampleURI_Matches() {
	u, err := ni.Parse("ni:///sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk")
	if err != nil {
		panic(err)
	}
	fmt.Println(u.Matches([]byte("Hello World!")))
	fmt.Println(u.Matches([]byte("Hello World?")))
	// Output:
	// true
	// false
}

// Parse refuses digests too short to bind content.
func ExampleParse() {
	_, err := ni.Parse("ni:///sha-256-32;f4OxZQ")
	fmt.Println(err)
	// Output: ni: malformed URI: unsupported algorithm "sha-256-32"
}
