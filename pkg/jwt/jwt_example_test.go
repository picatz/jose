package jwt_test

import (
	"fmt"
	"time"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
	"github.com/picatz/jose/pkg/keyutil"
)

var now = time.Time{} // time.Now() would be used in reality

// https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.1
var secretKeyBytes = []byte{
	3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166,
	143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80,
	46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119,
	98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103,
	208, 128, 163,
}

func ExampleNew_symmetric() {
	token, _ := jwt.New(
		header.Parameters{
			header.Type:      jwt.HeaderType,
			header.Algorithm: jwa.HS256,
		},
		jwt.ClaimsSet{
			jwt.Subject:        "example",
			jwt.IssuedAt:       now,
			jwt.NotBefore:      now.Add(2 * time.Hour),
			jwt.ExpirationTime: now.Add(24 * time.Hour),
		},
		secretKeyBytes,
	)

	_ = token.Verify(jwt.AllowedAlgorithms(jwa.HS256), jwt.SecretKey(secretKeyBytes))

	fmt.Println(token)
	// Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9Cg.eyJleHAiOi02MjEzNTUxMDQwMCwiaWF0IjotNjIxMzU1OTY4MDAsIm5iZiI6LTYyMTM1NTg5NjAwLCJzdWIiOiJleGFtcGxlIn0K.ha_kAIOiX9BQegjRlPSBMuAcEo8slvXGmJPq8HaTNlU
}

func ExampleNew_asymmetric() {
	publicKey, privateKey, _ := keyutil.NewRSAKeyPair()

	token, _ := jwt.New(
		header.Parameters{
			header.Type:      jwt.HeaderType,
			header.Algorithm: jwa.RS256,
		},
		jwt.ClaimsSet{
			jwt.Subject:        "example",
			jwt.IssuedAt:       now,
			jwt.NotBefore:      now.Add(2 * time.Hour),
			jwt.ExpirationTime: now.Add(24 * time.Hour),
		},
		privateKey,
	)

	_ = token.Verify(jwt.AllowedAlgorithms(jwa.RS256), jwt.PublicKey(publicKey))

	fmt.Println(token.Claims[jwt.Subject])
	// Output: example
}
