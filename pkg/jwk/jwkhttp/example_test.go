package jwkhttp_test

import (
	"github.com/picatz/jose/pkg/jwk/jwkhttp"
	"github.com/picatz/jose/pkg/jwt"
)

// Verify tokens from an OpenID Connect provider. The key set is fetched on
// the first token, cached, and refetched when a token names a kid it lacks.
func ExampleKeys() {
	verifier := jwt.Verifier{
		Keys:     &jwkhttp.Keys{URL: "https://issuer.example/.well-known/jwks.json"},
		Issuer:   "https://issuer.example",
		Audience: "my-api",
	}

	// Use verifier.Verify(ctx, token) per request; it needs network
	// access on first use, so this example has no output.
	_ = verifier
}
