package jose_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"
	"github.com/picatz/jose/pkg/jwt"
	"github.com/stretchr/testify/require"
)

func ExampleParseString() {
	token, err := jwt.ParseString("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InBpY2F0eiIsImlhdCI6MTUxNjIzOTAyMn0.UOXSwO9AAuqSpOCt-PDjMmek7SmKOR7v35rmMzeyYfM")
	if err != nil {
		panic(fmt.Sprintf("failed to parse JWT string: %v", err))
	}

	err = token.Verify(jwt.WithAllowedAlgorithms(jwa.HS256), jwt.WithKey("supersecret"))
	if err != nil {
		panic(fmt.Sprintf("failed to verify JWT signature: %v", err))
	}

	sub, err := token.Claims.Get(jwt.Subject)
	if err != nil {
		panic(fmt.Sprintf("failed to get JWT claim %q: %v", jwt.Subject, err))
	}

	fmt.Println(sub)
	// Output: 1234567890
}

func TestExampleJWTParseStringAndVerifySignatureHS256(t *testing.T) {
	token, err := jwt.ParseString("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InBpY2F0eiIsImlhdCI6MTUxNjIzOTAyMn0.UOXSwO9AAuqSpOCt-PDjMmek7SmKOR7v35rmMzeyYfM")
	require.NoError(t, err)
	require.NotNil(t, token)

	err = token.Verify(jwt.WithAllowedAlgorithms(jwa.HS256), jwt.WithKey("supersecret"))
	require.NoError(t, err)

	alg, err := token.Header.Algorithm()
	require.NoError(t, err)
	require.Equal(t, jwa.HS256, alg)

	typ, err := token.Header.Type()
	require.NoError(t, err)
	require.Equal(t, jwt.Type, typ)

	claimNames := token.Claims.Names()
	require.Equal(t, []jwt.ClaimName{"sub", "name", "iat"}, claimNames)

	sub, err := token.Claims.Get(jwt.Subject)
	require.NoError(t, err)
	require.Equal(t, "1234567890", sub)

	iat, err := token.Claims.Get(jwt.IssuedAt)
	require.NoError(t, err)
	require.Equal(t, int64(1516239022), iat)

	name, err := token.Claims.Get("name")
	require.NoError(t, err)
	require.Equal(t, "picatz", name)
}

func TestExampleCreateJWTAndSignWithHS256(t *testing.T) {
	token := &jwt.Token{
		Header: jws.Header{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.HS256,
		},
		Claims: jwt.ClaimsSet{
			jwt.Subject:  "1234567890",
			jwt.Issuer:   "test",
			jwt.IssuedAt: time.Now(),
		},
	}

	signature, err := token.Sign("supersecret")
	require.NoError(t, err)
	require.NotNil(t, signature)
	require.NotEmpty(t, signature)

	// Essentially same as:

	token, err = jwt.New(
		jws.Header{
			header.Algorithm: jwa.HS256,
		},
		jwt.ClaimsSet{
			jwt.Subject:  "1234567890",
			jwt.Issuer:   "test",
			jwt.IssuedAt: time.Now(),
		},
		"supersecret",
	)
	require.NoError(t, err)

	t.Logf("generated signed token: %v", token)
}
