package dpop_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/picatz/jose/pkg/dpop"
)

// FuzzBoundThumbprint checks that BoundThumbprint never panics on arbitrary
// JSON claims, and that it returns a thumbprint only for a "cnf" holding
// "jkt" and nothing else.
func FuzzBoundThumbprint(f *testing.F) {
	for _, s := range []string{
		`{"cnf":{"jkt":"abc"}}`, `{"cnf":{"jkt":"abc","x5t#S256":"d"}}`, `{"cnf":{"jkt":""}}`,
		`{"cnf":{"jkt":1}}`, `{"cnf":{}}`, `{"cnf":[]}`, `{"cnf":null}`, `{}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var claims map[string]any
		if json.Unmarshal(data, &claims) != nil {
			return
		}
		jkt, err := dpop.BoundThumbprint(claims)
		if err != nil {
			if !errors.Is(err, dpop.ErrBinding) || jkt != "" {
				t.Fatalf("BoundThumbprint() = %q, %v", jkt, err)
			}
			return
		}
		cnf, _ := claims["cnf"].(map[string]any)
		if jkt == "" || len(cnf) != 1 || cnf["jkt"] != jkt {
			t.Fatalf("BoundThumbprint() = %q for cnf %v", jkt, claims["cnf"])
		}
	})
}
