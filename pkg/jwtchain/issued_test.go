package jwtchain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/jwtchain"
)

// A link signed on a clock ahead of the verifier's is refused until the
// verifier's clock, plus leeway, reaches its "iat".
func TestLinkIssuedInTheFuture(t *testing.T) {
	f := newFixture(t)
	for name, tc := range map[string]struct {
		ahead time.Duration
		ok    bool
	}{
		"within leeway": {jwtchain.DefaultLeeway - time.Second, true},
		"beyond leeway": {jwtchain.DefaultLeeway + time.Minute, false},
	} {
		t.Run(name, func(t *testing.T) {
			issued := now.Add(tc.ahead)
			c, err := jwtchain.Derive(parse(t, f.root), f.a, jwtchain.Restriction{
				Expiry: issued.Add(10 * time.Minute),
				Holder: f.b.Public(),
			}, jwtchain.WithClock(func() time.Time { return issued }))
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.policy().VerifyChain(c)
			if tc.ok != (err == nil) || err != nil && !errors.Is(err, jwtchain.ErrVerification) {
				t.Fatalf("VerifyChain() error = %v, want ok=%v", err, tc.ok)
			}
			// Once the verifier's clock catches up, the link verifies.
			later := f.policy()
			later.Now = func() time.Time { return issued }
			if _, err := later.VerifyChain(c); err != nil {
				t.Fatalf("VerifyChain() at issue time: %v", err)
			}
		})
	}
}
