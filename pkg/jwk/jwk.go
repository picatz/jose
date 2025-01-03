package jwk

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/picatz/jose/pkg/base64"
)

// https://datatracker.ietf.org/doc/html/rfc7517#section-4
type (
	ParamaterName = string

	RSA       = ParamaterName
	ECDSA     = ParamaterName
	Symmetric = ParamaterName
)

const (
	KeyType              ParamaterName = "kty"      // https://datatracker.ietf.org/doc/html/rfc7517#section-4.1
	PublicKeyUse         ParamaterName = "use"      // https://datatracker.ietf.org/doc/html/rfc7517#section-4.2
	KeyOperations        ParamaterName = "key_ops"  // https://datatracker.ietf.org/doc/html/rfc7517#section-4.3
	Algorithm            ParamaterName = "alg"      // https://datatracker.ietf.org/doc/html/rfc7517#section-4.4
	KeyID                ParamaterName = "kid"      // https://datatracker.ietf.org/doc/html/rfc7517#section-4.5
	X509URL              ParamaterName = "x5u"      // https://datatracker.ietf.org/doc/html/rfc7517#section-4.6
	X509CertificateChain ParamaterName = "x5c"      // https://datatracker.ietf.org/doc/html/rfc7517#section-4.7
	X509SHA1Thumbprint   ParamaterName = "x5t"      // https://datatracker.ietf.org/doc/html/rfc7517#section-4.8
	X509SHA256Thumbprint ParamaterName = "x5t#S256" // https://datatracker.ietf.org/doc/html/rfc7517#section-4.9

	// K is the symmetric key value within a JWK.
	// https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.3
	K Symmetric = "k"

	// Curve is the curve value within an ECDSA JWK, such as "P-256".
	// https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.3
	Curve ECDSA = "crv"
	X     ECDSA = "x" // X is the x-coordinate for the elliptic curve point.
	Y     ECDSA = "y" // Y is the y-coordinate for the elliptic curve point.

	N RSA = "n" // N is the RSA public modulus value.
	E RSA = "e" // E is the RSA public exponent value.
	D RSA = "d" // D is the RSA private exponent value.
)

// Values is a JSON object containing the parameters describing
// the cryptographic operations and parameters employed.
//
// https://datatracker.ietf.org/doc/html/rfc7517#section-4
type Value = map[ParamaterName]any

// Validate checks that the required parameters are present for
// the given key type, and that the values are valid.
func Validate(v Value) error {
	_, ok := v[KeyType]
	if !ok {
		return fmt.Errorf("missing required paramater %q", KeyType)
	}

	switch v[KeyType] {
	case "EC":
		curveValue, ok := v[Curve]
		if !ok {
			return fmt.Errorf("missing required paramater %q", Curve)
		}

		if curve, ok := curveValue.(string); ok {
			switch curve {
			case "P-256":
				// ok
			case "P-384":
				// ok
			case "P-521":
				// ok
			default:
				return fmt.Errorf("invalid curve %q", curve)
			}
		} else {
			return fmt.Errorf("invalid curve type %T", curveValue)
		}

		xValue, ok := v[X]
		if !ok {
			return fmt.Errorf("missing required paramater %q", X)
		}

		if x, ok := xValue.(string); ok {
			_, err := base64.Decode(x)
			if err != nil {
				return fmt.Errorf("invalid base64 encoding for %q: %w", X, err)
			}
		} else {
			return fmt.Errorf("invalid type for %q", X)
		}

		yValue, ok := v[Y]
		if !ok {
			return fmt.Errorf("missing required paramater %q", Y)
		}

		if y, ok := yValue.(string); ok {
			_, err := base64.Decode(y)
			if err != nil {
				return fmt.Errorf("invalid base64 encoding for %q: %w", Y, err)
			}
		} else {
			return fmt.Errorf("invalid type for %q", Y)
		}
	case "RSA":
		nValue, ok := v[N]
		if !ok {
			return fmt.Errorf("missing required paramater %q", N)
		}

		if n, ok := nValue.(string); ok {
			_, err := base64.Decode(n)
			if err != nil {
				return fmt.Errorf("invalid base64 encoding for %q: %w", N, err)
			}
		} else {
			return fmt.Errorf("invalid type for %q", N)
		}

		eValue, ok := v[E]
		if !ok {
			return fmt.Errorf("missing required paramater %q", E)
		}

		if e, ok := eValue.(string); ok {
			_, err := base64.Decode(e)
			if err != nil {
				return fmt.Errorf("invalid base64 encoding for %q: %w", E, err)
			}
		} else {
			return fmt.Errorf("invalid type for %q", E)
		}

		dValue, ok := v[D]
		if ok { // optional
			if d, ok := dValue.(string); ok {
				_, err := base64.Decode(d)
				if err != nil {
					return fmt.Errorf("invalid base64 encoding for %q: %w", D, err)
				}
			} else {
				return fmt.Errorf("invalid type for %q", D)
			}
		}
	default:
		return fmt.Errorf("unknown key type %q", v[KeyType])
	}

	return nil
}

// RSAValues returns the values for the RSA key type.
func RSAValues(v Value) (n, e, d string, err error) {
	if v[KeyType] != "RSA" {
		err = fmt.Errorf("JWK value is not RSA")
		return
	}

	if nValue, ok := v[N]; ok {
		n = fmt.Sprintf("%v", nValue)
	} else {
		err = fmt.Errorf("no %q set", N)
		return
	}

	if eValue, ok := v[E]; ok {
		e = fmt.Sprintf("%v", eValue)
	} else {
		err = fmt.Errorf("no %q set", E)
		return
	}

	if dValue, ok := v[D]; ok {
		d = fmt.Sprintf("%v", dValue)
	}
	// d can be empty

	return
}

// ECDSAValues returns the values for the ECDSA key type.
func ECDSAValues(v Value) (crv, x, y string, err error) {
	if v[KeyType] != "EC" {
		err = fmt.Errorf("JWK value is not RSA")
		return
	}

	crv = fmt.Sprintf("%v", v[Curve])
	if crv == "" {
		err = fmt.Errorf("no %q set", Curve)
		return
	}

	x = fmt.Sprintf("%v", v[X])
	if x == "" {
		err = fmt.Errorf("no %q set", X)
		return
	}

	y = fmt.Sprintf("%v", v[Y])
	if y == "" {
		err = fmt.Errorf("no %q set", Y)
		return
	}

	return
}

// Ed25519Values returns the values for the Ed25519 key type.
func Ed25519Values(v Value) (x string, err error) {
	if v[KeyType] != "OKP" {
		err = fmt.Errorf("JWK value is not OKP")
		return
	}

	if v[Curve] != "Ed25519" {
		err = fmt.Errorf("JWK value is not Ed25519")
		return
	}

	x = fmt.Sprintf("%v", v[X])
	if x == "" {
		err = fmt.Errorf("no %q set", X)
		return
	}

	return
}

// SymmetricKey returns the symmetric key.
func SymmetricKey(v Value) (k string, err error) {
	k = fmt.Sprintf("%v", v[K])

	if k == "" {
		err = fmt.Errorf("not symmetric key")
	}

	return
}

// HMACSecretKey returns the HMAC secret key (symmetric key).
func HMACSecretKey(v Value) ([]byte, error) {
	key, err := SymmetricKey(v)
	if err != nil {
		return nil, fmt.Errorf("failed to get symmetric key: %w", err)
	}
	return base64.Decode(key)
}

// RSAPublicKey returns the RSA public key and blinding value, or an error
// if the key is not an RSA public key.
func RSAPublicKey(v Value) (pkey *rsa.PublicKey, blindingValue []byte, err error) {
	nEnc, eEnc, dEnc, err := RSAValues(v)
	if err != nil {
		err = fmt.Errorf("failed to get RSA public key: %w", err)
		return
	}

	var (
		// n is the RSA public modulus.
		n = new(big.Int)

		// e is the RSA public exponent.
		e = new(big.Int)

		// d is the RSA private exponent.
		d []byte
	)

	pkey = &rsa.PublicKey{}

	nBytes, err := base64.Decode(nEnc)
	if err != nil {
		err = fmt.Errorf("failed to decode RSA public key N: %w", err)
		return
	}
	n.SetBytes(nBytes)

	pkey.N = n

	eBytes, err := base64.Decode(eEnc)
	if err != nil {
		err = fmt.Errorf("failed to decode RSA public key E: %w", err)
		return
	}
	e.SetBytes(eBytes)

	pkey.E = int(e.Int64())

	// d is optional
	if len(dEnc) > 0 {
		d, err = base64.Decode(dEnc)
		if err != nil {
			err = fmt.Errorf("failed to decode RSA public key D: %w", err)
			return
		}
		blindingValue = d
	}

	return
}

// ECDSAPublicKey returns the ECDSA public key and blinding value, or an error
// if the key is not an ECDSA public key.
func ECDSAPublicKey(v Value) (pkey *ecdsa.PublicKey, blindingValue []byte, err error) {
	crv, xEnc, yEnc, err := ECDSAValues(v)
	if err != nil {
		err = fmt.Errorf("failed to get ECDSA values for public key: %w", err)
		return
	}

	pkey = &ecdsa.PublicKey{}

	switch crv {
	case "P-224":
		pkey.Curve = elliptic.P224()
	case "P-256":
		pkey.Curve = elliptic.P256()
	case "P-384":
		pkey.Curve = elliptic.P384()
	case "P-521":
		pkey.Curve = elliptic.P521()
	default:
		err = fmt.Errorf("invalid curve %q while getting ECDSA values for public key", crv)
		return
	}

	var (
		x = new(big.Int)
		y = new(big.Int)
	)

	xBytes, err := base64.Decode(xEnc)
	if err != nil {
		err = fmt.Errorf("failed to decode ECDSA public key X: %w", err)
		return
	}
	x.SetBytes(xBytes)

	pkey.X = x

	yBytes, err := base64.Decode(yEnc)
	if err != nil {
		err = fmt.Errorf("failed to decode ECDSA public key X: %w", err)
		return
	}
	y.SetBytes(yBytes)

	pkey.Y = y

	return
}

// Ed25519PublicKey returns the Ed25519 public key, or an error if the
// key is not an Ed25519 public key.
func Ed25519PublicKey(v Value) (pkey ed25519.PublicKey, err error) {
	x, err := Ed25519Values(v)
	if err != nil {
		err = fmt.Errorf("failed to get Ed25519 values for public key: %w", err)
		return
	}

	xBytes, err := base64.Decode(x)
	if err != nil {
		err = fmt.Errorf("failed to decode Ed25519 public key X: %w", err)
		return
	}

	// check the length of the key to make sure it is 32 bytes
	if len(xBytes) != ed25519.PublicKeySize {
		err = fmt.Errorf("invalid Ed25519 public key X length: %d", len(xBytes))
		return
	}

	pkey = xBytes

	return
}

// ValueFromPublicKey returns a JWK value from the given public key.
func ValueFromPublicKey(pubKey any) (Value, error) {
	switch pubKey := pubKey.(type) {
	case *rsa.PublicKey:
		value := Value{
			KeyType:      "RSA",
			PublicKeyUse: "sig",
			N:            base64.Encode(pubKey.N.Bytes()),
			E:            base64.Encode(big.NewInt(int64(pubKey.E)).Bytes()),
		}

		return value, nil
	case *ecdsa.PublicKey:
		var crv string
		switch pubKey.Curve {
		case elliptic.P224():
			crv = "P-224"
		case elliptic.P256():
			crv = "P-256"
		case elliptic.P384():
			crv = "P-384"
		case elliptic.P521():
			crv = "P-521"
		default:
			return nil, fmt.Errorf("invalid curve %q used for JWK value", pubKey.Curve)
		}

		return Value{
			KeyType:      "EC",
			PublicKeyUse: "sig",
			Curve:        crv,
			X:            base64.Encode(pubKey.X.Bytes()),
			Y:            base64.Encode(pubKey.Y.Bytes()),
		}, nil
	case ed25519.PublicKey:
		return Value{
			KeyType:      "OKP",
			PublicKeyUse: "sig",
			Curve:        "Ed25519",
			X:            base64.Encode(pubKey),
		}, nil
	default:
		return nil, fmt.Errorf("invalid type %T used for JWK value", pubKey)
	}
}

// Set is a JWK set as defined in RFC 7517.
//
// https://datatracker.ietf.org/doc/html/rfc7517#section-5
type Set struct {
	// Keys is a list of JWK values.
	//
	// https://datatracker.ietf.org/doc/html/rfc7517#section-5.1
	Keys []Value `json:"keys"`
}

// Validate validates the JWK set, returning an error if any
// of the keys are invalid.
func (s *Set) Validate() error {
	if len(s.Keys) == 0 {
		return fmt.Errorf("no key values in JWK set")
	}

	for _, key := range s.Keys {
		err := Validate(key)
		if err != nil {
			return fmt.Errorf("key set validation error: %w", err)
		}
	}

	return nil
}

// Get returns the key that matches the given key id.
func (s *Set) Get(keyID string) (Value, error) {
	for _, key := range s.Keys {
		if key[KeyID] == keyID {
			return key, nil
		}
	}

	return nil, fmt.Errorf("key %q found in set", keyID)
}

// FetchSet fetches a JWK set from the given URL and HTTP client.
func FetchSet(ctx context.Context, url string, client *http.Client) (*Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK set request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWK set: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWK set: %s", resp.Status)
	}

	var set Set
	err = json.NewDecoder(resp.Body).Decode(&set)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK set: %w", err)
	}

	err = set.Validate()
	if err != nil {
		return nil, fmt.Errorf("failed to validate JWK set: %w", err)
	}

	return &set, nil
}

// URLSetCache is a cache of JWK sets keyed by URL that can be easily used to verify
// JWTs from multiple issuers. It handles refreshing the JWK sets when they expire,
// retrying failed fetches, and caching the JWK sets for a configurable amount of time.
type URLSetCache struct {
	mutex sync.RWMutex

	// sets is a map of JWK sets keyed by URL.
	sets map[string]*Set

	// cacheTimes is a map of JWK set cache times keyed by URL.
	cacheTimes map[string]time.Time

	// client is the HTTP client used to fetch JWK sets.
	client *http.Client

	// refreshInterval is the amount of time between refreshing JWK sets.
	refreshInterval time.Duration

	// cacheDuration is the amount of time to cache JWK sets.
	cacheDuration time.Duration
}

// NewURLSetCache returns a new JWK set cache.
func NewURLSetCache(client *http.Client, refreshInterval, cacheDuration time.Duration) *URLSetCache {
	return &URLSetCache{
		mutex:           sync.RWMutex{},
		sets:            make(map[string]*Set),
		cacheTimes:      make(map[string]time.Time),
		client:          client,
		refreshInterval: refreshInterval,
		cacheDuration:   cacheDuration,
	}
}

// Get returns the JWK set for the given URL, fetching it if it is not already cached.
func (c *URLSetCache) Get(ctx context.Context, url string) (*Set, error) {
	c.mutex.RLock()
	set, cached := c.sets[url]
	expiry := c.cacheTimes[url]
	c.mutex.RUnlock()

	// If there's no set or the set is expired, fetch a fresh copy.
	if !cached || time.Now().After(expiry) {
		return c.Fetch(ctx, url)
	}
	return set, nil
}

// Get returns the first key from the JWK set for the given URL that matches the given key id,
// fetching the JWK set if it is not already cached.
func (c *URLSetCache) GetKey(ctx context.Context, url string, keyID string) (Value, error) {
	c.mutex.RLock()
	set, ok := c.sets[url]
	urlCacheTime := c.cacheTimes[url]
	c.mutex.RUnlock()

	if !ok {
		var err error
		set, err = c.Fetch(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch JWK set: %w", err)
		}
	}

	if time.Now().After(urlCacheTime) {
		var err error
		set, err = c.Refresh(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("failed to refresh JWK set: %w", err)
		}
	}

	key, err := set.Get(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key %q from JWK set: %w", keyID, err)
	}

	return key, nil
}

// Range iterates over the JWK sets in the cache, calling the given function for each
// URL and key. If the function returns false, the iteration will stop.
func (c *URLSetCache) Range(fn func(url string, key Value) bool) {
	if fn == nil || c == nil {
		return
	}

	c.mutex.RLock()
	defer c.mutex.RUnlock()

	for url, set := range c.sets {
		for _, key := range set.Keys {
			if !fn(url, key) {
				return
			}
		}
	}
}

// Fetch fetches the JWK set for the given URL.
func (c *URLSetCache) Fetch(ctx context.Context, url string) (*Set, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	set, err := FetchSet(ctx, url, c.client)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWK set: %w", err)
	}

	c.sets[url] = set

	return set, nil
}

// Refresh refreshes the JWK set for the given URL.
func (c *URLSetCache) Refresh(ctx context.Context, url string) (*Set, error) {
	return c.Fetch(ctx, url)
}

// RefreshAll refreshes all JWK sets in the cache.
func (c *URLSetCache) RefreshAll(ctx context.Context) error {
	c.mutex.RLock()
	urls := make([]string, 0, len(c.sets))
	for url := range c.sets {
		urls = append(urls, url)
	}
	c.mutex.RUnlock()

	for _, url := range urls {
		if _, err := c.Refresh(ctx, url); err != nil {
			return fmt.Errorf("failed to refresh JWK set for %q: %w", url, err)
		}
	}
	return nil
}

// Start starts the JWK set cache, refreshing the JWK sets at the given interval.
// It will block until the context is canceled, and will only return an error if
// the refresh fails, possibly due to a network error.
//
// Most callers will want to call this in a goroutine after creating the cache.
func (c *URLSetCache) Start(ctx context.Context) error {
	ticker := time.NewTicker(c.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			err := c.RefreshAll(ctx)
			if err != nil {
				return fmt.Errorf("failed to refresh JWK sets: %w", err)
			}
		}
	}
}
