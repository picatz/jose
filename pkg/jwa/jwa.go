package jwa

// https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
type Algorithm string

const (
	HS256 Algorithm = "HS256"
	HS384 Algorithm = "HS384"
	HS512 Algorithm = "HS512"
	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
	None  Algorithm = "none"

	// I have no idea where these are documented, but other libraries implement them?
	ES256K Algorithm = "ES256K"
	EdDSA  Algorithm = "EdDSA"
)

type AlgorithmSet map[Algorithm]struct{}

type AllowedAlgorithms AlgorithmSet

func DefaultAllowedAlgorithms() AllowedAlgorithms {
	return AllowedAlgorithms{
		RS256: {},
		ES256: {},
	}
}

func NewAllowedAlgorithms(algs ...Algorithm) AllowedAlgorithms {
	allowed := AllowedAlgorithms{}

	for _, alg := range algs {
		allowed[alg] = struct{}{}
	}

	return allowed
}

func (a AllowedAlgorithms) Allowed(algs ...Algorithm) bool {
	var allowed bool
	for _, alg := range algs {
		_, ok := a[alg]
		if !ok {
			return false
		}
		allowed = true
	}
	return allowed
}

func (a AllowedAlgorithms) List() (list []Algorithm) {
	for alg := range a {
		list = append(list, alg)
	}
	return
}
