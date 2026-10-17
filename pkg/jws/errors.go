package jws

import (
	"errors"
	"fmt"
	"strings"
)

// Errors returned by this package wrap one of these sentinels, so callers
// can branch with [errors.Is] instead of matching message text. Messages
// never include key material or the secret being checked.
var (
	// ErrFormat reports a JWS that is malformed: bad serialization,
	// encoding, UTF-8, JSON, header parameters, "crit" or "b64" handling.
	ErrFormat = errors.New("jws: malformed JWS")

	// ErrSignature reports a signature or MAC that does not verify.
	ErrSignature = errors.New("jws: invalid signature")

	// ErrAlgorithm reports an "alg" that is missing, unsupported or
	// unsecured ("none"), or a key that does not suit the algorithm
	// (wrong type, wrong curve, too small).
	ErrAlgorithm = errors.New("jws: unsupported algorithm or unsuitable key")
)

// jwsError is an error that wraps one of the sentinels above. Its message
// is "jws: " followed by detail, which keeps messages specific while
// [errors.Is] still finds the sentinel.
type jwsError struct {
	kind   error
	detail string
	cause  error
}

func (e *jwsError) Error() string { return "jws: " + e.detail }

func (e *jwsError) Unwrap() []error {
	if e.cause == nil {
		return []error{e.kind}
	}
	return []error{e.kind, e.cause}
}

// fail returns an error of the given kind. format and args work as in
// [fmt.Errorf], including %w.
func fail(kind error, format string, args ...any) error {
	cause := fmt.Errorf(format, args...)
	detail := cause.Error()
	if errors.Unwrap(cause) == nil && len(unwrapAll(cause)) == 0 {
		cause = nil
	}
	return &jwsError{kind: kind, detail: strings.TrimPrefix(detail, "jws: "), cause: cause}
}

func unwrapAll(err error) []error {
	if multi, ok := err.(interface{ Unwrap() []error }); ok {
		return multi.Unwrap()
	}
	if inner := errors.Unwrap(err); inner != nil {
		return []error{inner}
	}
	return nil
}

// context prefixes the detail of err with what, keeping its kind.
func context(err error, what string) error {
	var e *jwsError
	if errors.As(err, &e) {
		return &jwsError{kind: e.kind, detail: what + ": " + e.detail, cause: e}
	}
	return fmt.Errorf("jws: %s: %w", what, err)
}
